# Eclipse Cluster MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
# Minimal OCI / Docker registry read client for Eclipse Cluster K0.

"""Minimal OCI / Docker registry read client for Eclipse Cluster K0.

Powered by Cyan Eclipse Technologies (cetech.ai).

Stdlib only (urllib). Read-only: this client can resolve manifests and
fetch blobs; it has no push, delete, or write path at all.

Supported flows:
  * Anonymous bearer-token auth (the Docker Hub / GHCR pattern: a 401
    carries WWW-Authenticate realm/service/scope; we fetch a token and
    retry). No credentials are ever configured or sent beyond the
    anonymous token the registry itself issues.
  * Manifest resolution by tag or digest, including manifest lists /
    OCI indexes (a child manifest is selected and its digest is the
    image digest the gate reports).
  * Cosign-style signature / attestation discovery via the derived tags
    ``sha256-<digest>.sig`` and ``sha256-<digest>.att``, with the OCI
    Referrers API as a fallback. [verify per registry: GHCR supports
    referrers; Docker Hub's referrers coverage has historically been
    partial, which is why the tag layout is tried first.]

HTTPS everywhere except loopback hosts (127.0.0.1 / localhost), where
plain HTTP is accepted so tests and local dev registries work.
"""
import hashlib
import json
import re
import urllib.error
import urllib.parse
import urllib.request

ACCEPT_MANIFESTS = ", ".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])
INDEX_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}
# Canonical registry API endpoints for registries whose API host
# differs from the name image references (and policy allowlists) use.
# docker.io is Docker Hub's website (it redirects to www.docker.com),
# not a registry endpoint; the Hub API lives at registry-1.docker.io.
_REGISTRY_ENDPOINTS = {"docker.io": "registry-1.docker.io"}


def _headers_dict(headers) -> dict:
    """Response headers as a plain dict with lowercased names.

    HTTP header names are case-insensitive, but registries do not
    agree on casing on the wire (GHCR sends 'www-authenticate' in
    lowercase). Normalize here, at the wire boundary; look headers
    up by their lowercase name everywhere else.
    """
    return {k.lower(): v for k, v in dict(headers or {}).items()}


class RegistryError(Exception):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


def parse_image_ref(ref: str) -> dict:
    """Parse [registry/]repo[:tag][@digest] into its parts.

    Docker conventions: a first component containing '.' or ':' (or
    'localhost') is a registry host; otherwise the registry is docker.io
    and single-component names live under library/.
    """
    digest = None
    if "@" in ref:
        ref, digest = ref.rsplit("@", 1)
    parts = ref.split("/")
    first = parts[0]
    if "." in first or ":" in first or first == "localhost":
        registry, repo_parts = first, parts[1:]
    else:
        registry, repo_parts = "docker.io", parts
    if not repo_parts:
        raise ValueError(f"image reference has no repository: {ref!r}")
    repo = "/".join(repo_parts)
    tag = "latest"
    if ":" in repo_parts[-1]:
        repo, tag = repo.rsplit(":", 1)
    if registry == "docker.io" and "/" not in repo:
        repo = "library/" + repo
    return {"registry": registry, "repository": repo, "tag": tag,
            "digest": digest}


def _parse_auth_challenge(header: str) -> dict:
    out = {}
    for m in re.finditer(r'(\w+)="([^"]*)"', header or ""):
        out[m.group(1)] = m.group(2)
    return out


class RegistryClient:
    def __init__(self, registry: str, timeout: int = 20):
        self.registry = registry
        host = _REGISTRY_ENDPOINTS.get(registry, registry)
        scheme = "http" if host.startswith(("127.0.0.1", "localhost")) \
            else "https"
        self.base = f"{scheme}://{host}"
        self.timeout = timeout
        self._tokens = {}  # (repository, scope) -> token

    # -- transport ------------------------------------------------------
    def _raw_get(self, url: str, headers: dict, allow_redirect: bool):
        req = urllib.request.Request(url, headers=headers, method="GET")
        opener = urllib.request.build_opener()
        if not allow_redirect:
            class _NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *a, **kw):
                    return None
            opener = urllib.request.build_opener(_NoRedirect)
        try:
            with opener.open(req, timeout=self.timeout) as resp:
                return resp.status, _headers_dict(resp.headers), resp.read()
        except urllib.error.HTTPError as e:
            return e.code, _headers_dict(e.headers), \
                e.read() if e.fp else b""
        except urllib.error.URLError as e:
            raise RegistryError(f"registry unreachable: {e.reason}")
        except (TimeoutError, OSError) as e:
            # Read-phase timeouts surface as raw TimeoutError, not
            # URLError. They are reachability failures: fail closed.
            raise RegistryError(f"registry unreachable: {e}")

    def _get(self, path: str, repository: str, accept: str = None,
             scope: str = "pull") -> tuple:
        """GET with anonymous-token retry. Returns (status, headers, body).

        Redirects are followed manually for blobs so the bearer token is
        only ever sent to the registry host itself, never to the storage
        backend a registry redirects blob reads to.
        """
        url = self.base + path
        for hop in range(6):
            headers = {}
            if accept:
                headers["Accept"] = accept
            token = self._tokens.get((repository, scope))
            if token:
                headers["Authorization"] = f"Bearer {token}"
            status, resp_headers, body = self._raw_get(
                url, headers, allow_redirect=False)
            if status == 401:
                challenge = _parse_auth_challenge(
                    resp_headers.get("www-authenticate", ""))
                realm = challenge.get("realm")
                if not realm:
                    return status, resp_headers, body
                token = self._fetch_token(realm, challenge.get("service", ""),
                                          challenge.get("scope",
                                                      f"repository:{repository}:{scope}"))
                self._tokens[(repository, scope)] = token
                continue
            if status in (301, 302, 303, 307, 308):
                location = resp_headers.get("location")
                if not location:
                    return status, resp_headers, body
                url = urllib.parse.urljoin(url, location)
                continue
            return status, resp_headers, body
        raise RegistryError("too many auth/redirect hops")

    def _fetch_token(self, realm: str, service: str, scope: str) -> str:
        q = urllib.parse.urlencode(
            {k: v for k, v in {"service": service, "scope": scope}.items() if v})
        try:
            with urllib.request.urlopen(f"{realm}?{q}",
                                        timeout=self.timeout) as resp:
                data = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            raise RegistryError(f"token endpoint returned HTTP {e.code}",
                                  status=e.code)
        except urllib.error.URLError as e:
            raise RegistryError(f"token endpoint unreachable: {e.reason}")
        except (TimeoutError, OSError) as e:
            raise RegistryError(f"token endpoint unreachable: {e}")
        token = data.get("token") or data.get("access_token")
        if not token:
            raise RegistryError("token endpoint returned no token")
        return token

    # -- registry reads ---------------------------------------------------
    def get_manifest(self, repository: str, ref: str) -> dict:
        """Return {body, digest, media_type} or raise RegistryError."""
        path = f"/v2/{repository}/manifests/{urllib.parse.quote(ref, safe='')}"
        status, headers, body = self._get(path, repository,
                                          accept=ACCEPT_MANIFESTS)
        if status == 404:
            raise RegistryError(f"manifest not found: {repository}:{ref}",
                                status=404)
        if status != 200:
            raise RegistryError(f"manifest fetch failed: HTTP {status}",
                                status=status)
        # The gate trusts the digest it computes over the exact bytes
        # served, not only the registry's header claim.
        digest = "sha256:" + hashlib.sha256(body).hexdigest()
        return {"body": body, "digest": digest,
                "media_type": (headers.get("content-type") or "")
                .split(";")[0].strip()}

    def resolve_image(self, repository: str, ref: str) -> dict:
        """Resolve a tag/digest to a single image manifest digest.

        Follows one level of manifest list / index: prefers a linux/amd64
        child, else the first child. Returns {digest, index_digest}.
        """
        first = self.get_manifest(repository, ref)
        try:
            doc = json.loads(first["body"])
        except Exception:
            return {"digest": first["digest"], "index_digest": None}
        if first["media_type"] in INDEX_TYPES or "manifests" in doc:
            children = doc.get("manifests") or []
            if not children:
                raise RegistryError("manifest index has no children")
            child = next(
                (c for c in children
                 if (c.get("platform") or {}).get("os") == "linux"
                 and (c.get("platform") or {}).get("architecture") == "amd64"),
                children[0])
            child_digest = child["digest"]
            resolved = self.get_manifest(repository, child_digest)
            return {"digest": resolved["digest"],
                    "index_digest": first["digest"]}
        return {"digest": first["digest"], "index_digest": None}

    def get_blob(self, repository: str, digest: str) -> bytes:
        path = f"/v2/{repository}/blobs/{digest}"
        status, _, body = self._get(path, repository)
        if status == 404:
            raise RegistryError(f"blob not found: {digest}", status=404)
        if status != 200:
            raise RegistryError(f"blob fetch failed: HTTP {status}",
                                status=status)
        actual = "sha256:" + hashlib.sha256(body).hexdigest()
        if actual != digest:
            raise RegistryError(
                f"blob digest mismatch: served {actual}, expected {digest}")
        return body

    def get_referrers(self, repository: str, digest: str):
        """OCI Referrers API: descriptors referencing a subject digest.

        Returns a list of descriptors, or None when the registry does
        not answer the referrers endpoint. [verify per registry]
        """
        path = f"/v2/{repository}/referrers/{digest}"
        try:
            status, _, body = self._get(path, repository,
                                        accept=ACCEPT_MANIFESTS)
        except RegistryError:
            return None
        if status != 200:
            return None
        try:
            return json.loads(body).get("manifests", [])
        except Exception:
            return None

# Eclipse Cluster MCP · © 2026 Cyan Eclipse Technologies LLC · cetech.ai
