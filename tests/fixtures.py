"""Test fixtures for Eclipse Cluster K0: a local stub OCI registry and
openssl-signed fixture images, in cosign's on-registry layout.

The stub implements just enough of the registry HTTP API for the gate:
anonymous bearer-token auth (401 + WWW-Authenticate -> /token), manifest
reads by tag or digest, blob reads, 404s. Signing is done with the
system openssl binary — an external signer, exactly how cosign-produced
objects arrive — while verification under test is the gate's pure-stdlib
code. Nothing here is used by the server at runtime.
"""
import base64
import hashlib
import json
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SIG_MT = "application/vnd.dev.cosign.simplesigning.v1+json"
ATT_MT = "application/vnd.dsse.envelope.v1+json"
SIG_ANNOTATION = "dev.cosignproject.cosign/signature"
SLSA = "https://slsa.dev/provenance/v1"


def sha(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def make_key(kind: str, workdir: Path, label: str = ""):
    """openssl keygen. kind: 'ec' (P-256) or 'ed25519'. Returns (priv, pub_pem)."""
    priv = workdir / f"key-{label or kind}.pem"
    pub = priv.with_suffix(".pub.pem")
    if kind == "ec":
        subprocess.run(["openssl", "ecparam", "-name", "prime256v1",
                        "-genkey", "-noout", "-out", str(priv)],
                       check=True, capture_output=True)
        subprocess.run(["openssl", "ec", "-in", str(priv), "-pubout",
                        "-out", str(pub)], check=True, capture_output=True)
    elif kind == "ed25519":
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519",
                        "-out", str(priv)], check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", str(priv), "-pubout",
                        "-out", str(pub)], check=True, capture_output=True)
    else:
        raise ValueError(kind)
    return priv, pub.read_text()


def sign_bytes(kind: str, priv: Path, data: bytes) -> bytes:
    # openssl one-shot signing (Ed25519) needs a real file with a size;
    # write the message out rather than piping it.
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        msg, sig = Path(td) / "msg", Path(td) / "sig"
        msg.write_bytes(data)
        if kind == "ec":  # DER-encoded ECDSA over SHA-256, as cosign emits
            subprocess.run(["openssl", "dgst", "-sha256", "-sign",
                            str(priv), "-out", str(sig), str(msg)],
                           check=True, capture_output=True)
        elif kind == "ed25519":  # raw 64-byte signature over the message
            subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey",
                            str(priv), "-rawin", "-in", str(msg),
                            "-out", str(sig)], check=True,
                           capture_output=True)
        else:
            raise ValueError(kind)
        return sig.read_bytes()


class StubRegistry:
    """In-memory registry: manifests keyed (repo, ref), blobs (repo, digest)."""

    def __init__(self):
        self.manifests = {}
        self.blobs = {}
        self.requests = []  # (method, path) — tests assert on contact
        self.httpd = None
        self.host = None

    # -- fixture population ----------------------------------------------
    def add_blob(self, repo, data: bytes) -> str:
        d = sha(data)
        self.blobs[(repo, d)] = data
        return d

    def add_manifest(self, repo, ref, doc: dict) -> str:
        body = json.dumps(doc, separators=(",", ":")).encode()
        self.manifests[(repo, ref)] = body
        self.manifests[(repo, sha(body))] = body
        return sha(body)

    # -- http --------------------------------------------------------------
    def start(self):
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body=b"", ctype="application/json",
                      extra=None):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                stub.requests.append(("GET", self.path))
                path = self.path.split("?", 1)[0]
                if path == "/token":
                    return self._send(200, json.dumps(
                        {"token": "stub-token"}).encode())
                if not path.startswith("/v2/"):
                    return self._send(404, b"{}")
                rest = path[len("/v2/"):]
                if self.headers.get("Authorization") != "Bearer stub-token":
                    realm = f"http://{stub.host}/token"
                    scope = "repository:pull"
                    return self._send(401, b"{}", extra={
                        "WWW-Authenticate":
                            f'Bearer realm="{realm}",service="stub",'
                            f'scope="{scope}"'})
                if "/manifests/" in rest:
                    repo, ref = rest.split("/manifests/", 1)
                    body = stub.manifests.get((repo, ref))
                    if body is None:
                        return self._send(404, b'{"errors":[{"code":'
                                               b'"MANIFEST_UNKNOWN"}]}')
                    return self._send(200, body, extra={
                        "Docker-Content-Digest": sha(body)})
                if "/blobs/" in rest:
                    repo, digest = rest.split("/blobs/", 1)
                    body = stub.blobs.get((repo, digest))
                    if body is None:
                        return self._send(404, b'{"errors":[{"code":'
                                               b'"BLOB_UNKNOWN"}]}')
                    return self._send(200, body,
                                      ctype="application/octet-stream")
                return self._send(404, b"{}")

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.host = f"127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever,
                         daemon=True).start()
        return self

    def stop(self):
        if self.httpd:
            self.httpd.shutdown()


def _empty_config(store: StubRegistry, repo) -> dict:
    d = store.add_blob(repo, b"{}")
    return {"mediaType": "application/vnd.oci.empty.v1+json",
            "digest": d, "size": 2}


def build_image(store: StubRegistry, repo: str, tag: str = "v1",
                sign=None, attest=None, payload_digest_override=None,
                payload_ref=None, predicate=SLSA):
    """Create a fixture image in the stub. sign/attest: (kind, priv_path)
    or None. Returns the image manifest digest."""
    # Config carries the tag so every fixture image has a DISTINCT
    # manifest digest — identical manifests would make signed/unsigned
    # fixtures indistinguishable to the gate.
    config = json.dumps({"architecture": "amd64", "os": "linux",
                         "fixture": f"{repo}:{tag}"}).encode()
    cfg_digest = store.add_blob(repo, config)
    manifest = {"schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                           "digest": cfg_digest, "size": len(config)},
                "layers": []}
    digest = store.add_manifest(repo, tag, manifest)
    hexpart = digest.split(":", 1)[1]

    if sign is not None:
        kind, priv = sign
        payload = {"critical": {
                       "identity": {"docker-reference":
                                    payload_ref or repo},
                       "image": {"docker-manifest-digest":
                                 payload_digest_override or digest},
                       "type": "cosign container image signature"},
                   "optional": None}
        payload_bytes = json.dumps(payload, separators=(",", ":")).encode()
        payload_digest = store.add_blob(repo, payload_bytes)
        sig = sign_bytes(kind, priv, payload_bytes)
        sig_manifest = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": _empty_config(store, repo),
            "layers": [{"mediaType": SIG_MT, "digest": payload_digest,
                        "size": len(payload_bytes)}],
            "annotations": {SIG_ANNOTATION:
                            base64.b64encode(sig).decode()}}
        store.add_manifest(repo, f"sha256-{hexpart}.sig", sig_manifest)

    if attest is not None:
        kind, priv = attest
        statement = {"_type": "https://in-toto.io/Statement/v1",
                     "subject": [{"name": repo,
                                  "digest": {"sha256": hexpart}}],
                     "predicateType": predicate,
                     "predicate": {"buildType": "fixture"}}
        stmt_bytes = json.dumps(statement, separators=(",", ":")).encode()
        ptype = b"application/vnd.in-toto+json"
        pae = (b"DSSEv1 " + str(len(ptype)).encode() + b" " + ptype + b" "
               + str(len(stmt_bytes)).encode() + b" " + stmt_bytes)
        sig = sign_bytes(kind, priv, pae)
        envelope = {"payload": base64.b64encode(stmt_bytes).decode(),
                    "payloadType": "application/vnd.in-toto+json",
                    "signatures": [{"keyid": "",
                                    "sig": base64.b64encode(sig).decode()}]}
        env_bytes = json.dumps(envelope, separators=(",", ":")).encode()
        env_digest = store.add_blob(repo, env_bytes)
        att_manifest = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": _empty_config(store, repo),
            "layers": [{"mediaType": ATT_MT, "digest": env_digest,
                        "size": len(env_bytes)}]}
        store.add_manifest(repo, f"sha256-{hexpart}.att", att_manifest)
    return digest
