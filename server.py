#!/usr/bin/env python3
"""Eclipse Cluster MCP — v0.1.0, K0: the signed-image verification gate.

Powered by Cyan Eclipse Technologies (cetech.ai).

Spec: eclipse-cluster-container-spec-20261025.md §5 rule 1 + §8 phase K0.
Cluster's first rule is that a workload starts only from an image whose
signature AND provenance verify pre-run. This server is that pre-run
check, usable before any container runtime exists: it talks to OCI
registries over HTTPS (read-only), verifies cosign-style signatures and
DSSE/in-toto provenance against a written policy and a local trust
bundle, and returns a CertBridge-shaped verdict — PASS/FAIL per check,
never a shrug.

FAIL-CLOSED, everywhere: an unreachable registry, a missing signature,
an unknown signer, a tampered digest — each is a FAIL with a reason.
There is no code path that returns PASS by default, and every verdict —
pass or fail — is appended to a hash-chained receipt ledger.

Verification is pure Python stdlib (see sigverify.py): ECDSA P-256,
Ed25519, RSA. Out of scope for v0.1: keyless/Fulcio certificate
signatures (a signature object carrying only a certificate chain fails
the signer check, with that reason stated), image building/scanning,
and all runtime/orchestration phases (K1+).

Transport: MCP over stdio (newline-delimited JSON-RPC 2.0), stdlib only.
CLI mirror: `python3 server.py verify <image> [--policy <id>]`,
`python3 server.py policies`, `python3 server.py receipts [--limit N]`.

Config (environment):
  ECLIPSE_CLUSTER_POLICIES   dir of policy JSON files (default ./policies)
  ECLIPSE_CLUSTER_TRUST      trust bundle JSON (default ./trust-bundle.json)
  ECLIPSE_CLUSTER_RECEIPTS   receipt ledger JSONL (default ./receipts.jsonl)
"""
import base64
import hashlib
import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import registry as reg_mod  # noqa: E402
import sigverify  # noqa: E402

VERSION = "0.1.0"
SIG_MEDIA_TYPE = "application/vnd.dev.cosign.simplesigning.v1+json"
ATT_MEDIA_TYPE = "application/vnd.dsse.envelope.v1+json"
SIG_ANNOTATION = "dev.cosignproject.cosign/signature"
CERT_ANNOTATION = "dev.cosignproject.cosign/certificate"
SLSA_PREDICATE = "https://slsa.dev/provenance/v1"


class ToolError(Exception):
    pass


# --------------------------------------------------------------------- config
def cfg() -> dict:
    here = Path(__file__).parent
    return {
        "policies_dir": Path(os.environ.get(
            "ECLIPSE_CLUSTER_POLICIES", here / "policies")),
        "trust_path": Path(os.environ.get(
            "ECLIPSE_CLUSTER_TRUST", here / "trust-bundle.json")),
        "receipts_path": Path(os.environ.get(
            "ECLIPSE_CLUSTER_RECEIPTS", here / "receipts.jsonl")),
    }


def load_policies() -> dict:
    out = {}
    d = cfg()["policies_dir"]
    if d.is_dir():
        for p in sorted(d.glob("*.json")):
            try:
                doc = json.loads(p.read_text())
                if doc.get("policy_id"):
                    out[doc["policy_id"]] = doc
            except Exception:
                continue  # a malformed policy file is simply not a policy
    return out


def load_trust_keys() -> list:
    """Trust bundle -> [{key_id, identity, issuer, key(parsed), fingerprint}]."""
    path = cfg()["trust_path"]
    keys = []
    if path.exists():
        try:
            bundle = json.loads(path.read_text())
        except Exception:
            return []
        for entry in bundle.get("keys", []):
            pem = entry.get("public_key_pem", "")
            try:
                parsed = sigverify.parse_public_key(pem)
            except Exception:
                continue  # unparseable key material can never verify: skip
            keys.append({"key_id": entry.get("key_id", ""),
                         "identity": entry.get("identity", ""),
                         "issuer": entry.get("issuer"),
                         "key": parsed,
                         "fingerprint": sigverify.key_fingerprint(pem)})
    return keys


def policy_signer_keys(policy: dict, trust_keys: list) -> list:
    wanted = {s.get("key_id") for s in policy.get("signers", [])}
    return [k for k in trust_keys if k["key_id"] in wanted]


# --------------------------------------------------------------------- receipts
def append_receipt(verdict: dict) -> dict:
    path = cfg()["receipts_path"]
    prev_hash, seq = "GENESIS", 0
    if path.exists():
        lines = [l for l in path.read_text().splitlines() if l.strip()]
        if lines:
            last = json.loads(lines[-1])
            prev_hash, seq = last["entry_hash"], last["seq"]
    entry = {"seq": seq + 1,
             "ts": datetime.now(timezone.utc).isoformat(),
             "event": "image_verification",
             "image": verdict["image"],
             "resolved_digest": verdict.get("resolved_digest"),
             "policy_id": verdict["policy_id"],
             "verdict": verdict["verdict"],
             "checks": {c["name"]: c["status"] for c in verdict["checks"]},
             "prev_hash": prev_hash}
    entry["entry_hash"] = hashlib.sha256(
        (prev_hash + json.dumps(entry, sort_keys=True)).encode()).hexdigest()
    with path.open("a") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")
    return entry


def read_receipts(limit: int = 50, image: str = None) -> dict:
    path = cfg()["receipts_path"]
    entries, chain_ok, prev = [], True, "GENESIS"
    if path.exists():
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            e = json.loads(line)
            expect = hashlib.sha256(
                (prev + json.dumps({k: v for k, v in e.items()
                                    if k != "entry_hash"},
                                   sort_keys=True)).encode()).hexdigest()
            if e.get("prev_hash") != prev or e.get("entry_hash") != expect:
                chain_ok = False
            prev = e["entry_hash"]
            entries.append(e)
    if image:
        entries = [e for e in entries if e["image"] == image]
    return {"entries": entries[-limit:], "total": len(entries),
            "chain_valid": chain_ok}


# --------------------------------------------------------------------- gate
class Check:
    def __init__(self, name):
        self.name, self.status, self.detail = name, "FAIL", ""

    def set(self, status, detail):
        self.status, self.detail = status, detail
        return self

    def skip(self, why):
        return self.set("FAIL", f"not evaluated — {why} (fail-closed)")

    def as_dict(self):
        return {"name": self.name, "status": self.status,
                "detail": self.detail}


def _find_artifact(client, repository, digest, kind):
    """Locate a cosign .sig/.att manifest: derived tag first, then the
    OCI Referrers API. Returns the parsed manifest doc or None."""
    hexpart = digest.split(":", 1)[1]
    try:
        found = client.get_manifest(repository, f"sha256-{hexpart}.{kind}")
        return json.loads(found["body"])
    except reg_mod.RegistryError as e:
        if e.status != 404:
            raise
    referrers = client.get_referrers(repository, digest) or []
    want = SIG_MEDIA_TYPE if kind == "sig" else ATT_MEDIA_TYPE
    for desc in referrers:
        if desc.get("artifactType") == want or \
                (desc.get("annotations") or {}).get("kind") == kind:
            try:
                found = client.get_manifest(repository, desc["digest"])
                return json.loads(found["body"])
            except reg_mod.RegistryError:
                continue
    return None


def _layer_blob(client, repository, doc, media_type):
    for layer in doc.get("layers", []):
        if layer.get("mediaType") == media_type:
            return client.get_blob(repository, layer["digest"]), layer
    return None, None


def _signature_b64(doc):
    """Cosign stores the signature in the manifest annotation
    dev.cosignproject.cosign/signature (some versions annotate the
    layer descriptor instead — check both). [verify per cosign version]
    """
    ann = doc.get("annotations") or {}
    if ann.get(SIG_ANNOTATION):
        return ann[SIG_ANNOTATION], ann
    for layer in doc.get("layers", []):
        lann = layer.get("annotations") or {}
        if lann.get(SIG_ANNOTATION):
            return lann[SIG_ANNOTATION], lann
    return None, ann


def run_verification(image_ref: str, policy: dict) -> dict:
    checks = {name: Check(name) for name in [
        "registry_allowlisted", "manifest_resolved", "signature_present",
        "signature_valid", "signer_matches_policy", "payload_digest_matches",
        "payload_reference_matches", "provenance_present",
        "provenance_valid", "provenance_predicate_matches"]}
    verdict = {"gate": "eclipse-cluster-k0", "version": VERSION,
               "image": image_ref, "resolved_digest": None,
               "index_digest": None,
               "policy_id": policy.get("policy_id", "<none>"),
               "timestamp": datetime.now(timezone.utc).isoformat(),
               "checks": [], "verdict": "FAIL"}
    trust_keys = load_trust_keys()
    signers = policy_signer_keys(policy, trust_keys)

    try:
        parsed = reg_mod.parse_image_ref(image_ref)
    except ValueError as e:
        checks["registry_allowlisted"].set("FAIL", str(e))
        for c in checks.values():
            if c.name != "registry_allowlisted":
                c.skip("unparseable image reference")
        verdict["checks"] = [c.as_dict() for c in checks.values()]
        return verdict
    verdict["image_parsed"] = parsed
    repository = parsed["repository"]

    allowed = policy.get("allowed_registries", [])
    if parsed["registry"] not in allowed:
        checks["registry_allowlisted"].set(
            "FAIL", f"registry {parsed['registry']} not in policy allowlist "
                    f"{allowed}; no registry contact made")
        for name, c in checks.items():
            if name != "registry_allowlisted":
                c.skip("registry not allowlisted")
        verdict["checks"] = [c.as_dict() for c in checks.values()]
        return verdict
    checks["registry_allowlisted"].set(
        "PASS", f"{parsed['registry']} is allowlisted by policy "
                f"{policy.get('policy_id')}")

    client = reg_mod.RegistryClient(parsed["registry"])
    ref = parsed["digest"] or parsed["tag"]
    try:
        resolved = client.resolve_image(repository, ref)
    except reg_mod.RegistryError as e:
        checks["manifest_resolved"].set("FAIL", f"manifest resolution "
                                               f"failed: {e}")
        for name, c in checks.items():
            if name not in ("registry_allowlisted", "manifest_resolved"):
                c.skip("manifest unresolved")
        verdict["checks"] = [c.as_dict() for c in checks.values()]
        return verdict
    digest = resolved["digest"]
    verdict["resolved_digest"] = digest
    verdict["index_digest"] = resolved["index_digest"]
    if parsed["digest"] and parsed["digest"] != digest:
        checks["manifest_resolved"].set(
            "FAIL", f"reference pins {parsed['digest']} but resolution "
                    f"yielded {digest} — possible tampering or moved tag")
        for name, c in checks.items():
            if name not in ("registry_allowlisted", "manifest_resolved"):
                c.skip("pinned digest mismatch")
        verdict["checks"] = [c.as_dict() for c in checks.values()]
        return verdict
    checks["manifest_resolved"].set(
        "PASS", f"resolved to {digest}"
        + (f" via index {resolved['index_digest']}" if resolved["index_digest"] else ""))

    # ---- signature object -------------------------------------------
    sig_doc = None
    try:
        sig_doc = _find_artifact(client, repository, digest, "sig")
    except reg_mod.RegistryError as e:
        checks["signature_present"].set(
            "FAIL", f"signature lookup failed: {e}")
    if sig_doc is None and checks["signature_present"].status != "FAIL":
        checks["signature_present"].set(
            "FAIL", f"no signature object found for {digest} "
                    f"(sha256-*.sig tag and referrers both empty)")
    payload = None
    if sig_doc is not None:
        checks["signature_present"].set(
            "PASS", "signature object located (cosign layout)")
        sig_b64, sig_ann = _signature_b64(sig_doc)
        try:
            payload, _ = _layer_blob(client, repository, sig_doc,
                                     SIG_MEDIA_TYPE)
        except reg_mod.RegistryError as e:
            checks["signature_valid"].set(
                "FAIL", f"signature payload blob unreadable: {e}")
        if sig_b64 is None:
            checks["signature_valid"].set(
                "FAIL", "signature object carries no signature value; "
                        "keyless/certificate-only signatures are not "
                        "accepted by this gate build")
            checks["signer_matches_policy"].skip("no signature value")
        elif payload is not None:
            validated_by = None
            for key in trust_keys:
                if sigverify.verify_signature(key["key"], payload, sig_b64):
                    validated_by = key
                    break
            if validated_by is None:
                checks["signature_valid"].set(
                    "FAIL", "signature does not verify under any key in "
                            "the local trust bundle (unknown signer or "
                            "corrupt signature)")
                checks["signer_matches_policy"].set(
                    "FAIL", "no policy signer validated the signature")
            else:
                checks["signature_valid"].set(
                    "PASS", f"signature verifies under trust-bundle key "
                            f"{validated_by['key_id']}")
                if any(k["key_id"] == validated_by["key_id"]
                       for k in signers):
                    checks["signer_matches_policy"].set(
                        "PASS", f"signer {validated_by['key_id']} "
                                f"({validated_by['identity']}) is named "
                                f"by policy {policy.get('policy_id')}")
                else:
                    checks["signer_matches_policy"].set(
                        "FAIL", f"signature is valid but signer "
                                f"{validated_by['key_id']} is not named "
                                f"by policy {policy.get('policy_id')}")
        # payload binding checks run whenever a payload was recovered
        if payload is not None:
            try:
                doc = json.loads(payload)
                claimed = (doc.get("critical", {}).get("image", {})
                           .get("docker-manifest-digest"))
                ref_claim = (doc.get("critical", {}).get("identity", {})
                             .get("docker-reference"))
            except Exception:
                claimed, ref_claim = None, None
            if claimed == digest:
                checks["payload_digest_matches"].set(
                    "PASS", "signed payload names the resolved digest")
            else:
                checks["payload_digest_matches"].set(
                    "FAIL", f"signed payload names {claimed!r}, resolved "
                            f"image is {digest} — signature was made for "
                            f"a different image (tamper or substitution)")
            full_ref = f"{parsed['registry']}/{repository}"
            if ref_claim in (repository, full_ref):
                checks["payload_reference_matches"].set(
                    "PASS", f"signed payload reference {ref_claim} matches")
            else:
                checks["payload_reference_matches"].set(
                    "FAIL", f"signed payload reference {ref_claim!r} does "
                            f"not match {full_ref}")
        else:
            checks["payload_digest_matches"].skip("no signature payload")
            checks["payload_reference_matches"].skip("no signature payload")

    # ---- provenance attestation --------------------------------------
    prov_req = policy.get("required_provenance") or {}
    if not prov_req.get("required"):
        checks["provenance_present"].set(
            "NA", "policy does not require provenance")
        checks["provenance_valid"].set(
            "NA", "policy does not require provenance")
        checks["provenance_predicate_matches"].set(
            "NA", "policy does not require provenance")
    else:
        att_doc = None
        try:
            att_doc = _find_artifact(client, repository, digest, "att")
        except reg_mod.RegistryError as e:
            checks["provenance_present"].set(
                "FAIL", f"attestation lookup failed: {e}")
        if att_doc is None and \
                checks["provenance_present"].status != "FAIL":
            checks["provenance_present"].set(
                "FAIL", f"policy requires provenance but no attestation "
                        f"object found for {digest}")
        if att_doc is not None:
            checks["provenance_present"].set(
                "PASS", "attestation object located (cosign layout)")
            envelope_bytes, _ = (None, None)
            try:
                envelope_bytes, _ = _layer_blob(client, repository,
                                                att_doc, ATT_MEDIA_TYPE)
            except reg_mod.RegistryError as e:
                checks["provenance_valid"].set(
                    "FAIL", f"attestation envelope unreadable: {e}")
            if envelope_bytes is not None:
                try:
                    envelope = json.loads(envelope_bytes)
                    payload_bytes = base64.b64decode(envelope["payload"])
                    statement = json.loads(payload_bytes)
                except Exception as e:
                    envelope, statement = None, None
                    checks["provenance_valid"].set(
                        "FAIL", f"attestation envelope malformed: {e}")
                if statement is not None:
                    pae = sigverify.dsse_pae(
                        envelope.get("payloadType",
                                     "application/vnd.in-toto+json"),
                        payload_bytes)
                    ok_by = None
                    for s in envelope.get("signatures", []):
                        for key in signers:
                            if sigverify.verify_signature(
                                    key["key"], pae, s.get("sig", "")):
                                ok_by = key
                                break
                        if ok_by:
                            break
                    subjects = statement.get("subject", [])
                    subj_digests = {
                        "sha256:" + (s.get("digest") or {}).get("sha256", "")
                        for s in subjects}
                    if ok_by is None:
                        checks["provenance_valid"].set(
                            "FAIL", "DSSE envelope signature does not "
                                    "verify under any policy signer")
                    elif digest not in subj_digests:
                        checks["provenance_valid"].set(
                            "FAIL", "attestation subject does not name "
                                    "the resolved image digest")
                    else:
                        checks["provenance_valid"].set(
                            "PASS", f"DSSE envelope verifies under policy "
                                    f"signer {ok_by['key_id']} and names "
                                    f"the resolved digest")
                    wanted = prov_req.get("predicate_types") or []
                    got = statement.get("predicateType")
                    if not wanted or got in wanted:
                        checks["provenance_predicate_matches"].set(
                            "PASS", f"predicateType {got}")
                    else:
                        checks["provenance_predicate_matches"].set(
                            "FAIL", f"predicateType {got!r} not in policy "
                                    f"list {wanted}")

    verdict["checks"] = [c.as_dict() for c in checks.values()]
    verdict["verdict"] = "PASS" if all(
        c["status"] in ("PASS", "NA") for c in verdict["checks"]) else "FAIL"
    return verdict


# --------------------------------------------------------------------- tools
def t_verify_image(args):
    image = str(args.get("image", "")).strip()
    if not image:
        raise ToolError("image is required")
    policies = load_policies()
    if args.get("policy"):
        policy = args["policy"]
        if not isinstance(policy, dict) or not policy.get("policy_id"):
            raise ToolError("inline policy must be an object with policy_id")
    else:
        pid = args.get("policy_id") or "default"
        policy = policies.get(pid)
        if policy is None and pid == "default" and policies:
            policy = next(iter(policies.values()))
    if policy is None:
        verdict = {"gate": "eclipse-cluster-k0", "version": VERSION,
                   "image": image, "resolved_digest": None,
                   "policy_id": args.get("policy_id") or "default",
                   "timestamp": datetime.now(timezone.utc).isoformat(),
                   "checks": [{"name": "policy_loaded", "status": "FAIL",
                               "detail": "no such policy; the gate fails "
                                         "closed rather than inventing one"}],
                   "verdict": "FAIL"}
    else:
        verdict = run_verification(image, policy)
    entry = append_receipt(verdict)
    verdict["receipt"] = {"seq": entry["seq"],
                          "entry_hash": entry["entry_hash"]}
    return verdict


def t_policy_show(args):
    c = cfg()
    policies = load_policies()
    keys = [{"key_id": k["key_id"], "identity": k["identity"],
             "issuer": k["issuer"], "algorithm": k["key"]["algorithm"],
             "fingerprint": k["fingerprint"]} for k in load_trust_keys()]
    return {"policies": list(policies.values()),
            "trust_keys": keys,
            "config": {"policies_dir": str(c["policies_dir"]),
                       "trust_bundle": str(c["trust_path"]),
                       "receipts": str(c["receipts_path"])},
            "gate": "eclipse-cluster-k0", "version": VERSION}


def t_receipt_list(args):
    return read_receipts(limit=int(args.get("limit", 50)),
                         image=args.get("image"))


TOOLS = {
    "verify_image": (t_verify_image,
                     "Verify a container image against policy BEFORE it is "
                     "allowed anywhere near a runtime: registry allowlist, "
                     "digest resolution, cosign-style signature validity, "
                     "signer named by policy, payload binding, and DSSE "
                     "provenance. Returns a per-check PASS/FAIL verdict and "
                     "appends a receipt. Fails closed on every error.",
                     {"image": {"type": "string"},
                      "policy_id": {"type": "string"},
                      "policy": {"type": "object"}}, ["image"]),
    "policy_show": (t_policy_show,
                    "Show the loaded verification policies, the trust "
                    "bundle's public keys (fingerprints only), and config "
                    "paths. The written scope the gate enforces.",
                    {}, []),
    "receipt_list": (t_receipt_list,
                     "The append-only, hash-chained receipt ledger of "
                     "past verifications — passes and failures alike.",
                     {"limit": {"type": "integer"},
                      "image": {"type": "string"}}, []),
}


def tool_list():
    return [{"name": name, "description": desc,
             "inputSchema": {"type": "object", "properties": props,
                             "required": req}}
            for name, (_, desc, props, req) in TOOLS.items()]


def handle(req: dict):
    method, rid = req.get("method", ""), req.get("id")
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": req.get("params", {}).get("protocolVersion",
                                                         "2025-03-26"),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "eclipse-cluster", "version": VERSION}}}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": rid, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": tool_list()}}
    if method == "tools/call":
        name = req["params"]["name"]
        args = req["params"].get("arguments", {})
        if name not in TOOLS:
            return {"jsonrpc": "2.0", "id": rid, "error": {
                "code": -32602, "message": f"unknown tool {name}"}}
        try:
            out = TOOLS[name][0](args)
            return {"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text",
                             "text": json.dumps(out, indent=1)}]}}
        except ToolError as e:
            return {"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text",
                             "text": json.dumps({"error": str(e)})}],
                "isError": True}}
    if rid is not None:
        return {"jsonrpc": "2.0", "id": rid, "error": {
            "code": -32601, "message": f"method not found: {method}"}}
    return None  # notification


def main_stdio():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            resp = handle(json.loads(line))
        except Exception as e:  # never crash the transport
            resp = {"jsonrpc": "2.0", "id": None,
                    "error": {"code": -32603, "message": str(e)}}
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


def main_cli(argv):
    if argv[0] == "verify":
        image = argv[1]
        pid = None
        if "--policy" in argv:
            pid = argv[argv.index("--policy") + 1]
        out = t_verify_image({"image": image, "policy_id": pid})
        print(json.dumps(out, indent=1))
        return 0 if out["verdict"] == "PASS" else 1
    if argv[0] == "policies":
        print(json.dumps(t_policy_show({}), indent=1))
        return 0
    if argv[0] == "receipts":
        limit = 50
        if "--limit" in argv:
            limit = int(argv[argv.index("--limit") + 1])
        print(json.dumps(t_receipt_list({"limit": limit}), indent=1))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    if len(sys.argv) > 1:
        sys.exit(main_cli(sys.argv[1:]))
    main_stdio()
