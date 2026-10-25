#!/usr/bin/env python3
"""Eclipse Cluster K0 smoke test: drive the real MCP server over stdio
against a local stub registry with an openssl-signed fixture image.

Offline by design (loopback stub only). Prints a JSON summary and exits
nonzero on any failed expectation.

Run:  python3 smoke_test.py
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / "tests"))
import fixtures  # noqa: E402


def call(proc, rid, method, params=None):
    req = {"jsonrpc": "2.0", "id": rid, "method": method,
           "params": params or {}}
    proc.stdin.write(json.dumps(req) + "\n")
    proc.stdin.flush()
    return json.loads(proc.stdout.readline())


def tool_text(resp):
    return json.loads(resp["result"]["content"][0]["text"])


def main():
    tmp = Path(tempfile.mkdtemp(prefix="cluster-smoke-"))
    priv, pub = fixtures.make_key("ec", tmp, "smoke")
    stub = fixtures.StubRegistry().start()
    repo = "cetech/widget"
    fixtures.build_image(stub, repo, tag="v1", sign=("ec", priv),
                         attest=("ec", priv),
                         payload_ref=f"{stub.host}/{repo}")
    fixtures.build_image(stub, repo, tag="unsigned")

    pol_dir = tmp / "policies"
    pol_dir.mkdir()
    (pol_dir / "strict.json").write_text(json.dumps({
        "policy_id": "strict", "allowed_registries": [stub.host],
        "signers": [{"key_id": "smoke-key"}],
        "required_provenance": {"required": True,
                                "predicate_types": [fixtures.SLSA]}}))
    (tmp / "trust.json").write_text(json.dumps({"keys": [
        {"key_id": "smoke-key", "identity": "Smoke signer",
         "issuer": None, "public_key_pem": pub}]}))

    env = dict(os.environ,
               ECLIPSE_CLUSTER_POLICIES=str(pol_dir),
               ECLIPSE_CLUSTER_TRUST=str(tmp / "trust.json"),
               ECLIPSE_CLUSTER_RECEIPTS=str(tmp / "receipts.jsonl"))
    proc = subprocess.Popen([sys.executable, str(HERE / "server.py")],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            text=True, env=env)
    results = {}
    try:
        r = call(proc, 1, "initialize",
                 {"protocolVersion": "2025-03-26"})
        results["server"] = r["result"]["serverInfo"]
        r = call(proc, 2, "tools/list")
        results["tools"] = [t["name"] for t in r["result"]["tools"]]

        r = call(proc, 3, "tools/call",
                 {"name": "verify_image",
                  "arguments": {"image": f"{stub.host}/{repo}:v1",
                                "policy_id": "strict"}})
        good = tool_text(r)
        results["signed_image_verdict"] = good["verdict"]
        results["signed_image_checks"] = {
            c["name"]: c["status"] for c in good["checks"]}

        r = call(proc, 4, "tools/call",
                 {"name": "verify_image",
                  "arguments": {"image": f"{stub.host}/{repo}:unsigned",
                                "policy_id": "strict"}})
        bad = tool_text(r)
        results["unsigned_image_verdict"] = bad["verdict"]

        r = call(proc, 5, "tools/call", {"name": "policy_show",
                                         "arguments": {}})
        results["policies"] = [p["policy_id"]
                                for p in tool_text(r)["policies"]]

        r = call(proc, 6, "tools/call",
                 {"name": "receipt_list", "arguments": {"limit": 10}})
        led = tool_text(r)
        results["receipts"] = {"total": led["total"],
                               "chain_valid": led["chain_valid"]}
    finally:
        proc.kill()
        stub.stop()

    ok = (results["signed_image_verdict"] == "PASS"
          and results["unsigned_image_verdict"] == "FAIL"
          and results["receipts"]["chain_valid"]
          and results["receipts"]["total"] == 2
          and results["tools"] == ["verify_image", "policy_show",
                                   "receipt_list"])
    results["smoke"] = "PASS" if ok else "FAIL"
    print(json.dumps(results, indent=1))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
