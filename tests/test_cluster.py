"""Eclipse Cluster K0 — verification-gate test suite.

Runs fully offline against a local stub registry (tests/fixtures.py)
serving cosign-layout fixture images signed by the openssl binary.
Verification under test is the gate's pure-stdlib implementation.

Run:  python3 -m unittest discover -s tests -v
Live-registry test (opt-in):  ECLIPSE_CLUSTER_LIVE=1 python3 -m unittest ...
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))

import fixtures  # noqa: E402
import server  # noqa: E402


class GateCase(unittest.TestCase):
    """Base: stub registry + keys A (EC, policy signer), B (EC, stranger),
    C (Ed25519, in trust bundle but NOT in the test policy)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="cluster-test-"))
        cls.priv_a, cls.pub_a = fixtures.make_key("ec", cls.tmp, "a")
        cls.priv_b, cls.pub_b = fixtures.make_key("ec", cls.tmp, "b")
        cls.priv_c, cls.pub_c = fixtures.make_key("ed25519", cls.tmp, "c")
        cls.stub = fixtures.StubRegistry().start()
        cls.repo = "cetech/widget"

        trust = {"keys": [
            {"key_id": "key-a", "identity": "Release signer A",
             "issuer": None, "public_key_pem": cls.pub_a},
            {"key_id": "key-c", "identity": "Other signer C",
             "issuer": None, "public_key_pem": cls.pub_c}]}
        (cls.tmp / "trust.json").write_text(json.dumps(trust))

        pol_dir = cls.tmp / "policies"
        pol_dir.mkdir()
        cls.strict = {"policy_id": "strict",
                      "allowed_registries": [cls.stub.host],
                      "signers": [{"key_id": "key-a"}],
                      "required_provenance": {
                          "required": True,
                          "predicate_types": [fixtures.SLSA]}}
        cls.sigonly = {"policy_id": "sigonly",
                       "allowed_registries": [cls.stub.host],
                       "signers": [{"key_id": "key-a"}],
                       "required_provenance": {"required": False,
                                               "predicate_types": []}}
        cls.elsewhere = {"policy_id": "elsewhere",
                         "allowed_registries": ["ghcr.io"],
                         "signers": [{"key_id": "key-a"}],
                         "required_provenance": {"required": False,
                                                 "predicate_types": []}}
        for p in (cls.strict, cls.sigonly, cls.elsewhere):
            (pol_dir / f"{p['policy_id']}.json").write_text(json.dumps(p))

        os.environ["ECLIPSE_CLUSTER_POLICIES"] = str(pol_dir)
        os.environ["ECLIPSE_CLUSTER_TRUST"] = str(cls.tmp / "trust.json")
        os.environ["ECLIPSE_CLUSTER_RECEIPTS"] = str(cls.tmp / "receipts.jsonl")

    @classmethod
    def tearDownClass(cls):
        cls.stub.stop()

    def verify(self, image, policy_id):
        return server.t_verify_image({"image": image,
                                      "policy_id": policy_id})

    def checks(self, verdict):
        return {c["name"]: c["status"] for c in verdict["checks"]}

    def image_ref(self, repo=None, tag="v1"):
        return f"{self.stub.host}/{repo or self.repo}:{tag}"


class TestPassPaths(GateCase):
    def test_ec_signed_with_provenance_passes(self):
        fixtures.build_image(self.stub, self.repo, tag="good",
                             sign=("ec", self.priv_a),
                             attest=("ec", self.priv_a),
                             payload_ref=f"{self.stub.host}/{self.repo}")
        v = self.verify(self.image_ref(tag="good"), "strict")
        self.assertEqual(v["verdict"], "PASS", json.dumps(v, indent=1))
        c = self.checks(v)
        for name in ("registry_allowlisted", "manifest_resolved",
                     "signature_present", "signature_valid",
                     "signer_matches_policy", "payload_digest_matches",
                     "payload_reference_matches", "provenance_present",
                     "provenance_valid", "provenance_predicate_matches"):
            self.assertEqual(c[name], "PASS", f"{name}: {c[name]}")
        self.assertIn("receipt", v)

    def test_ed25519_signed_passes_sigonly(self):
        # Policy names key-a only for provenance; for the sig-only path we
        # sign with A but as Ed25519-style raw? A is EC — use C via a
        # dedicated policy instead: build one naming key-c.
        pol = dict(self.sigonly, policy_id="sigonly-c",
                   signers=[{"key_id": "key-c"}])
        (Path(os.environ["ECLIPSE_CLUSTER_POLICIES"]) / "sigonly-c.json") \
            .write_text(json.dumps(pol))
        fixtures.build_image(self.stub, self.repo, tag="ed",
                             sign=("ed25519", self.priv_c),
                             payload_ref=f"{self.stub.host}/{self.repo}")
        v = self.verify(self.image_ref(tag="ed"), "sigonly-c")
        self.assertEqual(v["verdict"], "PASS", json.dumps(v, indent=1))
        c = self.checks(v)
        self.assertEqual(c["signature_valid"], "PASS")
        self.assertEqual(c["provenance_present"], "NA")


class TestFailPaths(GateCase):
    def test_wrong_signer_fails(self):
        fixtures.build_image(self.stub, self.repo, tag="wrong",
                             sign=("ec", self.priv_b),
                             payload_ref=f"{self.stub.host}/{self.repo}")
        v = self.verify(self.image_ref(tag="wrong"), "sigonly")
        self.assertEqual(v["verdict"], "FAIL")
        c = self.checks(v)
        self.assertEqual(c["signature_present"], "PASS")
        self.assertEqual(c["signature_valid"], "FAIL")
        self.assertEqual(c["signer_matches_policy"], "FAIL")

    def test_signer_in_bundle_but_not_in_policy_fails(self):
        fixtures.build_image(self.stub, self.repo, tag="other",
                             sign=("ed25519", self.priv_c),
                             payload_ref=f"{self.stub.host}/{self.repo}")
        v = self.verify(self.image_ref(tag="other"), "sigonly")
        self.assertEqual(v["verdict"], "FAIL")
        c = self.checks(v)
        self.assertEqual(c["signature_valid"], "PASS")  # crypto is fine
        self.assertEqual(c["signer_matches_policy"], "FAIL")  # policy says no

    def test_tampered_digest_fails(self):
        real = fixtures.build_image(self.stub, self.repo, tag="victim")
        fixtures.build_image(
            self.stub, self.repo, tag="tampered",
            sign=("ec", self.priv_a), payload_digest_override=real,
            payload_ref=f"{self.stub.host}/{self.repo}")
        v = self.verify(self.image_ref(tag="tampered"), "sigonly")
        self.assertEqual(v["verdict"], "FAIL")
        c = self.checks(v)
        self.assertEqual(c["signature_valid"], "PASS")  # sig is genuine...
        self.assertEqual(c["payload_digest_matches"], "FAIL")  # ...for another image

    def test_unsigned_fails(self):
        fixtures.build_image(self.stub, self.repo, tag="bare")
        v = self.verify(self.image_ref(tag="bare"), "sigonly")
        self.assertEqual(v["verdict"], "FAIL")
        self.assertEqual(self.checks(v)["signature_present"], "FAIL")

    def test_missing_provenance_fails_strict(self):
        fixtures.build_image(self.stub, self.repo, tag="noatt",
                             sign=("ec", self.priv_a),
                             payload_ref=f"{self.stub.host}/{self.repo}")
        v = self.verify(self.image_ref(tag="noatt"), "strict")
        self.assertEqual(v["verdict"], "FAIL")
        self.assertEqual(self.checks(v)["provenance_present"], "FAIL")

    def test_registry_not_allowlisted_fails_without_contact(self):
        before = len(self.stub.requests)
        v = self.verify(self.image_ref(tag="good"), "elsewhere")
        self.assertEqual(v["verdict"], "FAIL")
        self.assertEqual(self.checks(v)["registry_allowlisted"], "FAIL")
        self.assertEqual(len(self.stub.requests), before,
                         "gate contacted a non-allowlisted registry")

    def test_unreachable_registry_fails_closed(self):
        pol = dict(self.sigonly, policy_id="dead",
                   allowed_registries=["127.0.0.1:1"])
        (Path(os.environ["ECLIPSE_CLUSTER_POLICIES"]) / "dead.json") \
            .write_text(json.dumps(pol))
        v = self.verify("127.0.0.1:1/cetech/widget:v1", "dead")
        self.assertEqual(v["verdict"], "FAIL")
        self.assertEqual(self.checks(v)["manifest_resolved"], "FAIL")
        self.assertIn("receipt", v)  # failures are receipted too


class TestPolicyAndReceipts(GateCase):
    def test_policy_show(self):
        out = server.t_policy_show({})
        ids = {p["policy_id"] for p in out["policies"]}
        self.assertIn("strict", ids)
        key_ids = {k["key_id"] for k in out["trust_keys"]}
        self.assertEqual(key_ids, {"key-a", "key-c"})
        for k in out["trust_keys"]:
            self.assertTrue(k["fingerprint"].startswith("sha256:"))

    def test_receipt_chain_valid(self):
        fixtures.build_image(self.stub, self.repo, tag="chain",
                             sign=("ec", self.priv_a),
                             payload_ref=f"{self.stub.host}/{self.repo}")
        self.verify(self.image_ref(tag="chain"), "sigonly")
        out = server.t_receipt_list({"limit": 500})
        self.assertTrue(out["chain_valid"])
        self.assertGreaterEqual(out["total"], 1)
        mine = [e for e in out["entries"]
                if e["image"] == self.image_ref(tag="chain")]
        self.assertEqual(len(mine), 1)
        self.assertEqual(mine[0]["verdict"], "PASS")

    def test_unknown_policy_fails_closed(self):
        v = server.t_verify_image({"image": self.image_ref(),
                                   "policy_id": "nope"})
        self.assertEqual(v["verdict"], "FAIL")


@unittest.skipUnless(os.environ.get("ECLIPSE_CLUSTER_LIVE"),
                     "live registry test is opt-in (ECLIPSE_CLUSTER_LIVE=1)")
class TestLiveRegistry(GateCase):
    def test_public_image_fails_gate_not_errors(self):
        # A real public image carries no signature from our release
        # signer: the gate must answer FAIL with reasons, never PASS.
        pol = {"policy_id": "live",
               "allowed_registries": ["docker.io"],
               "signers": [{"key_id": "key-a"}],
               "required_provenance": {"required": False,
                                       "predicate_types": []}}
        v = server.t_verify_image(
            {"image": "docker.io/library/hello-world:latest",
             "policy": pol})
        # Either the registry answers (digest resolves, signature checks
        # fail) or this host's egress blocks it (resolution fails). Both
        # must be a FAIL verdict with a receipt — never PASS, never a
        # raised exception escaping the tool.
        self.assertEqual(v["verdict"], "FAIL")
        c = self.checks(v)
        if c["manifest_resolved"] == "PASS":
            self.assertIsNotNone(v["resolved_digest"])
            self.assertEqual(c["signer_matches_policy"], "FAIL")
        self.assertIn("receipt", v)


if __name__ == "__main__":
    unittest.main()
