# Eclipse Cluster MCP

**Powered by Cyan Eclipse Technologies** — https://cetech.ai

**Eclipse Cluster — the container substrate of the Constellation family: signed images, governed runtimes, orchestrated workloads, every action receipted.**

## What this build is (and is not)

**v0.1.0 implements phase K0 only** (spec: `eclipse-cluster-container-spec-20261025.md` §8): the **signed-image verification gate**. Before any image is allowed near a runtime, this server checks it against a written policy — registry allowlist, digest resolution, cosign-style signature, signer identity, DSSE/in-toto provenance — and returns a verdict that is PASS/FAIL **per check**, in the shape of a CertBridge result card.

It is deliberately usable **before any container runtime exists**: the host this was built on has no Docker, and none is required. Runtime, image-pipeline, and orchestration phases (K1–K3) are later work and are **not** in this build — no tool here can start, stop, or deploy anything.

## The gate fails closed

An unreachable registry, a missing signature, a valid signature from the *wrong* signer, a signature made for a different digest, a registry that isn't allowlisted — each is a **FAIL with a reason**. There is no PASS-by-default path. Every verdict, pass or fail, is appended to a **hash-chained receipt ledger**.

Checks, in order:

| Check | Question it answers |
|---|---|
| `registry_allowlisted` | Is this registry named in the policy? (No contact is made if not.) |
| `manifest_resolved` | Does the reference resolve to a concrete digest — and if the reference pinned a digest, does it match? |
| `signature_present` | Is there a cosign-layout signature object (`sha256-*.sig` tag, or the OCI Referrers API)? |
| `signature_valid` | Does the signature cryptographically verify under a key in the local trust bundle? |
| `signer_matches_policy` | Is the key that verified the one the *policy* names? (A valid signature from the wrong signer fails here.) |
| `payload_digest_matches` | Does the signed payload name *this* image's digest? (Catches signatures transplanted from another image.) |
| `payload_reference_matches` | Does the signed payload name this repository? |
| `provenance_present` / `provenance_valid` / `provenance_predicate_matches` | If the policy requires provenance: does a DSSE attestation exist, verify under a policy signer, name this digest, and carry an allowed predicate type (e.g. SLSA provenance)? If the policy doesn't require it, these report `NA`. |

## How verification works

- **Registry access is read-only** (`registry.py`, stdlib urllib): manifest resolution by tag or digest (one level of manifest-list/index selection), blob fetches with digest self-check, and the anonymous bearer-token flow Docker Hub / GHCR use. The client has no write path. HTTPS everywhere except loopback (so local dev registries and tests work).
- **Signature layout** follows cosign: the signature object at tag `sha256-<digest>.sig` carries the base64 signature in the `dev.cosignproject.cosign/signature` annotation and the signed simple-signing payload as a layer; attestations live at `sha256-<digest>.att` as a DSSE envelope layer. The OCI Referrers API is tried as a fallback. *[Verify per registry: GHCR supports referrers; Docker Hub coverage has historically been partial — the tag layout is tried first for that reason. Signature-annotation placement also varies slightly across cosign versions; both manifest-level and layer-level annotations are read.]*
- **Cryptography is pure Python stdlib** (`sigverify.py`): ECDSA over NIST P-256, Ed25519, and RSA PKCS#1 v1.5, plus SubjectPublicKeyInfo parsing and DSSE pre-auth-encoding. No `cryptography` package, no cosign binary, no dependencies.
- **Out of scope in v0.1:** keyless/Fulcio signatures. A signature object that carries only a certificate chain fails `signer_matches_policy` with that reason stated — key-based trust bundles are the K0 trust model, matching the spec's owner-custodied signing-key decision (§8.2).

## Tools (3)

| Tool | What it does |
|---|---|
| `verify_image` | Run the gate on an image reference (`registry/repo:tag` or `@digest`) under a named policy or an inline policy object. Returns the full verdict + receipt reference. |
| `policy_show` | The loaded policies, the trust bundle's public keys (fingerprints only), and config paths — the written scope the gate enforces. |
| `receipt_list` | The append-only, hash-chained receipt ledger of past verifications, with chain validation. |

## Run it

```bash
python3 server.py            # MCP over stdio, stdlib only, no dependencies
```

CLI mirror:

```bash
python3 server.py verify ghcr.io/your-org/your-image:v1 --policy default
python3 server.py policies
python3 server.py receipts --limit 20
```

(`verify` exits 0 on PASS, 1 on FAIL.)

### Configure

| Env var | Default | Purpose |
|---|---|---|
| `ECLIPSE_CLUSTER_POLICIES` | `./policies/` | Directory of policy JSON files (see `policies/default.json`, `policies/signature-only.json`). |
| `ECLIPSE_CLUSTER_TRUST` | `./trust-bundle.json` | Trust bundle: the public keys the gate trusts at all. Start from `trust-bundle.example.json` — its example key is a throwaway whose private half was discarded. |
| `ECLIPSE_CLUSTER_RECEIPTS` | `./receipts.jsonl` | Append-only receipt ledger (hash-chained). |

A **policy** names: `policy_id`, `allowed_registries`, `signers` (by trust-bundle `key_id`), and `required_provenance` (`required` + allowed `predicate_types`). A signature can verify cryptographically yet still fail the gate if its signer isn't named by the policy — that separation is the point.

## Tests

```bash
python3 -m unittest discover -s tests -v   # 12 offline tests, local stub registry
python3 smoke_test.py                      # MCP-over-stdio end-to-end, offline
```

The suite builds cosign-layout fixture images signed with the system `openssl` binary (an external signer, as in production) and serves them from a local stub registry implementing token auth, manifests, and blobs. Covered: signed+attested PASS (ECDSA), Ed25519 PASS, wrong signer FAIL, in-bundle-but-not-in-policy signer FAIL, payload-for-a-different-digest FAIL, unsigned FAIL, missing-provenance FAIL, non-allowlisted registry FAIL (with proof the gate made **no** registry contact), unreachable registry FAIL, receipt-chain integrity, unknown-policy FAIL. One opt-in live test (`ECLIPSE_CLUSTER_LIVE=1`) checks a real public image fails the gate *with reasons* rather than erroring.

## Status

v0.1.0 reference implementation — **K0 gate only; orchestration is later phases.** Local tests pass (see above); **Test Bench run pending** — no certification is claimed. Per spec §7, Cluster does not list as a runtime product until something real runs under it; this gate is the first real thing.

## License / attribution

MIT (see LICENSE). A Cyan Eclipse Technologies product. The "Powered by Cyan Eclipse Technologies" attribution travels with it.
