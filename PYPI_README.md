# cyan-eclipse-cluster

mcp-name: io.github.CYAN-ECLIPSE-TECHNOLOGIES-LLC/cluster

**What this is:** the MCP server for **Eclipse Cluster MCP** - The container substrate of the Constellation family. v0.1 ships phase K0 only: a signed-image verification gate an agent (or a pipeline, or the Test Bench) calls before an image is allowed anywhere near a runtime. It resolves the image digest from its registry (read-only), verifies the cosign-style signature and DSSE/in-toto provenance against a written policy and a local trust bundle, and returns a per-check PASS/FAIL verdict — registry allowlisted, signature valid, signer named by policy, payload bound to this digest, provenance present and of the required type. Fail-closed on every error, and every verdict lands in a hash-chained receipt ledger. Pure Python stdlib cryptography (ECDSA P-256, Ed25519, RSA); no container runtime required.

## Run it

```console
$ pip install cyan-eclipse-cluster
$ eclipse-cluster           # MCP over stdio, Python stdlib only
```

MCP client config:

```json
{ "mcpServers": { "cyan-eclipse-cluster": { "command": "uvx", "args": ["--from", "cyan-eclipse-cluster", "eclipse-cluster"] } } }
```

## Tools (3)

`verify_image` - `policy_show` - `receipt_list`

## Honest scope

- In development — v0.1.0 K0 verification gate only (local reference implementation; 12 offline tests + stdio smoke pass; CERTIFIED(simulator) — Eclipse Bazaar Test Bench 2026-10-25; orchestration K1-K3 not built)
- State and runtime data files ship in the wheel beside `server.py`,
  at the same relative paths the server reads them from.

Powered by Cyan Eclipse Technologies LLC (cetech.ai) - a Veteran-Owned
Small Business. MIT licensed.
