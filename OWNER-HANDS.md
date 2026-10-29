# OWNER-HANDS - cyan-eclipse-cluster PyPI launch (renamed from eclipse-cluster, 2026-10-28)

Everything in this file is done **by the owner, in the owner's
browser**. The package is built and locally proven (wheel + sdist,
clean-venv install, MCP handshake against the installed entry point);
it is **not yet published** - no Trusted Publisher exists for this
project yet.

> **Stop rule:** no step below creates or hands over an API token.
> Publishing runs on Trusted Publishing (OIDC) only.

## Trusted Publisher for `cyan-eclipse-cluster` (pending publisher)

On <https://pypi.org/manage/account/publishing/> - "Add a new pending
publisher" - **GitHub** tab. Enter these strings **exactly**:

| Field | Value |
|---|---|
| PyPI Project Name | `cyan-eclipse-cluster` |
| GitHub Repository Owner | `CYAN-ECLIPSE-TECHNOLOGIES-LLC` |
| GitHub Repository Name | `eclipse-cluster-mcp` |
| GitHub Workflow Name | `publish-pypi.yml` |
| Environment Name | `pypi` |

## Ship day (after the publisher above exists)

1. Agent verifies `VERSION` + `server.json` agree at the release
   version and the full test suite is green.
2. Owner reviews; agent tags `v<version>` and pushes the tag.
   **Do not tag before the Trusted Publisher exists** - the
   `publish-pypi.yml` workflow fires on `v*` tags and will fail.
3. GitHub Actions then builds, runs `twine check`, and publishes to
   PyPI via Trusted Publishing with PEP 740 attestations.
