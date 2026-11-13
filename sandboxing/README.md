# Optional SRT integration

The workspace setting is `sandbox.enabled` in `guardrails/config.yml`. Missing
settings mean off, including in legacy policy files. The maintained profile
revision participates in the compiled policy fingerprint, so profile changes
invalidate approvals and require gateways to reconnect. Increase
`PROFILE_REVISION` when changing maintained permissions or worker code.

The shared runner owns each invocation's private configuration, scratch space,
credential copy and subprocess tree. The local MCP transport uses it for
discovery, testing and execution; the PDF worker uses the same runner. Original
command review happens before managed Brave/Analytics entrypoint substitution.
Other Python handlers and native API requests are outside this boundary.

## Installation and policy

Only the explicit setup job installs packages. It uses the exact npm manifest
and lock in `resources/`, plus the hash-locked Analytics requirements. Package
scripts are disabled. Environments are built in new installation directories,
published atomically under an exclusive activity lease and retained only after
real local probes pass. Failed replacement restores the prior receipt. Node and
npm are supplied by the exact `nodejs-wheel` dependency in the app's uv lock.
Setup resolves the native executable and npm JS entrypoint inside that wheel,
independently of system PATH or nvm. Normal `uv run` launches also expose the
environment's private node/npm/npx commands to local tools. No global Node,
shell startup files or nvm defaults are changed.

The current complete wheel release is 24.19.0; the newer 24.22.1 CLI wheel lacks
its required binary distribution and cannot resolve. Review and test complete
releases when updating the pin. Bump `PROFILE_REVISION` for a Node runtime
upgrade so existing sandbox receipts must be checked again. Distributions are
third-party Node builds: https://pypi.org/project/nodejs-wheel/.

`current.json` identifies the private installation and records successful checks
on this host platform. Execution requires a valid checked receipt. **Check
again** invalidates that receipt before probing and leaves execution blocked
when verification fails. Each launch uses an explicit settings file; ambient SRT
configuration is not merged. Runtime changes and profile edits are blocked while
chat, a connection test, a worker or another setup job is active.

Custom profiles bind to the entire saved connection hash. They contain only
literal extra read/write paths and exact public host/port destinations. Review
cannot grant private state or a containing directory; write grants cannot cover
the application or runtime. Environment mappings cannot override loaders,
runtime settings, proxy configuration or the private working directory.

Workers receive a minimal environment. Brave gets its assigned key; Analytics
gets only its request-owned credential copy and routes Google transports through
the proxy. PDF gets no service credentials or network destinations. SRT's proxy
checks exact destinations and rejects resolved private, loopback, link-local
and metadata addresses. Readiness alone uses an internal loopback fixture grant
that public profile validation cannot create.

Windows uses a private pinned helper with a deterministic Kindred account and
WFP configuration, without force replacement, unrestricted loopback or the full
user-profile read grant. Sessions serialize across Kindred processes. A dirty
marker blocks new workers until temporary and retained grants are revoked and
checked. Failed cleanup keeps recovery records rather than reporting success.
The Windows argv adapter avoids passing user arguments through `cmd.exe`.
Upstream Windows isolation remains experimental and has residual limitations.

## Dashboard API

All routes inherit dashboard pairing, origin and CSRF protection. Mutations
require the current workspace `revision`.

| Route | Purpose |
| --- | --- |
| `GET /api/sandbox` | Saved choice, state, checks, profiles, busy status and recent jobs |
| `PUT /api/sandbox` | Save `{revision, enabled}`; installation is independent |
| `PUT /api/sandbox/connections/{name}` | Save `{revision, profile}` with `configuration_hash`, `read_paths`, `write_paths`, `destinations` |
| `POST /api/sandbox/setup` | Start explicit asynchronous provisioning; Windows also requires `confirm_windows: true` |
| `POST /api/sandbox/check` | Start bounded local verification without provider calls |
| `GET /api/sandbox/jobs/{id}` | Poll a job's safe progress and outcome |

Jobs are owned by the dashboard process and are cancelled on shutdown. Worker
leases and recovery records include PID creation times to avoid acting on a
reused PID. Audit events contain connection, mode, profile/policy revision and
sanitised outcome; they exclude profiles, credentials and raw worker output.

## Verification

The normal suite requires no SRT and never downloads runtime packages:

```sh
LITELLM_LOCAL_MODEL_COST_MAP=True uv run pytest tests/test_sandbox.py
```

For actual integration, explicitly prepare a **test** installation from the
committed npm locks in a temporary directory. Prepare its `analytics` venv from
`resources/analytics.lock` with `uv pip sync --require-hashes` as well. Supply
absolute paths to that directory and a supported Node executable:

```sh
KINDRED_TEST_SRT_PACKAGES=/absolute/test-install \
KINDRED_TEST_SRT_NODE=/absolute/supported-node \
LITELLM_LOCAL_MODEL_COST_MAP=True \
uv run pytest tests/test_sandbox.py
```

These tests use local fixture servers, fake OAuth data and MCP discovery. They
exercise actual denied file reads/writes, denied direct sockets, permitted and
forbidden proxy requests, literal arguments, PDF extraction, maintained Node
and Python MCP servers, concurrent ownership, cancellation and emergency stop.
They need native OS sandbox access and permission to bind local fixture sockets.
No paid inference or live account access is used. Missing opt-in environment
variables produce explicit skips, not a platform verification result.

Windows additionally requires `KINDRED_TEST_SRT_RECEIPT` pointing to an explicitly
provisioned disposable test account's receipt. Never use a production receipt
or another app's account for these checks. On PowerShell set the environment
variables with `$env:NAME = 'value'` before running pytest.

Run real integration on **each native macOS, Linux and Windows target** before
declaring that platform validated. macOS ARM64 was exercised during development;
Linux and Windows have not yet been exercised on native hosts. On Windows,
additionally verify UAC cancellation, conflicting installations, denied
Schannel-dependent workloads, stale ACL recovery and serialization. Browser
coverage in `tests/test_browser.py` verifies switch/setup errors and chat draft
preservation. The full regression suite covers gateway policy synchronization,
external gateway mismatches and existing authentication lifecycles.
