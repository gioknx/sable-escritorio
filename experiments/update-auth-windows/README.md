# Windows gate 0: authenticated update persistence

This is an isolated, manually triggered experiment, not an enabled updater. Its first
Windows result is a measurement or a reproducible block. It does not build or run
NSIS, install an application, demonstrate autonomous updating/reopening, or change
the production update policy. No real profile, account, installer or key is used.

## Immutable inputs

`update-auth.cjs` and `test.cjs` are byte-for-byte copies of the reviewed UNIT
prototype. SHA256:

- `update-auth.cjs`: `1da99c9b45624455071219caf07c42013cf5373cfb2a177ab35aa304f4f4fe9b`
- `test.cjs`: `cac6b2cf851dd9831a6d2660e82c22e12ef3e1a8e7d1fbc01d2bfd032830a148`
- Official `electron-updater` 6.8.11 npm tar:
  `f1344e79b420da2c390761ffedee2668ca9baf1792786df966ffefce6845e1b2`

The original lock's dependency versions and integrity values are retained. Only
its root package name and updater source change: the same updater bytes now come
from the official npm registry instead of a local tar. `semver` remains 7.7.3.
Licenses are in `THIRD-PARTY-NOTICES.txt` and the installed npm distributions.
No vendored tree, tarball, node_modules, logs or private keys are committed.

## Local checks

Use Node, npm and an installed OpenSSL executable. The workflow pins Node 24.22.0;
local Linux checks can run on another Node 24 patch, but that is not Windows proof.
From this directory:

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm run check
npm test
node probe-policy.cjs
```

`npm test` requires all 14 immutable UNIT groups to pass, with no skips. The last
command deliberately returns **78 / BLOQUEADO_NAO_WINDOWS** on Linux; this is not
a passing native gate. It does not pretend Linux is NTFS or mock filesystem calls.
`UPDATE_AUTH_OPENSSL` may select an installed OpenSSL executable by absolute path.
There is no package lifecycle-script dependency or shell invocation by the Node
runners. No Actions dependency cache or TLS validation bypass is configured.

## Manual Windows run

The workflow `.github/workflows/update-auth-windows.yml` has only
`workflow_dispatch`, uses the standard `windows-latest` runner in the public repo,
and grants only `contents: read`. It never publishes, deploys, signs, creates a
release, handles secrets or touches Ronald. Dispatch/publication is a separate
operator action; creation of these files does not dispatch anything.

Before the first dispatch, register the workflow on the default branch through a
reviewed pull request. GitHub requires the manual workflow file to exist there.
The separate `update-auth-check.yml` runs Linux source checks for pull requests:
immutable hashes, syntax, all 14 UNIT groups and the expected non-Windows block.
A green Linux check permits registering the experiment, not claiming Windows proof.
Only after that merge, dispatch the Windows measurement explicitly:

```sh
gh workflow run update-auth-windows.yml --repo gioknx/sable-escritorio --ref main
```

It verifies the exact Node patch, win32/x64, both source hashes and the official
npm tar's SHA256. Checkout disables CRLF conversion for the immutable copies.
Actions are public official repositories, pinned to full commits resolved through
`https://api.github.com/repos/actions/{checkout,setup-node,upload-artifact}/commits/{v6,v6,v4}`:

- checkout: `d23441a48e516b6c34aea4fa41551a30e30af803`
- setup-node: `249970729cb0ef3589644e2896645e5dc5ba9c38`
- upload-artifact: `ea165f8d65b6e75b540449e92b4886f43607fa02`

After `npm ci --ignore-scripts`, syntax, UNIT and native Policy are separate steps.
UNIT and Policy are **both attempted even after an earlier failure**. Any failed,
blocked, skipped or missing gate fails the workflow; upload runs on failure too.
Unavailability of the pinned runtime/OpenSSL is a failure, not permission to use
an unpinned substitute or disable TLS validation.

For a direct run on an already prepared Windows runner, in PowerShell:

```powershell
# RUNNER_TEMP must already identify the disposable runner's temporary directory.
$env:UPDATE_AUTH_EVIDENCE_DIR = Join-Path $env:RUNNER_TEMP ('update-auth-evidence-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $env:UPDATE_AUTH_EVIDENCE_DIR | Out-Null
node run-unit.cjs
$unitExit = $LASTEXITCODE
node probe-policy.cjs
$probeExit = $LASTEXITCODE
if ($unitExit -ne 0 -or $probeExit -ne 0) { throw 'Gate failed or blocked; inspect JSON' }
```

## What the probe actually measures

Before touching Policy state it requires win32/x64, an absolute `RUNNER_TEMP`, a
new exclusive directory, and a local fixed **NTFS** volume proved by
`Get-Item` / `Get-Volume` in a read-only PowerShell subprocess. Evidence includes
volume, OS/architecture/runtime, errors and signed public state snapshots.

An ephemeral Ed25519 key signs real metadata served by an HTTPS loopback server.
The probe uses the unchanged `AuthenticatedNsisUpdater` constructor,
`checkForUpdates()` and `close()` APIs, with the same app-adapter approach as UNIT.
It does not export or rewrite Policy and never calls download/install/quit.
Metadata binds the same MINDTECH/stable/win32/x64 identity and inert artifact hash.
The inert artifact is neither downloaded nor executed.

The first child attempts seq=2/version=2.2.3 and holds the lock. A second process
must fail with EEXIST while it is held. The first child then closes normally. A new
process resumes the exact persisted envelope; another must reject the signed
seq=1 rollback. Snapshots before/open/accepted/before-close/after-close record the
state, `.lock` and `.new`, including signed envelope/hash/size when present.
PIDs distinguish normal-close/restart processes. No filesystem mocks are used.

If directory `openSync` or `fsync` fails, the result is **BLOQUEADO / exit 1**, with
errno, stack and the actual intermediate state preserved in JSON. Normal `close()`
still runs. A new process is attempted against the same state even after the first
failure; success of that restart never cancels the original failure. No `.new`,
`.lock` or state repair, ignored fsync, fallback or recovery redesign is allowed.
Public-only state stays in the exclusive runner directory until runner disposal.
This does **not** measure abrupt death, power-loss durability or crash recovery.

## Private material and evidence

`run-unit.cjs` ports the original OpenSSL launcher. It creates an ephemeral
self-signed CA/server certificate and key in an exclusive temporary directory.
`NODE_EXTRA_CA_CERTS` and `UNIT_TLS_KEY` are set only in child environments, never
in the parent or global trust store. The probe reuses that launcher; signing keys
remain in parent memory and only the public key reaches workers. TLS files are
removed in `finally`, including failure. No ACL, Defender or UAC changes occur.

When `UPDATE_AUTH_EVIDENCE_DIR` names an existing directory, each runner writes
`unit.json` or `probe.json`; otherwise it prints the same JSON to stdout. UNIT
includes TAP output and errors, not key contents. Probe includes only known public
state files, not a directory dump. The workflow adds environment, preflight and
verdict JSON, then uploads **only that evidence directory's `*.json`**. It never
uploads temporary TLS directories, npm trees, arbitrary logs or private PEM files.
An interrupted runner/upload-service failure cannot guarantee delivery of an
artifact; no workflow can turn such interruption into a passing gate.

The unresolved native compatibility is intentionally left to the first Windows
measurement. A PASS covers only these UNIT/persistence operations, not Electron,
NSIS, Authenticode/SmartScreen, bootstrap trust, power failure, existing production
transport redirects, profile continuity or autonomous updating.
