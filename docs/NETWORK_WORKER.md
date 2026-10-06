# Private Network Worker — Operational Contract

This document is the **operational contract** for the Windows network Worker.
It describes what the RH-B implementation actually does. Where a behaviour is a
security gate, the document states the gate and the operator response; it never
offers a bypass.

Related documents:

- [Release Process](RELEASE_PROCESS.md) — how artifacts are built and verified.
- [Windows worker hardening](windows-worker-hardening.md)
- [Partial install recovery](windows-partial-install-recovery.md)

---

## 0. Concepts and boundaries

Three trust domains are kept strictly separate. Conflating them is a defect.

| Domain | Owns | Never contains |
|---|---|---|
| **Immutable release** | `manifest.json`, installer scripts, worker code, V2 aggregate | `worker_id`, `api_base_url`, fixture path, tokens, `worker.dpapi` |
| **Target config** | `service.json` on the target | tokens, DPAPI bytes, payload hashes, builder paths |
| **Secret state** | `credentials\worker.dpapi` on the target | anything that appears in a release artifact |

The **immutable release artifact is secret-free**. It carries declarative
`policy_requirements` only — never concrete target values.

### Install layout on the target

| Path | Contents |
|---|---|
| `%ProgramFiles%\DevAIWorker\` | immutable code (`control\`, `host-runtime\`, `sandbox-runtime\`) + `install-worker.ps1` / `install-support.ps1` |
| `%ProgramData%\DevAIWorker\service.json` | validated target configuration |
| `%ProgramData%\DevAIWorker\credentials\worker.dpapi` | DPAPI-protected worker token (secret) |
| `%ProgramData%\DevAIWorker\volumes\`, `workspace-volume\` | private workspace volume + mount |
| `%ProgramData%\DevAIWorker\logs\`, `journal\`, `reports\` | runtime output |
| `%USERPROFILE%\DevAIWorkerAccessProbe\service-access-denial.fixture` | personal-denial witness (§9) |

---

## 1. Initial Provisioning

### 1.1 Exact sequence

```
trusted artifact + expected hashes available
  ↓
verify outer release artifact            (tools\verify-release.py)
  ↓
verify manifest.json + install-worker.ps1 anchors
  ↓
install immutable release               (install-worker.ps1)
  ↓
supply WorkerId                         ← non-secret, target config
  ↓
supply ApiBaseUrl                       ← non-secret, target config
  ↓
create + validate personal denial fixture
  ↓
generate service.json
  ↓
provision token through stdin           ← the ONLY secret step
  ↓
create worker.dpapi
  ↓
validate ACL / state
  ↓
register service
  ↓
start service
  ↓
runtime acceptance gates
```

**No target mutation occurs before immutable verification succeeds.** The
installer computes every immutable digest first and fails closed before it
creates a single directory, file, service or ACL.

### 1.2 What is secret and what is not

**Non-secret** (safe to pass on a command line, record in a ticket, or store in
configuration):

- `WorkerId` (a UUID)
- `ApiBaseUrl` (an endpoint URL)
- filesystem paths, hashes, expected release digests

**Secret** — the worker token. It is supplied **only** through one of two
supported channels, both converging into `Read-WorkerTokenSecureString`:
the interactive `Read-Host -AsSecureString` prompt (default), or exactly one
token line on redirected stdin with `-WorkerTokenFromStdin` (automation).
Either way the SecureString is converted narrowly to feed the provision
child's **redirected stdin**, and released in a `finally` block that frees
the BSTR. There is deliberately no plaintext token parameter.

Never place the token:

- on a command line or in process arguments / process metadata
- in an environment variable
- in `service.json`, `manifest.json`, or any release artifact
- in a script, ticket, chat message, log, or `reports/install.json`

### 1.3 Procedure

Run from the **repository root** (see [Release Process §3](RELEASE_PROCESS.md)):

```powershell
# 1. Obtain the artifact and its trusted expected digest from the release record.
#    Do NOT accept a digest from an untrusted channel; see Release Process §8.

# 2. Verify the outer artifact (Layer A) before touching the machine.
python tools\verify-release.py `
    devai-<commit>-windows-x64.tar `
    --sha256-file devai-<commit>-windows-x64.tar.sha256 `
    --repo .

# 3. Install. Identity and endpoint are supplied HERE, as target config.
.\devai-<commit>-windows-x64\launch-worker-install.ps1 `
    -PackageRoot .\devai-<commit>-windows-x64 `
    -ExpectedManifestSHA256 <manifest.json sha256> `
    -ExpectedInstallerSHA256 <install-worker.ps1 sha256> `
    -ResultPath .\install-result.json `
    -WorkerId <uuid> `
    -ApiBaseUrl <url>
```

The prompt for the token appears during target provisioning. An ordinary
reinstall that finds a valid `worker.dpapi` does **not** prompt and does **not**
overwrite it.

`-DiagnoseOnly` performs read-only validation and writes a proof document. It
mutates nothing.

### 1.4 Runtime acceptance gates

After `Start-Service`, the service itself enforces runtime gates, including
`service_personal_profile_denied` (§9). These are **runtime** properties and are
distinct from installer policy.

---

## 2. Credential Rotation

### 2.1 What does NOT rotate the token

| Operation | Rotates token? |
|---|---|
| Normal reinstall (same release) | **No** |
| Upgrade to a new release | **No** |
| Rollback to a previous release | **No** |
| `-ResumeServiceCreation` | **No** |
| **Explicit rotation** | **Yes** |

The installer preserves an existing credential by default. It never silently
replaces a valid credential.

### 2.2 Rotation is explicit

Rotation is a deliberate operator action. Rotate when the control plane issues a
new token or the old token is suspected compromised.

1. Stop the worker service.
2. Provision the new token through the approved stdin path only.
3. Verify the credential state (§2.4).
4. Start the worker service.

Rotation is **not** driven by a release upgrade and **not** driven by rollback.

### 2.3 Failed rotation preserves the last valid credential

If provisioning fails, the installer throws `CREDENTIAL_PROVISIONING_FAILED`
and the service is **not** started. The service must never be left in a
false-success state: there is no code path that reports success while the
credential is absent.

Re-provisioning over an existing file requires an explicit operator decision; the
provisioner writes the DPAPI store itself and reports a non-zero exit on failure.

### 2.4 Stated validation limitation — read this

Credential validity is checked with the strongest checks available **without
adding new decryption logic**:

1. **presence** of `credentials\worker.dpapi`
2. **path** correctness (the exact expected location under the state root)
3. **ACL** conformance (owner and allowed-principal model)

The installer does **not** decrypt, unwrap, or semantically validate the token.
A stale-but-present credential with a correct ACL cannot be distinguished from a
fresh one by these checks. Do not read §2 as "the installer proves the token is
valid". It proves the credential **state** is well-formed.

DPAPI binds the blob to the machine and user account that created it. It is
**not portable** between machines or accounts.

---

## 3. Worker Replacement

Replacement is a **different lifecycle event** from a code reinstall. The
installer does not implement replacement automation, and it must not be
inferred to.

### 3.1 Code reinstall (same identity)

- Same `worker_id`.
- Same `ApiBaseUrl` unless explicitly changed.
- Credential preserved.
- `service.json` regenerated with the same values.
- `-ResumeServiceCreation` is the supported path for resuming an interrupted
  install.

### 3.2 Worker replacement (new identity)

Replacement is a control-plane decision:

1. The control plane issues a **new** `worker_id` (and, if required, a new
   token).
2. The old identity is retired/revoked according to control-plane procedure.
3. The new identity is provisioned explicitly.

**The installer never generates a new `WorkerId` automatically.** A fresh install
*requires* `-WorkerId`; omitting it fails closed with `WORKER_ID_REQUIRED`.
There is no auto-generated or random identity path.

Supplying a new `WorkerId` together with an `-ExistingConfig` that holds a
different one is a conflict, not an upgrade: it fails closed with
`WORKER_ID_CONFLICT`. To replace a worker you must perform the change through
the documented replacement procedure, not by silently overriding existing state.

---

## 4. Worker Identity Lifecycle

### 4.1 `worker_id` semantics

- **Generated or assigned outside the immutable package.** It is target
  configuration, never release content.
- **Supplied as target configuration** via `-WorkerId` or `-ExistingConfig`.
- **Stable** across normal reinstall, upgrade and rollback.
- **CLI/config disagreement fails closed.** If both `-WorkerId` and
  `-ExistingConfig` supply a value they must agree, otherwise
  `WORKER_ID_CONFLICT`. There is deliberately **no precedence rule**.
- **The package does not own identity.** The manifest declares
  `requires_worker_identity` — a requirement, not a value.
- **Changing identity is a deliberate lifecycle action** (§3.2), never a side
  effect of installing code.

Format: a non-empty RFC-4122 UUID. Invalid values fail with `INVALID_WORKER_ID`;
the empty GUID is rejected.

### 4.2 `api_base_url` ownership and policy

`api_base_url` is owned by the control plane and supplied as target
configuration. It is stable across reinstall/upgrade/rollback, and a conflict
with `-ExistingConfig` fails closed with `API_BASE_URL_CONFLICT`.

**The accepted policy is exactly the tested contract. It is NOT "HTTPS only".**
`Test-TargetApiBaseUrl` in `deploy\windows\install-support.ps1` is the
authoritative implementation. It accepts a value only when **all** of the
following hold:

1. the URL parses as an absolute URI;
2. the scheme is `http` **or** `https` — both are accepted;
3. there is no userinfo component;
4. the path is exactly `/` (no path, query or fragment);
5. the host is a **literal IP address** (no hostnames, no DNS names);
6. that address is either **loopback** or inside **100.64.0.0/10** (CGNAT).

Everything else is rejected, including RFC1918 ranges (`10/8`, `172.16/12`,
`192.168/16`), any public address, any hostname, any non-`http(s)` scheme, and
any URL carrying a path, query or fragment. IPv6 loopback (`[::1]`) is accepted.

If this policy is ever changed, the change must be made in the installer
validation **and** re-derived from the executable tests, not from prose.

---

## 5. Token / Credential Lifecycle

### 5.1 Plaintext token lifetime

The plaintext token exists only:

- transiently in the operator's interactive entry,
- in the narrow converted buffer used to write the child's stdin,
- inside the provisioning process until it exits.

It is never written to disk by the installer, never passed in argv or the
environment, and never logged. The provisioning primitive is the existing,
byte-identical `worker_agent.provision`, which rejects an interactive TTY and
does not echo the token.

Managed-memory copies are **not** claimed to be cryptographically erasable. The
guarantee is narrower and is the one that matters operationally: **no durable,
loggable or process-metadata exposure.**

### 5.2 DPAPI storage

- The token is protected with Windows DPAPI for the creating user/machine.
- Location: `%ProgramData%\DevAIWorker\credentials\worker.dpapi`.
- **Target-local only.** It is not part of any release artifact.
- **Not portable.** DPAPI ciphertext cannot be moved to another machine or
  account and still decrypt. Copying `worker.dpapi` between hosts is not a
  supported credential-transfer mechanism.

### 5.3 Filesystem ACL boundary

`worker.dpapi` is protected by the managed install ACL model: trusted owner, and
an explicit rights set for the worker service SID. It is not readable by
unrelated principals. The installer re-validates this ACL before treating the
credential as usable.

### 5.4 What is never stored with a token

- No token in the immutable release artifact.
- No token in the rollback artifact.
- No token in `service.json`.
- No `worker.dpapi` in any release archive.
- No plaintext token in release material, retention storage, or tickets.

Target state stays on the target. Release material stays secret-free.

---

## 6. Failure and Recovery

**Governing rule: every one of these conditions fails closed. Do not bypass a
security check to make an install complete.** There is no supported "disable
validation" switch, and none may be added.

| Condition | Control code | Operator response |
|---|---|---|
| Outer artifact digest mismatch | `ARTIFACT_SHA256_MISMATCH` | Discard the artifact. Re-fetch and re-verify. **Never** edit `release.json` to match a hash. |
| Trusted anchors disagree | `TRUSTED_ANCHOR_DISAGREEMENT` | Resolve which digest is authoritative out of band. The verifier will not choose. |
| Manifest absent / malformed / BOM | `MANIFEST_MISSING`, `MANIFEST_NOT_VALID_JSON`, `MANIFEST_HAS_BOM` | Re-fetch the artifact. Do not hand-edit the manifest. |
| Unsupported manifest format/schema | `UNSUPPORTED_MANIFEST_FORMAT`, `UNSUPPORTED_MANIFEST_SCHEMA_VERSION` | Artifact/builder version mismatch. Use the matching installer for that artifact. |
| Payload hash or size mismatch | `MANIFEST_HASH_MISMATCH`, `MANIFEST_SIZE_MISMATCH` | Artifact corrupted or tampered. Re-fetch. |
| Unmanifested payload member | `UNMANIFESTED_PACKAGE_FILE` | Remove nothing manually — re-fetch a clean artifact. |
| V2 aggregate mismatch | `MANIFEST_IDENTITY_AGGREGATE_MISMATCH` | Artifact is not self-consistent. Re-fetch. |
| Legacy `package.json`-only artifact | `UNSUPPORTED_LEGACY_PACKAGE_FORMAT` | Expected. Use the historical installer that shipped with that release. See [Release Process §12](RELEASE_PROCESS.md). |
| Installer script hash mismatch | `PACKAGE_INSTALLER_CHANGED` | Artifact tampered. Re-fetch. The installer is authenticated **separately** from the manifest. |
| Manifest anchor mismatch (launcher) | `PACKAGE_MANIFEST_CHANGED` | Artifact tampered. Re-fetch. |
| Runtime artifact digest mismatch | `RUNTIME_SHA256_MISMATCH` | Wrong or corrupted runtime. Re-download the pinned embeddable and re-verify. |
| Dependency lock mismatch | `DEPENDENCY_LOCK_MISMATCH`, `*_LOCK_IDENTITY_MISMATCH` | Wrong lock for this release. Use the release's own lock. |
| Invalid `WorkerId` | `INVALID_WORKER_ID` | Supply a valid UUID. |
| `WorkerId` / `ApiBaseUrl` conflict with existing config | `WORKER_ID_CONFLICT`, `API_BASE_URL_CONFLICT` | Decide deliberately (§3.2) or omit the CLI value and reuse the existing config. |
| Missing identity on fresh install | `WORKER_ID_REQUIRED`, `API_BASE_URL_REQUIRED` | Supply both, or pass a valid `-ExistingConfig`. |
| Rejected `ApiBaseUrl` | `INVALID_API_BASE_URL` | See the exact policy in §4.2. |
| Personal fixture ACL failure | `PERSONAL_FIXTURE_ACL_*` | Do not weaken the ACL. Restore the three-ACE model or re-provision the fixture. |
| Reparse point / junction detected | `MANIFEST_REPARSE_MEMBER`, `PACKAGE_ANCESTOR_REPARSE_POINT`, `INVALID_PERSONAL_FIXTURE_PATH` | Remove the junction/symlink from the path and retry. Do not disable reparse checks. |
| Credential provisioning failure | `CREDENTIAL_PROVISIONING_FAILED` | The service is **not** started. Re-provision through the stdin path. The previous credential, if any, is preserved. |
| Missing `worker.dpapi` | `CREDENTIAL_PROVISIONING_FAILED` | Provision explicitly (§2.2). |
| Service registration failure | `WORKER_SERVICE_CREATION_FAILED_*`, `SERVICE_SID_UNAVAILABLE` | Resolve the SCM/ACL condition; do not force-create the service. |
| Service start failure | service start is blocked if any prior gate failed | Inspect `%ProgramData%\DevAIWorker\reports\install.json` and the event log. |
| Runtime personal-profile denial gate | `service_personal_profile_denied` | See §9. This is a **runtime** property, proven only by the native elevated gate. |
| Interrupted install | `RESUME_*` | Re-run with `-ResumeServiceCreation`. Resume never reformats the workspace volume. |
| Existing install in the way | `EXISTING_INSTALLATION_PATH_REQUIRES_REVIEW` | Reviewed upgrade path only. |

---

## 7. Personal denial fixture — operational contract

The fixture at
`%USERPROFILE%\DevAIWorkerAccessProbe\service-access-denial.fixture` is **not**
scratch data. It is the **runtime witness** for the `service_personal_profile_denied`
gate: a file that the worker service identity must be *unable* to read. If the
service could read it, the negative-privilege boundary the worker depends on
would not exist.

**Installer policy establishes the ACL** (verified structurally on real NTFS):

- DACL is **protected** (non-inherited).
- Exactly **three** allow ACEs, all Full Control:
  `SYSTEM` (`S-1-5-18`), `Builtin\Administrators` (`S-1-5-32-544`), and the
  installing owner.
- **No** service-SID ACE, and **no** broad principal (`Everyone`,
  `BUILTIN\Users`, `Authenticated Users`, `Guests`).

The fixture is created by the installer on the target. It never appears in the
immutable release artifact.

**Two distinct gates — keep them distinct:**

| Gate | Status | What it proves |
|---|---|---|
| `INSTALLER_ACL_POLICY_GATE` | PASS (automated, real NTFS) | the ACL the installer writes has exactly the intended shape |
| `RUNTIME_SERVICE_PERSONAL_PROFILE_DENIAL_GATE` | `BLOCKED_PENDING_ELEVATED_EXECUTION` | the worker service identity actually gets `PermissionError` and the service refuses |

The second is proven at runtime, and ultimately by the native elevated Windows
gate. It must not be simulated with mocks and reported as equivalent.

The fixture is validated for: absolute path, non-reparse fixture **and**
non-reparse parents, and rejection of forbidden/shared locations
(`ProgramData`, `ProgramFiles`, temp).

---

## 8. Quick reference — the two trust anchors

`launch-worker-install.ps1` takes **two independent, externally supplied**
digests:

- `-ExpectedManifestSHA256` authenticates `manifest.json`.
- `-ExpectedInstallerSHA256` authenticates the `install-worker.ps1` **bytes that
  are about to be executed**.

They are deliberately separate. A valid payload manifest must never be able to
authorise a substituted installer script. The manifest's own internal V2
aggregate proves **internal consistency only** — it is not proof of trusted
origin. See [Release Process §8](RELEASE_PROCESS.md) for the full trust model.