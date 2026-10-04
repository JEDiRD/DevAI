# DEVAI Release Process (RH-B)

Operational procedure to build and verify a DEVAI release artifact. This
document is written so that an independent release engineer can perform a
release **without tribal knowledge**.

Related: [Private Network Worker — Operational Contract](NETWORK_WORKER.md)

---

## 1. Release prerequisites

| Requirement | Value |
|---|---|
| OS for a Windows release | native Windows **x64** |
| OS for Linux tooling validation | native Linux **x86_64** |
| Interpreter | **CPython 3.13.16** (canonical; see §2) |
| Git | any version that supports `rev-parse`/`ls-tree`/`show` |
| Network | required to download the pinned runtime; **not** required to verify |

Do **not** substitute ARM, emulated or cross-resolved environments. Every lock
was resolved natively per platform; reproducing them any other way is not a
valid release build.

## 2. Canonical environment

These identities are fixed. Verify them before building.

| Item | Exact value |
|---|---|
| CPython | **3.13.16** |
| pip-tools | **7.6.1** |
| `requirements.in` SHA256 | `275bdf2469a4d401813ec8a90fe63494ca5324ef6a6466c5904184cbdf6166ad` |
| `lock/linux-cp313.txt` SHA256 | `05c9744beb969acc37b4a89eb61cb4d618291d53ae975ddab5503765c94c9560` |
| `lock/windows-cp313.txt` SHA256 | `a2647d678c0029d8ce0e5ce696ab342327cc929fb3e96988bb1665d7e771d125` |
| Windows CPython embeddable | `https://www.python.org/ftp/python/3.13.16/python-3.13.16-embed-amd64.zip` |
| Embeddable size | `11439094` bytes |
| Embeddable SHA256 | `97dae5274cc54867065e8d5a3226e48c35017ed332a0fdb0e27d5b5821961297` |

### 2.1 Runtime pin

The pinned runtime identity lives in `deploy/windows/runtime-lock.json`. It is
re-verified against the downloaded artifact on every build and **fails closed**
on mismatch. The host interpreter (`sys.executable`, `sys.base_prefix`) never
determines package identity.

**Python 3.13.0 is NOT canonical.** Builds produced under it are tooling
evidence only and must not be published as a release.

## 3. Source eligibility and working directory

Release tooling resolves all source content from **committed Git blobs at a
specific commit**. It does not read release inputs from the working tree, so
artifact bytes are independent of local edits.

It still refuses a dirty worktree by default, because a dirty tree means the
tree you tested is not the tree you are shipping.

**Run all release commands from the repository root.** The tools accept
`--repo` for cross-checking, but examples below assume the repository root as
the current directory. Identity never depends on the caller's current working
directory; the explicit statement here exists so operators are not surprised by
relative paths in examples.

## 4. Dependency locks

- `requirements.in` is **source intent**. It is not an installation authority.
- `lock/<platform>-cp313.txt` is the **installation authority**.

Install strictly from the platform lock with hash enforcement:

```bash
# Windows x64
python -m pip install --require-hashes -r lock/windows-cp313.txt

# Linux x86_64
python -m pip install --require-hashes -r lock/linux-cp313.txt

python -m pip check     # must report no broken requirements
```

**No release or deployment procedure may fall back to ranged requirements.**
Never install from `requirements.in` directly, and never use `--no-deps`,
`--no-binary` or an unpinned package to work around a lock failure. A lock
mismatch is a release blocker, not an obstacle to bypass.

Each lock was resolved natively by CPython 3.13.16 on its own platform's x64
runner. Cross-resolution is prohibited.

## 5. Build procedure

```bash
# From the repository root, on native Windows x64, CPython 3.13.16.
git status --porcelain          # must be empty
git rev-parse HEAD              # record the release commit
git rev-parse 'HEAD^{tree}'     # record the release tree

# Download the pinned runtime and confirm its digest BEFORE building.
# (verify against deploy/windows/runtime-lock.json)

python tools/build-release.py \
    --output-dir dist \
    --runtime-artifact python-3.13.16-embed-amd64.zip
```

Outputs:

```
dist/devai-<commit>-windows-x64.tar
dist/devai-<commit>-windows-x64.tar.sha256
```

What the builder guarantees:

- `SOURCE_DATE_EPOCH` is taken from `git show -s --format=%ct <commit>`. It is
  **never** wall-clock time.
- The artifact is an **uncompressed** `tar` (GNU format). Members are emitted in
  UTF-8 byte order with `uid=0`, `gid=0`, empty `uname`/`gname`,
  `mtime=SOURCE_DATE_EPOCH`, mode `0755` for directories and `0644` for regular
  files. Nothing is derived from umask, and no PAX/nondeterministic metadata is
  emitted.
- `release.json` is canonical JSON: UTF-8, no BOM, LF, sorted keys, stable
  compact formatting, trailing LF.
- The build **fails closed** on secrets and on target-specific state.
- `--allow-dirty-worktree` exists for tooling self-tests only. **Never** use it
  to produce release evidence.

### The artifact digest lives outside `release.json`

`release.json` deliberately does **not** contain the outer artifact SHA256.
Embedding a file's own digest inside that file is recursive and impossible. The
digest is published in the **external sidecar**:

```
<lowercase sha256><2 spaces><filename>\n
```

The sidecar is external to the tar and must be distributed through a channel
independent of the artifact itself.

## 6. Release artifact layout

```
release.json                                  Layer B: release identity
requirements.in                               committed source intent
lock/metadata.json                            lock metadata
lock/windows-cp313.txt                         platform lock
package/manifest.json                         Layer C: package contract
package/install-worker.ps1                     immutable installer
package/install-support.ps1                    immutable helper layer
package/control/worker_agent/*                 immutable worker code
```

The artifact contains **no** `service.json`, **no** `worker.dpapi`, **no**
personal fixture path, **no** plaintext token and **no** target-specific
absolute path. Required immutable members are asserted by both the builder and
the verifier, so a self-consistent but incomplete package can never ship.

## 7. Verification procedure

```bash
python tools/verify-release.py \
    dist/devai-<commit>-windows-x64.tar \
    --sha256-file dist/devai-<commit>-windows-x64.tar.sha256 \
    --repo . \
    --expect-commit <commit>
```

Supply exactly one trusted-anchor form: `--expected-sha256 <hash>` or
`--sha256-file`. If both are supplied they **must agree**; disagreement fails
closed rather than silently preferring one. Verification requires **no network
access**.

The verifier fails closed and reports success only after every layer passes:

1. parse/validate the expected outer hash or sidecar
2. hash the raw artifact bytes
3. compare the outer SHA256
4. inspect tar members **without unsafe extraction**
5. validate member types (no symlink, hardlink, device, FIFO) and paths
   (no absolute, `..`, drive-qualified, or backslash-ambiguous entries)
6. validate the normalised release structure
7. read and schema-validate `release.json`
8. validate source/release identities
9. verify the `manifest.json` digest
10. verify the `install-worker.ps1` digest
11. verify runtime identity
12. verify dependency-lock identities
13. run the authoritative package manifest verification
14. recompute the V2 aggregate
15. reject unexpected artifact members
16. run secret / target-state exclusion checks
17. report PASS only if all of the above succeeded

## 8. Trust model

Three nested layers. They are never collapsed.

```
LAYER A   trusted externally supplied SHA256  →  release .tar bytes
LAYER B   release.json                        →  manifest, installer, runtime,
                                                  locks, source commit/tree
LAYER C   manifest.json                       →  per-file sha256 + size
                                             →  verified payload
                                             →  recomputed V2 aggregate
```

Precise terminology — do not use these loosely:

| Term | Status | Meaning |
|---|---|---|
| **artifact integrity** | implemented | the bytes hash to the expected digest |
| **trusted external hash anchor** | implemented | that digest arrived through a channel you already trust |
| **publisher signature** | **NOT IMPLEMENTED** | no signing key exists |

**A SHA256 does not by itself establish publisher identity.** It authenticates
bytes *relative to the trusted channel that delivered the digest*. If the
expected hash is received over an untrusted channel — the same channel as the
artifact — then an attacker who replaces both defeats it completely. Signing is
future hardening and is **not** implied by anything in this process.

Internal consistency is not authenticity: the V2 aggregate proves the manifest
describes its own payload, and nothing more.

### Launcher trust on the target

`launch-worker-install.ps1` takes **two independent** externally supplied
digests:

- `-ExpectedManifestSHA256` authenticates `manifest.json`.
- `-ExpectedInstallerSHA256` authenticates the installer script bytes about to
  be executed.

These are separate on purpose: a valid payload manifest must never authorise a
substituted installer. Do not collapse them, and do not treat the manifest's
internal aggregate as a substitute for either.

## 9. Rollback material

Retain, for **each** release (current and previous known-good):

| Item | Notes |
|---|---|
| outer release artifact | the `.tar` |
| artifact SHA256 sidecar | external; the Layer A anchor |
| `release.json` | Layer B identity |
| `manifest.json` | Layer C contract |
| platform lock file + lock identities | `lock/<platform>-cp313.txt`, `lock/metadata.json` |
| runtime identity | from `deploy/windows/runtime-lock.json` |
| SBOM, if generated | see §12 |
| source commit + tree identity | from `release.json` |

**Never retain inside release archives:**

- `worker.dpapi` — target secret, and DPAPI-bound to one machine/account
- a populated `service.json` — target state
- any plaintext token
- the personal-denial fixture — target state

Target state stays on the target. Release material stays secret-free.

## 10. Rollback procedure

Rollback must be **artifact-coherent**. Never assemble a rollback package ad
hoc.

```
select a previously retained, verified artifact
  ↓
verify its trusted external hash (Layer A)
  ↓
verify its release metadata (Layer B)
  ↓
check migration compatibility (§11)  ← STOP if incompatible
  ↓
install the old immutable code
  ↓
preserve target identity
  ↓
preserve target credential
  ↓
preserve validated target config unless an explicit incompatible change exists
  ↓
restart and verify (§13)
```

A historical release and its historical installer are a **coherent unit**. Do
not use a new installer to reinterpret an old, incompatible package format
unless that combination is explicitly supported. A legacy `package.json`-only
artifact is correctly rejected by the current installer with
`UNSUPPORTED_LEGACY_PACKAGE_FORMAT`; that is expected behaviour, and the correct
response is to use the installer that shipped with that release.

## 11. Migration policy

**There is no silent database migration downgrade.**

Before any rollback, compare the target's current migration level against the
migration support of the release you intend to install. **If the rollback would
require a migration downgrade that the target release does not support, STOP.**
Escalate for an explicit recovery/migration plan. Do not attempt to reverse
migrations automatically, and do not edit migration files to force a level to
match.

Current frozen state: migrations **001–015**; migration **016 is absent** and
must not be created.

## 12. SBOM procedure

**Format:** CycloneDX JSON.

**Scope:** release software components and dependencies — the packages resolved
by the committed locks. Database tables, schemas and rows are **not**
components and must not be represented as such.

**Generator pin:**

```
SBOM_GENERATOR_PIN: PENDING_STEP_6_OR_RELEASE_PROCESS_VALIDATION
```

No SBOM generator or version has been frozen yet. **Do not** run "the latest
CycloneDX tool": an unpinned generator cannot produce a reproducible SBOM, and
its output would not be a release identity. Freezing the generator and version
is a prerequisite, not an optional extra.

Once a generator is pinned, the procedure is:

| Stage | Definition |
|---|---|
| **Input** | the committed canonical lock(s) (`lock/windows-cp313.txt`, `lock/linux-cp313.txt`), `requirements.in`, `lock/metadata.json`, and the release identity (`release.json`) |
| **Generation** | run the **pinned** generator at the **pinned** version against the committed locks; the SBOM describes the lock contents, not the build machine |
| **Determinism** | the same locks plus the same generator version must yield byte-identical SBOM output; any timestamp, hostname, path or tool-version drift makes the output non-reproducible and must be excluded or normalised |
| **Output** | an SBOM sidecar alongside the artifact (`…tar.sbom.json`), or release material referenced from `release.json` |
| **Identity** | the SBOM's own SHA256 is recorded **externally**, or in the optional `sbom` field of `release.json` **only when it actually exists** |
| **Retention** | retained with the release (§9) |

`release.json` may later carry an `sbom` identity field. Until a real SBOM
exists, the field is **omitted entirely** — no `null`, no empty object, no
placeholder hash. Omitting an optional field is correct; reserving schema space
with fake values is not.

## 13. Post-deploy verification

After installing, verify in this order. Record the outcome of each.

| # | Check | Source of truth |
|---|---|---|
| 1 | deployed release identity (commit + tree) | `release.json` |
| 2 | `manifest.json` digest and V2 aggregate recomputed | `manifest.json` |
| 3 | runtime identity (interpreter version + pinned runtime digest) | runtime lock |
| 4 | dependency identity (lock digests) | lock metadata |
| 5 | service config present and schema-valid | `%ProgramData%\DevAIWorker\service.json` |
| 6 | credential state present, correct path, correct ACL | `credentials\worker.dpapi` |
| 7 | service healthy and running | service control |
| 8 | worker registration / identity matches the control plane | control plane |
| 9 | runtime security gates, including `service_personal_profile_denied` | runtime |
| 10 | basic controller/worker communication | control plane |

Checks 5–10 are **target-side runtime** properties and cannot be established by
release tooling alone.

### Gates that require legitimate elevated Windows execution

These are **pending** and must be reported as pending, never as PASS:

- `RUNTIME_SERVICE_PERSONAL_PROFILE_DENIAL_GATE` — the worker service identity
  must actually receive `PermissionError` reading the denial fixture.
- `WINDOWS_NATIVE_VOLUME_GATE` — private workspace volume creation, formatting
  and NTFS root security.

Both are enforced by real Windows behaviour and require the native elevated
gate. Do not simulate them with mocks and record them as satisfied.

## 14. Signing status

```
PUBLISHER_SIGNATURE: NOT_IMPLEMENTED
```

RH-B introduces **no signing keys, secrets, or signing tooling**. The current
model is a trusted external SHA256 anchor plus fail-closed layered
verification. Introducing long-lived signing secrets is explicitly out of scope
for RH-B.

## 15. Retention

Minimum required retention:

- **CURRENT** — the active release
- **PREVIOUS KNOWN-GOOD** — enough for one verified rollback

Retaining more is encouraged by operational policy. Each retained release keeps
its artifact, its sidecar and its metadata together and verifiably paired. No
secret material is retained inside any release archive.

## 16. Known external gates

| Gate | Status |
|---|---|
| `WINDOWS_NATIVE_VOLUME_GATE` | `BLOCKED_PENDING_ELEVATED_EXECUTION` |
| `RUNTIME_SERVICE_PERSONAL_PROFILE_DENIAL_GATE` | `BLOCKED_PENDING_ELEVATED_EXECUTION` |
| `SBOM_GENERATOR_PIN` | `PENDING_STEP_6_OR_RELEASE_PROCESS_VALIDATION` |
| `PUBLISHER_SIGNATURE` | `NOT_IMPLEMENTED` |
| Native reproducibility (CPython 3.13.16, native x64) | pending STEP 6 |