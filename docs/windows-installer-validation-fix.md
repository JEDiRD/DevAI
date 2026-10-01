# Windows installer validation correction

The source installer no longer calls the ambiguous `String.Split('/', '\')`
overload. `Assert-PackageEntryName` uses `-split '[\\/]'`, rejects traversal and
rooted paths, and additionally rejects ambiguous dot/empty segments and NTFS ADS.
No other `.Split()` calls remain in `deploy/windows`.

`tests/windows/test_installer.ps1` executes the actual source validator under
Windows PowerShell 5.1. Explicit required results:

| Entry | Result |
| --- | --- |
| `valid/file.txt` | ALLOW |
| `valid\file.txt` | ALLOW |
| `../evil.txt` | DENY |
| `..\evil.txt` | DENY |
| `dir/../../evil.txt` | DENY |
| `dir\..\..\evil.txt` | DENY |
| `C:\evil.txt` | DENY |

Additional mixed-separator, UNC and ADS cases pass. Nine full package-flow cases
prove valid read-only validation, traversal rejection, tampered hash rejection,
unmanifested-file rejection and public API-origin rejection. Installation commands
are intercepted; an AST check additionally ensures filesystem writes/service or
volume operations cannot appear before the explicit installation boundary.

The source validates metadata, the complete manifest, every file hash, path
containment, reparse points, required files and the absence of unlisted files
before that boundary. `-ValidateOnly` returns before administrator checks and all
installation actions. Missing-service queries use `-ErrorAction Ignore`.

Windows Worker/native/installer suite: **29 tests passed**, no skips/warnings.
The new test harness gives PowerShell 5.1 its built-in module search path, avoiding
an inherited PowerShell 7 path while testing the real 5.1 runtime.

The regenerated private package contains 1,257 manifested files. Manifest SHA-256:
`690c658da0207a0a4c716074214b7dfcbf7a44ef3d4ebc881bd27d67dfe216bc`.
Installer SHA-256 (source and packaged copy match):
`1eb168325c39b98a74faf51a5ce441fc0f437db47182c5f52b4eb515ebf13525`.
The prepared local `outputs/install-windows-hardening.ps1` pins both hashes before
invoking the installer. It was parsed but **not executed for installation**.
The real regenerated package passed `-ValidateOnly` using Windows PowerShell 5.1.

No DevAIWorker service or installation directories currently exist. The previous
package is archived privately as `windows-hardening-install-before-split-fix`.
Package regeneration reuses the existing non-secret personal-denial fixture
explicitly without changing its permissions, and keeps credentials DPAPI-encrypted
and outside Git. No credentials, migration, Controller service or networking
configuration were modified in this correction. The overall hardening checkpoint
remains open until installed-service, recovery and real reboot gates pass.

## Subsequent elevated ItemNotFoundException

On 2026-10-01 an elevated launcher reported only ItemNotFoundException. The
previous wrapper discarded the original error location, so that output does not
identify a missing file or prove its cause. Local inspection found no installation
directories or services, and the same package validates from Windows System32.
An unelevated full-source probe reaches the expected ADMINISTRATOR_INSTALL_REQUIRED
guard, without installation mutations. The elevated-only cause is not yet known.

`deploy/windows/launch-worker-install.ps1` now preserves a safe phase, fixed error
identifier and original script basenames/line numbers, without exception text,
arguments, URLs or secret values. `-DiagnoseOnly` validates the pinned real package
and performs read-only target/service checks. Its only output-file mutation is a
separate non-secret diagnostic JSON; the original failure record is preserved.
This mode does not create services, installation directories or volumes.

Two Windows PowerShell 5.1 tests verify source package validation and that a
simulated ItemNotFoundException retains its original line while secret-bearing
exception text is absent from the diagnostic. The generated local launcher embeds
this tracked source template; package/installer hashes remain unchanged. An actual
elevated diagnostic is still needed before identifying the cause or retrying an
installation. Do not call this a diagnosed or fixed installation failure yet.

## Confirmed profile-fixture failure and correction (2026-10-01)

The elevated diagnostic identified package_validation / PathNotFound at
install-worker.ps1 line 30: Get-Item on the non-secret personal access fixture.
This was an AppData filesystem-view mismatch, not missing package files:
the Codex packaged process saw Local/DevAI/service-access-denial.fixture;
an unpackaged Python process did not. The physical fixture existed below the
application package's LocalCache/Local/DevAI directory. No fixture contents or
credential values were printed to establish that evidence.

The builder now creates the non-secret probe at
%USERPROFILE%/DevAIWorkerAccessProbe/service-access-denial.fixture, outside
virtualized AppData. The managed directory and file have protected allowlist
DACLs containing only the personal owner, SYSTEM and Administrators. The service
and execution AppContainers receive no access. Existing credentials, credential
paths and personal-profile permissions are unchanged. The original probe and
failure records are retained. Reuse is explicit and does not rewrite the probe.
The installer checks file metadata with -Force and rejects reparse points in
both the fixture and its ancestors, before the installation boundary.

Validation adds private-probe ACL/location/reuse tests, an unsupported-runtime
pre-mutation guard test, and hidden/missing-fixture package tests. Ten path cases
and eleven full-package flow cases retain mutation interception. The launcher
still pins the installer and manifest and retains sanitized diagnostics.

The local Windows suite passes 32 tests using the existing, previously tested
CPython 3.13 distribution. An intermediate build using a different bundled
runtime failed native process startup probes and was archived as unvalidated;
it is not the package referenced by the launcher. CPython 3.11 also cannot run
the deliberately pinned python313.dll/_pth layout. The builder now rejects a
non-3.13 interpreter or absent python313.dll before filesystem mutations.
Acceptance applies to the actual pinned package, not arbitrary Python runtimes.

Final private package: 1,257 manifested files.
Manifest SHA-256:
94497f46a946091ba56ec89ebd3c9d220282a5de49a2ad68984010a97f715325
Installer SHA-256:
b51110f7ce183847850b0b5dec887bbcee97321caf3b0b971fb7cc60f85ec225

An unpackaged process now finds the probe and Windows PowerShell 5.1 validates
the complete pinned package from C:/Windows/System32. DiagnoseOnly completes
installation_preflight, with no services, installation directories or volumes
created. Actual elevation, installation, service recovery and reboot acceptance
remain pending; local tests do not replace those gates. No networking, model
adapter, Controller runtime, migrations or credentials changed in this fix.

VPS acceptance rerun for this correction: 86 discovered, 72 passed and 14
Windows-only tests skipped, using a disposable database migrated through 015.
The disposable database was removed. The 14 Windows-specific gates are covered
by the 32-test local Windows run. Source/output secret scans passed, including
an in-memory comparison against the existing Worker token. Repository changes
are limited to the builder, installer, tests and this evidence document.
