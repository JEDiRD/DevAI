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
