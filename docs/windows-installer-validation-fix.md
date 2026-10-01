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
