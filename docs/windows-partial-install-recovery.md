# Windows partial installation: SCM quoting and private VHDX (2026-10-01)

The elevated install stopped after creating DevAIWorkerVolumes, before creating
DevAIWorker. The helper is stopped/Automatic/LocalSystem and its quoted binary
path matches the managed Program Files runtime. The original sanitized failure
is retained locally as windows-hardening-original-service-creation-failure.json.

Read-only storage inventory identifies disk 1 as a 134,217,728-byte File Backed
Virtual disk, backed by C:/ProgramData/DevAIWorker/volumes/workspace.vhdx. Its
partition is mounted at C:/ProgramData/DevAIWorker/workspace-volume and currently
has no letter. Disk 0 is the existing Samsung NVMe system/boot SSD containing C:.
No D: is present in current inventory. The reported formatting popup may have
occurred during automatic assignment before the old DiskPart sequence finished;
the exact transient popup cannot be reconstructed from current inventory.
No physical-disk formatting or partition operations were performed by this repair.
Cancel any formatting dialog. Do not retry a fresh install on the partial state.

The SCM failure was reproduced safely with an argument-capture process:
Windows PowerShell 5.1 split the quoted binPath into C:/Program and a second
argument beginning Files/DevAIWorker. The source now uses Win32_Service.Create
through structured CIM parameters, preserving the exact binary string, virtual
account, NULL password and helper dependency. Delayed auto start, restart policy
and SID type are configured afterward. Fixed numeric error codes are preserved;
no secrets or raw exception text are emitted.

## Controlled resume

The manifested install-support.ps1 is loaded only after full package validation.
ResumeServiceCreation is explicit; normal installs still refuse existing state.
Before any mutation, resume validates protected administrator/SYSTEM ownership
and DACLs, fixed config paths and worker identity, the stopped LocalSystem helper
and its exact command, installed runtime hashes and inventory against both its
original manifest and the newly pinned package. Only the approved volume_host.py
change may differ. The encrypted installed credential is inspected for path/ACL
metadata only; it is never read, decrypted or replaced by the resume.

The existing volume must map to the exact fixed VHDX, be file-backed, not a boot
or system disk, be exactly 128 MiB, have one data partition with healthy NTFS and
DevAIWorkspace label, match its pinned volume GUID and folder mount, and have no
letter or additional access paths. Any mismatch stops before writes. An existing
RAW/unrecognized volume is NOT formatted by resume. InspectInstall returns after
these checks without mutations.

Only after those checks, resume copies the approved, manifested mount helper,
updates that single entry in the installed code manifest, creates/configures the
missing Worker service and starts the two managed services. Configuration,
credential, VHDX, existing filesystem and workspaces are preserved.

The volume host now uses Mount-DiskImage -NoDriveLetter for its fixed VHDX,
checks file-backed identity/size and rejects drive letters. It never formats,
partitions or changes global automount. The legacy administrator-owned attach.txt
is still validated for compatibility, but DiskPart is no longer executed at boot.
Fresh installs create a new VHDX file only, attach without a letter, use explicit
storage objects and revalidate file-backed/non-system identity before initializing
and formatting only the newly created partition. Existing-image reuse is rejected.

## Validation and outstanding acceptance

Windows: 36 tests pass. Coverage includes structured SCM arguments with spaces,
virtual identity, dependency, creation error propagation, recovery configuration,
8 unsafe storage cases (physical/boot/system/wrong image/size, RAW, letter and extra
access paths), full partial-config/runtime validation, and no formatting in resume.
The Windows suite also retains real Job Object/AppContainer cancellation, timeout,
process-tree recovery, profile/environment/network isolation gates. Privileged SCM
and storage changes are mocked in installer tests; these do not prove deployment.

Manifest SHA-256:
7da44b04566a41aa9d29e0a6bdccfcea01ecf4fbf9454a57573f910ea871a9b1
Installer SHA-256:
5ba4536601f749d6e99388b115742d4c8e890a932c1dc8e93e8b79fc808da7d4
Support SHA-256 (also pinned by the manifest):
2f6eb41d9160de2a4e343e68ce4502605586ec7b2d77706a5c83c7c924c0773f
Private package: 1,258 manifested files, original tested CPython 3.13 runtime.

The agent is unelevated and cannot inspect protected installed state or establish
the existing volume's filesystem metadata fully. Run the same local launcher in
an elevated PowerShell with -ResumeServiceCreation -DiagnoseOnly first. This
validates the package and partial state read-only and writes only a sanitized
local diagnostic. If validated, run with -ResumeServiceCreation to perform the
bounded repair. Installed-service startup, recovery, DPAPI identity, complete E2E
and real reboot before login remain pending; the checkpoint is still open.
No networking, OCI/UFW/Tailscale settings, Controller runtime, migrations,
credentials or model/CLI adapters were changed.

Primary implementation references:
- https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/create-method-in-class-win32-service
- https://learn.microsoft.com/en-us/powershell/module/storage/mount-diskimage
- https://learn.microsoft.com/en-us/windows-hardware/drivers/storage/createpartition-msft-disk

VPS acceptance: 90 discovered, 75 passed, 15 Windows-only tests skipped;
all migrations through 015 applied only in a disposable test DB, then removed.
Source/output secret scans passed, including an in-memory comparison against
the real existing Worker token. Original failure evidence remains preserved.
