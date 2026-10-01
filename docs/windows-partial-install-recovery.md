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
c865865a543e39943ec08184030f7d412c8596d340f714f02c4b1a39c97b490c
Installer SHA-256:
facf24323c9ae573c3f0df1be3fd2703214b87dccb506ebe3134c2571c68e0bd
Support SHA-256 (also pinned by the manifest):
2e2e734ed85b15352c63e1f54bd8c2b6cf5d104df3039abfe3d66278cc7f06eb
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

Legacy compatibility: original manifest.json inherited its allowed DACL from the
protected code root. Resume accepts inheritance only for this exact file, while
still requiring trusted owner, allowed identities and service read-only rights.
After writing the updated hash, resume protects the same permitted entries.
Fresh installs explicitly protect the manifest file with administrator ownership.
