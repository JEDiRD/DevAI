# VHD attachment access boundary (2026-10-01)

The operator applied 91dcc76's diagnostic successfully; package/runtime/root-policy
validation passed and credentials/ACL/volume contents remained unchanged. Actual
Worker-thread results (primary token, no thread impersonation) now establish:

- ProgramData parent, managed state root and host mount entry: list, attributes
  and read-control opens ALL succeed.
- Followed mount, followed mount with trailing separator, and pinned GUID root:
  ALL nine opens fail ERROR_ACCESS_DENIED (5).
- SeChangeNotifyPrivilege present and enabled; no restricted SIDs, no AppContainer,
  no token filtering; SeBackup/SeRestore absent. The failure is not proof that
  traversal privilege is missing or that parent/mount/root DACLs need broadening.
- TokenElevation is true, but the existing verified service-identity gate passed:
  expected virtual-account user SID and NO Administrators SID in groups. A scalar
  elevation flag alone must not be reported as Administrators membership.
- Worker remains stopped at workspace_open; SYSTEM volume helper remains running.

The source has an additional policy gap to investigate: volume_host uses
Mount-DiskImage without an explicit attachment security descriptor. The installer
protects the backing VHDX file for SYSTEM/Administrators only. These are separate
objects from the mounted NTFS root. Microsoft's AttachVirtualDisk documentation
states that its optional attachment descriptor, if NULL, defaults to the image
file descriptor. This explains a plausible independent attachment barrier, but
the source calls a Storage cmdlet rather than AttachVirtualDisk directly: the
actual descriptor/flags used by that cmdlet must NOT be assumed from this alone.

Extend the existing READ-ONLY administrator metadata diagnostic with the explicit
IncludeDeviceSecurity switch. It validates the CURRENT pinned package, complete
installed runtime/config/SCM and exact fixed VHD/image/disk/partition/GUID/mount
before deriving three additional targets:

- Backing VHDX image: security/attribute metadata only, never image contents.
- That validated GUID without its final separator: volume DEVICE security only.
- PhysicalDriveN, where N is obtained from the verified 128 MiB file-backed VHD,
  never a supplied disk number and never a boot/system disk.

Device handles explicitly request READ_CONTROL ONLY, OPEN_EXISTING and share
read/write. No FILE_READ_DATA/WRITE_DATA, raw-sector read/write, IOCTL, security
modification, privilege adjustment, attach/detach, formatting, drive assignment,
account change, service restart, firewall, Tailscale or OCI change. Descriptors are
queried via GetSecurityInfo, retained only in memory and freed with their handles.
The JSON includes only fixed labels, error numbers, boolean/count summaries. SIDs,
paths, SDDL/descriptor buffers, file contents and arbitrary exception text are
never emitted. Generic read/write/full-control bits and common group allow ACE
presence are distinguished from mapped filesystem rights and effective access.

These administrator device-object ACL queries do NOT automatically prove that
the queried descriptor equals the VHD attachment user filter. The report explicitly
keeps attachment_filter_verified=false and effective_service_access=NOT_TESTED.
Unsupported/denied metadata queries are reported as such, without inference.

Tests exercise the native reader on an OWNED regular-file fixture denying data
read while permitting READ_CONTROL + SYNCHRONIZE: ordinary data-open is denied,
security-only mode succeeds. No actual disk is opened in automated tests. Existing
native junction distinction, generic-mask/group summary, secret omission, syntax,
invalid-package-before-action and no-mutator guards remain. Test-only DACL changes
are scoped to the owned temporary fixture and restored with DACL-only native calls,
preserving owner/SACL. Test cleanup remains bounded to that temporary directory.

Prepared command: outputs/diagnose-windows-worker-volume-security.ps1. It reuses
the operator's already-installed service-access-v2 package unchanged; no package
regeneration or runtime update is needed. The agent is unelevated and cannot query
the protected installed image/device descriptors itself. Obtain this evidence
before choosing a scoped attachment-policy repair. No remount/ACL/privilege change
has been executed or provided as a blind repair.

Any subsequent remount must verify the exact owned image and pinned GUID, stop the
Worker safely, preserve outstanding job/lease and recovery state, retain a backup
and avoid forced detach/formatting or touching the system disk. A persistent fix
must establish explicit attachment policy in the managed helper/fresh installer,
retain protected backing-file/NTFS/job ACLs, and prove actual service + AppContainer
access and denial outside each job before heartbeat. Do not grant Worker admin,
SeBackup/SeRestore, broad personal-profile access or network capabilities.

Primary references:
- https://learn.microsoft.com/en-us/windows/win32/api/virtdisk/nf-virtdisk-attachvirtualdisk
- https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo
- https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew

Checkpoint remains OPEN: attachment barrier not yet repaired; actual startup,
service E2E/recovery and reboot before login remain pending. No CLI/model/UI work.

Validation: Windows full subset 59 passed without skips; VPS full suite 113 tests,
90 passed and 23 Windows-only skips, disposable DB destroyed. Source/output real
token comparison secret scan is clean. The 1258-file current package validates
unchanged. Prepared read-only launcher SHA-256:
5bd8feccb00ad0eff2f4fa3c735e20a65457ab91d2fb70eb4a498970a132e864
Reused package manifest SHA-256:
505230089e7588eba6281c8104be9655bf3d5382a8417b16cf7ee22512a9b21a
