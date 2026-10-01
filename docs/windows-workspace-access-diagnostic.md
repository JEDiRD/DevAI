# Workspace open denial: bounded read-only diagnosis (2026-10-01)

The operator applied be19b3d's directory-capacity update successfully: complete
package/runtime validation passed, the 128 MiB file-backed NTFS volume remained
mounted without a drive letter, and the protected target-root DACL still matched.
Credentials, root ACL, volume contents, helper service and networking were unchanged.
The Worker nevertheless failed before any capacity syscall: CreateFileW returned
ERROR_ACCESS_DENIED (5), workspace_open / workspace.py:42. The SYSTEM volume helper
remained running; the dedicated non-administrative Worker remained stopped.

Do not attribute this additional denial to disk capacity or claim the NTFS-root
DACL proves effective service access. Do not grant administrators/system identity
to the Worker, broaden ACLs, ignore AccessDenied or disable quota verification.

deploy/windows/diagnose-worker-workspace-access.ps1 distinguishes the host-side
mount entry from its NTFS target without detaching/remounting the volume. It first
validates pinned package/installer hashes, the entire deployed runtime/config/SCM
inventory against the CURRENT package and the exact fixed VHD/partition/mount GUID.
Only then it opens fixed paths with READ_CONTROL + FILE_READ_ATTRIBUTES (no write
access, content reads, privilege enabling or raw-device handles):

- ProgramData parent and managed state root, OPEN_REPARSE_POINT.
- Managed workspace mount entry, OPEN_REPARSE_POINT, preserving the host entry.
- Same mount path following its verified volume mount.
- Pinned volume GUID with its trailing root separator, opening the directory.

GetFileInformationByHandleEx(FileAttributeTagInfo) verifies directory/mount-point
metadata. GetSecurityInfo(OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)
copies only security metadata. Handles and allocated descriptors are always freed.
The report emits fixed labels, booleans, counts and numeric Win32 errors. It does
not emit paths, SIDs, descriptor/SDDL bytes, arbitrary exception text, credentials,
raw config/logs or file contents. Inherit-only ACEs do not imply access to the
entry itself; deny/unknown ACEs are reported without inventing effective rights.

The metadata reader runs as ADMINISTRATOR, explicitly reports
effective_service_access=NOT_TESTED and names service ACEs worker_explicit_allow_*.
It does NOT simulate the Worker token or prove a successful service startup.
ServiceSidType and whether RequiredPrivileges/SeChangeNotifyPrivilege are
configured are reported, without claiming the privilege is actually enabled.

This diagnostic never starts/stops services or updates installed files, ACLs,
registry, credentials, disks, firewall, Tailscale or OCI. The existing encrypted
package is reused unchanged. An elevated operator must run the prepared launcher
because the agent cannot read the managed administrator/service-only paths.
Its output is the evidence needed before choosing any further targeted repair.

Tests exercise Windows PowerShell 5.1 syntax, invalid-package rejection, the closed
report schema/secret omission, access-denial visibility, inherit-only/deny ACEs,
and real native metadata reads against an owned temporary directory and junction.
The junction test proves the host reparse entry and followed target are distinct.
It removes ONLY its own junction entry non-recursively before fixture cleanup.
Static guards disallow service/ACL/disk/network mutators and dangerous native calls.
No managed-system change is performed by these tests.

Primary API references:
- https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
- https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo
- https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfileinformationbyhandleex

The checkpoint remains OPEN until actual dedicated-service startup/native gates,
Controller E2E, service crash recovery, and restart before login after a real reboot
have passed. No Codex/model CLI/UI work is authorized by this diagnostic.

Validation: Windows subset 53 passed, no skips. VPS full suite 107 discovered,
86 passed and 21 Windows-only skips; disposable database destroyed afterwards.
Source/output secret scans passed, including a comparison against the existing
Worker token loaded only in memory. Both managed Git checkouts were clean after
the diagnostic source/tests/documentation commit and its fast-forward merge.

Prepared operator command: outputs/diagnose-windows-worker-workspace-access.ps1.
No new installation package is needed. Reused unchanged package manifest:
8f49d6e3d5863d9e24634f92d1f20d2c178802ec9f85546e5d147e64067e8caf
Prepared launcher SHA-256:
876cb0a979e368979ae4be1cfce0f970a5c8ba490fd133537695161c760f2d5d
