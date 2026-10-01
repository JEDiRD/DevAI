# Directory-handle capacity verification (2026-10-01)

The elevated workspace repair proved a real target-root policy gap: before repair
the Worker could not list/modify that NTFS root, four foreign allow entries existed
and its DACL was unprotected. After repair only SYSTEM/Administrators/the dedicated
Worker are allowed, the DACL is protected and the Worker has list/Modify. Volume
identity/128 MiB/NTFS/no-letter proofs remained valid and no credentials or volume
contents were replaced. This did not resolve startup: GetDiskFreeSpaceExW still
returned access denied under the actual service at workspace_open / workspace.py:93.
The precise additional access check behind that API denial remains unverified.

Replace the capacity API with a directory-handle query:
1. Keep lexical ancestor/reparse and configured mount-GUID verification.
2. CreateFileW opens the mounted root directory with FILE_LIST_DIRECTORY only,
   OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, null security attributes (no inherited
   handle). It opens a directory, not a raw disk/volume device.
3. GetFinalPathNameByHandleW with VOLUME_NAME_GUID must identify that exact opened
   root as the pinned GUID. A different root, missing name or oversized response
   stops the Worker before any capacity query or process launch.
4. NtQueryVolumeInformationFile reads FileFsSizeInformation using THAT handle.
   Require STATUS_SUCCESS in both syscall and IO_STATUS_BLOCK, exactly 24 bytes,
   positive total units/sector sizes, and consistent available units. Compute
   capacity with Python integer arithmetic; retain the 128 MiB upper bound.
5. Close the noninheritable directory handle on success/failure before execution.
   Directory-open, handle-identity, capacity-query and invalid-result failures are
   distinct fixed errors. NTSTATUS maps to a numeric Win32 error without raw text.

No elevation, ignored AccessDenied, GetDiskFreeSpaceEx fallback, service-account
change, helper trust substitution or quota bypass. Existing SYSTEM boot checks of
the fixed VHDX image/file-backed disk/128 MiB location remain. Directory access
and kernel filesystem-size queries must succeed under the service itself.

Primary references:
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryvolumeinformationfile
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_file_fs_size_information
- https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew

Added a real unelevated native test querying the existing system-volume directory
handle, read-only (no enumeration, content reads, formatting, attachment or file
creation there). This validates the ABI and actual kernel call without mocking.
It does NOT establish that the dedicated installed Worker passes this query.
Mocked guards exercise open denial, incorrect mount/handle identity, excess
capacity, malformed/truncated/unsuccessful I/O and handle cleanup on every path.
Windows suite: 52 tests pass, including existing real AppContainer/Job tree gates.

deploy/windows/update-worker-capacity.ps1 validates the pinned package, installed
runtime/config/SCM/volume and already-correct root DACL before mutation. It refuses
to reconcile a changed root policy. It updates only workspace.py + manifest hash,
retaining backups and file ACLs, then restarts only the Worker and prints the
existing sanitized diagnostic. No root/volume/credential/network/recovery changes.
DiagnoseOnly validates read-only. Invalid package is tested before any mutation.

Separate local package: work/windows-hardening-directory-capacity, 1258 files;
DPAPI encrypted bytes copied unchanged without decryption; older packages retained.
Launcher: outputs/repair-windows-worker-capacity.ps1.
Manifest SHA-256:
8f49d6e3d5863d9e24634f92d1f20d2c178802ec9f85546e5d147e64067e8caf
Launcher SHA-256:
7f8bc9c55ce587980baaafb7e3e1d178fb09aa0a2647735adcbc26d9cff44d9f
Workspace source SHA-256:
b922ea29a28c7cac5d41322583c01762a2079058f26aa631c9b6ee7f04014b70
Pinned previous workspace source:
4b1414bf0c33542ecb93913e9b24807160b48320912895c5983de55e5917abc7

The operator must apply this via their elevated session; the agent is unelevated.
Checkpoint remains open pending actual installed-service capacity/startup/native
gates, E2E, SCM recovery and real reboot before login. No CLI/model/UI work.

VPS acceptance: 106 tests, 86 pass and 20 Windows-only skipped; migrations through
015 executed in a disposable database and that database was destroyed. Source and
outputs secret scans are clean, including an in-memory real-token comparison.
