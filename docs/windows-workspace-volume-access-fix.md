# Windows Worker: target-volume capacity/access repair (2026-10-01)

The operator installed the startup instrumentation from 57265be. The actual
dedicated nonadministrative service now reports phase workspace_open, AdapterError,
winerror 5, with the failing call workspace.py:90: GetDiskFreeSpaceExW. The NTFS
128 MiB VHDX/GUID/mount/no-letter proof remains valid, the SYSTEM helper is running,
and config/code/credential ACL verification succeeds. Historical FileNotFoundError
entries are retained. This evidence establishes a denied capacity query, not the
exact target-volume DACL; the earlier diagnostic omitted that security descriptor.

Microsoft documents FILE_LIST_DIRECTORY permission for this query:
https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdiskfreespaceexw
Mounted folders associate a directory on one volume with another volume:
https://learn.microsoft.com/en-us/windows/win32/fileio/volume-mount-points

Changes:
- workspace.py queries the already verified, pinned volume GUID with its trailing
  separator rather than inferring target capacity through the host mount object.
  Missing/wrong/oversized volume and failed capacity query still stop execution.
- The fresh installer explicitly enforces the protected DACL on the ACTUAL NTFS
  root through its verified volume GUID, in addition to the host mount folder.
  SYSTEM/Administrators retain full control; only NT SERVICE/DevAIWorker gets
  Modify on that private root, with child inheritance. No public/user/AppContainer
  root grants, administrative Worker membership, owner/SACL changes or quota bypass.
- GetFileSecurityW/SetFileSecurityW operate on that exact GUID root. The managed
  operation first verifies VHDX location/file-backed bus/128 MiB/non-system disk,
  NTFS label/health, mount GUID and exact no-letter partition access paths.
  Root owner must be SYSTEM/Administrators; explicit deny policy or untrusted owner
  requires review and stops the repair. ACL summary reports booleans/counts only.
- Existing-service validation permits only the pinned previous/new workspace.py
  hash, in addition to the separately pinned, already installed service source.
  Other code/config/identity changes are rejected before mutation.
- repair-worker-workspace.ps1 validates the entire package and installed inventory,
  reads the target root policy before stopping anything, supports DiagnoseOnly,
  gracefully stops only the Worker and backs up source/manifest/root DACL under
  protected managed updates. It applies the private policy only if different,
  updates only workspace.py plus its manifest entry preserving file ACLs, then
  starts the Worker and emits the sanitized existing diagnostic. Mutation failures
  restore source/manifest and prior DACL/protection after rechecking the volume.
  The volume helper stays running; no format/mount/detach/drive assignment, service
  account/recovery/network changes, credential reads/decryption/rotation or schema.

Windows: 47 tests pass, including native ACL roundtrip on an owned temporary
fixture, scoped/idempotent root policy, system-drive/untrusted-owner/deny refusal,
unknown runtime-hash refusal, mutation boundary, pinned capacity target, access
denied/oversized/wrong-volume fail-closed, and the existing real AppContainer/Job
tree/network/profile tests. Privileged VHDX queries/root mutation use mocks in
policy tests; the actual installed service remains the required acceptance gate.

Local prepared package: work/windows-hardening-workspace-repair, 1258 files.
Prior packages/launchers/evidence are retained. Encrypted DPAPI bytes are copied
unchanged without decryption. The source correction is tracked in Git; applying
the prepared upgrade requires the operator's elevated session.
Launcher: outputs/repair-windows-worker-workspace.ps1.
Manifest SHA-256:
a1823280492b09bb9c7837bfe5c5e89410fd0091adad5516cb0233f76e857307
Launcher SHA-256:
71c36a012f355ea6b32d134c5094c3771a5dd3c38a266b9cb598fd933db1017f
Previous workspace source:
aa95abd3c4993081497c0f2c4737640401606a551b656affcf4416d1d8bd0de5
Prepared workspace source:
4b1414bf0c33542ecb93913e9b24807160b48320912895c5983de55e5917abc7
Service source remains:
822e6c90e213a2e9dbf5bdcdfc4ccecf6482c3c2a1140d3b68f8d105860e5f30

Checkpoint remains open pending actual elevated root-policy proof, successful
service startup/native gates, E2E, recovery and real reboot before login. This
preparation alone does not prove the denied query or service startup is resolved.

VPS acceptance: 101 discovered, 83 pass, 18 Windows-only tests skipped. A newly
created database exercised migrations 001-015 and was removed afterward. Source
and output secret scans are clean, including in-memory real-token matching.
