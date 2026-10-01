# Effective service access diagnostic (2026-10-01)

The operator's read-only ce5e7d8 diagnostic passed full installed-runtime/package
validation. The file-backed NTFS volume remains 128 MiB, disk 1, correctly mounted
without a drive letter. Its target-root policy matches. Both the host mount entry
(OPEN_REPARSE_POINT) and the followed NTFS/GUID root have protected DACLs, trusted
owners, zero foreign allow/deny ACEs and explicit Worker list/traverse/read-control/
Modify. The managed state root grants list/traverse/read-control, without Modify.
The ProgramData parent has no explicit Worker ACE; that alone is not proof of an
effective traversal denial. ServiceSidType=1 (unrestricted); RequiredPrivileges
is absent. An absent RequiredPrivileges list does NOT prove SeChangeNotifyPrivilege
is absent/disabled in the actual service token. No ACL/privilege change is justified
solely by this administrator metadata report. Worker remains stopped; helper runs.

Add a diagnostic ONLY to the already-verified Worker's workspace_open failure path.
The original failure still stops startup before workspace recovery, credentials,
agent heartbeat or adapter execution. Diagnostic failure cannot clear/change the
original error or authorize execution. No volume-helper fallback/impersonation.

workspace_access_metadata rechecks fixed managed paths, lexical ancestor safety
and pinned mount GUID before probing. Under THAT service thread it records:

- Effective token source: thread if present; primary process only after the exact
  ERROR_NO_TOKEN result. AccessDenied on a thread token never substitutes another.
- Elevation/restriction/AppContainer booleans and bounded restricted-SID count.
- Presence/enabled booleans only for SeChangeNotify, SeBackup and SeRestore.
  TOKEN_QUERY only, no privilege enabling or token duplication/impersonation.
- A maximum of 18 noninheritable read-only directory opens: list, attributes and
  read-control, independently, for ProgramData parent, state root, host mount entry
  without following, followed mount with/without trailing separator, and GUID root
  WITH root separator. No raw volume/device opens, enumeration, file creation,
  content reads, writes or filesystem mutation. All successful handles close.

The GUID root is never trimmed into a raw-device path. No API fallback is added to
normal execution. Original capacity, 128 MiB bound, reparse checks, identity/runtime
validation and fail-closed behavior are preserved. A token-query failure does not
hide independently available directory-open results.

Token query buffers are bounded (4 bytes for scalar flags, 64 KiB maximum for
variable metadata). ReturnLength is honored. Native testing on this Windows runtime
showed TokenElevation requires its exact 4-byte buffer and TokenHasRestrictions
returns a one-byte BOOLEAN; parsing accepts one byte or DWORD without overreading.
No SIDs, token buffers, arbitrary privilege names, paths, exception messages,
credentials, environment contents or raw logs are published. The existing public
startup-failure report receives only fixed labels and numeric/boolean metadata.
The PowerShell report reader revalidates every nested field and drops unknowns.

deploy/windows/update-worker-access-diagnostic.ps1 validates pinned package,
complete installed runtime/config/SCM/VHD state and matching root policy BEFORE
stopping/writing. DiagnoseOnly performs only this preflight. Application gracefully
stops ONLY DevAIWorker, backs up two source files + manifest, preserves file ACLs,
updates ONLY workspace.py/windows_service.py and their hashes, then starts ONLY
that Worker to obtain the actual failure diagnostic. Write failures restore the
backups after confirming the Worker is stopped. No account/recovery/helper/registry,
workspace-root ACL, credential, disk, Tailscale, OCI or firewall changes.

Windows suite: 59 pass, no skips. VPS suite: 113 discovered, 90 pass and 23 Windows
only skips; disposable database destroyed. Native tests query the actual local
token and read-open matrix on an owned directory. Other guards test thread-token
AccessDenied, pinned GUID before probes, independent token-query failure, no
contents/paths in output, closed nested report schema and invalid-package rejection
before mutation. These tests do NOT establish actual installed-service access.
An actual temporary-file transaction also exercises two-source-file + manifest
updates, injected hash failure restoring ALL original files, and preservation of
file ACLs. Every SCM call is mocked and no installed component is touched.

Prepared launcher: outputs/install-windows-worker-access-diagnostic.ps1. Apply from
the operator's elevated shell. It installs diagnostics and starts the Worker; it
does not claim to repair the still-unidentified root cause. Existing encrypted
credentials are copied into the private package byte-for-byte without decryption.
Historical packages/reports are retained. Checkpoint remains OPEN pending the real
service diagnostic/repair, startup gates/E2E/recovery and reboot before user login.

Private package: work/windows-hardening-service-access-v2, 1258 validated files.
Manifest SHA-256:
505230089e7588eba6281c8104be9655bf3d5382a8417b16cf7ee22512a9b21a
Launcher SHA-256:
c0708169458898764f3992f6d6e182ea3f18d50ef919e7c418cf323a72f76e16
The only accepted old runtime hashes are the actual installed workspace
b922ea29a28c7cac5d41322583c01762a2079058f26aa631c9b6ee7f04014b70
and service host
822e6c90e213a2e9dbf5bdcdfc4ccecf6482c3c2a1140d3b68f8d105860e5f30.

Primary references:
- https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation
- https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class
- https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants
- https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
