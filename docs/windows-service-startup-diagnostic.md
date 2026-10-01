# Worker service startup failure: protected diagnostic (2026-10-01)

The elevated resume validated the exact existing NTFS 128 MiB VHDX, pinned mount
and absence of a letter, without reformatting. It successfully created the Worker
under NT SERVICE/DevAIWorker and configured delayed start/recovery. The next error
was StartServiceFailed at install-worker.ps1 line 90 (Start-Service DevAIWorker),
not line 89 (the volume helper). Current SCM inventory shows the helper Running /
LocalSystem / exit 0 and the Worker Stopped / dedicated account / exit 1066,
service-specific exit 1. Events show the configured restart recovery acting on
Worker startup failures. Exact cause has not yet been established.

The Worker log/state directories are intentionally inaccessible to the unelevated
agent. The existing bootstrap logs only a fixed exception class, so SCM's generic
exit 1 is insufficient. Do not rerun the partial-install mode: the missing service
has now been created and the original resume correctly refuses that state.

Added deploy/windows/diagnose-worker-service.ps1, mirrored as the local artifact
outputs/diagnose-windows-worker.ps1. It is read-only and requires the administrator
session to inspect protected installed state. It emits service states/codes,
allowlisted exception classes extracted from the two owned logs, ACL ownership/
protection/read-write booleans, profile registration/existence booleans, and a
replay of the installed ACL check as administrator. This replay does NOT simulate
the Worker token/identity or start jobs/heartbeat. It never reads/decrypts DPAPI,
prints raw logs/config/exception text, modifies a service or touches disks.
Unknown exception classes are replaced by UNKNOWN_ERROR_CLASS.

The source test executes the real log filter against secret-bearing fixtures and
checks the diagnostic AST for mutating commands. Six installer/diagnostic tests
pass on Windows PowerShell 5.1. The original sanitized install failure is retained
as windows-hardening-original-worker-start-failure.json. Installed services,
runtime, credentials, volume, networking and their policy were not modified in
this diagnostic preparation. The broader checkpoint remains open pending an
actual diagnostic, startup correction, installed service gates and reboot.

## Actual protected diagnostic and bounded startup instrumentation

The operator's elevated diagnostic at 2026-10-01T05:39:05Z reports the helper
Running, Worker Stopped / 1066 / specific 1, eight FileNotFoundError entries,
trusted/protected ACLs without foreign allow entries, read-only Worker access
to code/config/credentials, writable journal/logs, and an existing registered
service profile. The administrator ACL replay passes. This does not prove which
startup operation failed, nor that the service identity has passed native gates.

The service source now records a closed-schema startup failure report: an
allowlisted phase/class, bounded numeric errno/winerror, and at most eight known
worker_agent source basenames/line numbers. Exception text, failure filenames,
locals, request URLs, tokens, credentials and arbitrary error codes are omitted.
The destination is a fixed managed reports file; lexical reparse checks precede
writes and failure to write cannot enable execution. The read-only diagnostic
reconstructs the same schema and rejects unknown values, including malicious
fields in a forged report. Historical failure entries are retained.

Missing personal fixtures STILL fail closed. FileNotFoundError is never treated
as proof of access denial; only PermissionError satisfies that startup check.

deploy/windows/update-worker-startup-diagnostic.ps1 performs a separate bounded
upgrade of an EXISTING dedicated service; the missing-service resume remains
unchanged. It pins the complete new package, runs the real read-only validator,
verifies installed code inventory/digests, config/tenant-worker identity paths,
SCM identity/command and exact mounted private volume before stopping anything.
Only the known previous/new windows_service.py digest can differ from the new
package. Unknown service-source versions, other runtime changes, an administrative
Worker or altered volume/config fail before mutation.

It gracefully stops only DevAIWorker, backs up the exact source and manifest
under managed updates, writes the one new source/hash preserving ACLs, and starts
the Worker to obtain the actual phase report. Write/integrity failures restore
the prior source/manifest. It does not format, mount, detach or recreate a disk,
create a service, alter recovery/identity, modify networking or read/change the
installed DPAPI credential. The existing volume helper is left running. The
operator must execute this in their elevated session: the agent is unelevated.

Local package: work/windows-hardening-startup-diagnostic, 1258 files; the original
install package remains unchanged. DPAPI bytes are copied without decryption.
Manifest SHA-256:
d9a4125748e245e6acbd8f90d48212eb65f299294c15b791a4010951fc091322
New service source SHA-256:
822e6c90e213a2e9dbf5bdcdfc4ccecf6482c3c2a1140d3b68f8d105860e5f30
Previous installed source SHA-256:
435e8ffa241a0fe7bd7d7cf0974ab3bcc2857606bfc6d23bf25c491a6ddf0a60
Installer remains facf24323c9ae573c3f0df1be3fd2703214b87dccb506ebe3134c2571c68e0bd.
Local launcher: outputs/repair-windows-worker-startup.ps1. DiagnoseOnly validates
the complete package and installed state without changing them; default applies
the bounded instrumentation and emits the read-only sanitized diagnostic.

Windows acceptance: 42 tests pass, including native process-tree termination and
isolation, source installer paths, existing-service upgrade guards, actual invalid
package rejection before mutation, and malicious diagnostic redaction. Actual
elevated upgrade/result and the original startup cause remain pending. The wider
checkpoint cannot close before installed-service gates/E2E/recovery/real reboot.

VPS full acceptance: 96 discovered, 79 pass, 17 Windows-only tests skipped. All
migrations through 015 were exercised in a disposable database, removed afterward.
Source/output secret scans pass, including an in-memory real-token comparison.
Controller runtime, API, schema and networking are not changed by this patch.
