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
