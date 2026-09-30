# Windows Worker Execution Hardening — acceptance pending

Base: DevAI `4cc5ca8`. No model CLI or new UI is installed. This document records
implementation boundaries; configuration alone is not a passed acceptance gate.

## Service boundary

`DevAIWorker` uses the dedicated Windows virtual account `NT SERVICE\DevAIWorker`,
not the personal account and not Administrators. The service verifies its actual
SID and group membership before heartbeat. SCM configures delayed automatic start,
restart after 10/10/60 seconds, and shutdown controls. A separate SYSTEM service,
`DevAIWorkerVolumes`, attaches only the administrator-owned, fixed 128 MiB VHDX.
It never formats on startup, accepts a disk from the Controller, or hosts execution.

Code lives under `%ProgramFiles%\DevAIWorker`, state under
`%ProgramData%\DevAIWorker`. Protected DACLs allow SYSTEM/Administrators management;
the Worker reads code/config/credentials, and writes only journal/logs/reports and
the managed workspace volume. Runtime hashes are checked at startup. Public
acceptance reports contain booleans, timestamps and public identity, never tokens.
Package preparation also creates a non-secret `service-access-denial.fixture` in
the personal account's existing private credential folder, with a protected
personal/SYSTEM/Administrators DACL. Its fixed path is administrator-approved
service configuration. Startup must prove the service itself cannot read it;
missing fixture is a failed gate, not a successful denial. Keep this documented
fixture for subsequent boot proofs; it never contains credential material.

The machine-DPAPI encrypted credential is readable only by SYSTEM, Administrators
and the service SID. Machine DPAPI alone is not an identity boundary: the file ACL
is mandatory and checked. Tokens are loaded at runtime, never passed in argv or
stored in Git/config/logs. Provisioning/cutover must revoke the previous personal
credential after the service is verified online; duplicating a valid credential
for installation does not count as completing cutover.

## Payload boundary

Only the fixed `synthetic_process` 1.0 payload and absolute Python executable are
allowlisted, including SHA-256 and the exact four local arguments. The prompt goes
through stdin as data. Controller fields cannot choose cwd, executable, argv, env,
network capability or quota. `shell=False` is mandatory.

The Worker generates each job directory and unique AppContainer locally. No
network capabilities or loopback exemptions are granted. Only that AppContainer
receives Modify on its job directory, with low integrity. Runtime/OS files needed
to start Python may be read; personal profile data, Worker credentials/journal and
other jobs are not granted. AppContainer profile storage denies payload writes;
its registry storage is read-only. Reparse ancestors/entries fail closed. Cleanup
does not follow attacker-created junctions and requires confirmed termination.

Processes are created suspended, assigned to a non-breakaway Job Object, then
resumed. Only three pipe handles are inherited, never the Job handle. Limits:
one execution, eight OS processes, 128 MiB/process, 256 MiB/job, 30% CPU hard cap,
60 seconds maximum, 64 KiB prompt/output, 4,096 workspace entries and a dedicated
128 MiB filesystem. Filesystem space is a hard volume bound; entry counts are
polled. stdout/stderr are bounded in memory, stdout is redacted before return;
neither raw stream is dumped in logs. Descendants are killed/waited even after
normal parent exit. Named jobs have private recovery markers outside the payload
workspace. Startup kills/waits surviving jobs or relies on the kernel's final
KILL_ON_JOB_CLOSE reference release before cleaning known workspaces; unknown
directories are quarantined by refusing execution.

## Network baseline

The service host needs outbound Controller TCP 8765 at `100.91.132.78` through
the existing private network, plus existing OS Tailscale infrastructure. It never
needs PostgreSQL access. Synthetic payloads need **no network**: AppContainer
denies Controller 8765, PostgreSQL, Paperclip 3100, LAN, other Tailscale peers and
loopback. Safe probes use Windows access-denied codes for private destinations
and a proven-reachable temporary loopback listener with no payload connection.
Connection refused or an unreachable target alone is not isolation evidence.
Any future model adapter requires a separate reviewed network policy; none is
introduced here. No OCI/UFW/Tailscale rules or public listeners are changed.

## Authority, crash and retention

The authenticated status endpoint is scoped by tenant, Worker and claim_version.
Controller cancellation, lease/deadline loss, shutdown or uncertain connectivity
cancel the local context and kill/wait the Job. A separate authenticated terminal
receipt confirms process termination. The Controller refuses fallback until that
receipt exists; unknown containment raises a fatal ExecutionSafetyError.

The SQLite journal is committed before execution, capped at 16 MiB, with 90-day
retention for terminal acknowledged records. Unacknowledged/unknown records are
retained; exhaustion stops execution safely. On verified boot recovery, running
records become EXECUTION_OUTCOME_UNKNOWN; adapters are never rerun. Pending
terminal receipts are retried as connectivity only. Logs rotate at 1 MiB x four
files. Graceful stop sends a bounded failure/termination acknowledgement.

## Metered evidence reconciliation

Migration `015_worker_execution_hardening.sql` adds price snapshots, evidence
cases, immutable audit events, recovery and unpriced exposures. Prior applied
migrations remain unchanged. Attempt creation and reservation are atomic. Missing
usage transfers reservation to recoverable exposure immediately, stops fallback,
and records an audit event. At 15 minutes it requires review; at 24 hours it is
finally classified as unrecoverable exposure with **NULL actual cost**, not
invented zero usage. Both exposures count against budget. Later authoritative
usage/provider statement can resolve that exposure exactly once, with evidence
hash and audit identity. No provider execution or model fallback is retried.

`devai-accounting-reconciliation.timer` sweeps every minute, loopback DB only.
Manual resolution uses `python -m devai.reconciliation --resolve-stdin`; stdin
accepts tenant_id, case_id, usage or statement_cost or unrecoverable, and an
evidence_sha256 for authoritative cost. Output is status only; evidence contents
are never copied to audit logs. Installation must inspect historical funded
metered attempts before applying 015: unknown legacy prices must not be guessed.

## Deployment and acceptance

Build the private package with `deploy/windows/build-package.py` using the existing
DPAPI config. Review its manifest and `install-worker.ps1`, then run the installer
elevated. The installer refuses existing services/paths rather than overwriting an
unknown installation. A partial install requires reviewed repair, not blind rerun.
The package contains encrypted credential material and must remain private and be
removed after verified cutover. Never commit it.

Before its first heartbeat the installed service runs native cancellation,
timeout, filesystem/registry/environment/network probes under its actual identity.
It writes `reports/service-start.json` only on success. Verify SCM identity,
delayed start, recovery configuration, actual startup probes, quota and heartbeat.
Create a synthetic dispatch, cancel it through Controller, and verify a fenced
termination receipt. Test timeout and forced service crash/restart without rerun.

Finally perform a real Windows reboot with a separate VPS heartbeat observer and
compare boot/start/heartbeat evidence before manual login. Merely setting delayed
start or testing Job-handle closure is not proof of SCM recovery or boot autostart.
This checkpoint stays open until all mandatory service and reboot gates pass.

Native Windows tests: `python -m unittest discover -s tests -p test_windows_process.py -v`.
Worker tests also cover protocol, cancellation, journal recovery and DPAPI. Full
VPS suite: `tests/run_isolated_suite.py` creates an empty temporary database,
applies all migrations, runs tests, then drops it. Credentials stay in runtime env.
