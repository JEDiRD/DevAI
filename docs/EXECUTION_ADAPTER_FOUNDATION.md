# Execution Adapter Foundation

Checkpoint based on DevAI `74e4ec2`. This implements the remote execution
contract with a synthetic adapter only. Codex, Ollama, UI and process adapters
are not implemented. Security infrastructure and network policy are unchanged.

## Schema and migration

`014_execution_adapter_foundation.sql` is the only new migration. Apply it in
one PostgreSQL transaction after reviewing a rollback-only trial. Migrations
001–013 are unchanged. Do not reapply or edit an applied migration.

Routes explicitly select `free`, `metered`, `subscription` or `local` billing.
Initial routes are openrouter/free → free, gemini/standard → metered and
codex/frontier → subscription. Connections carry nullable `adapter_key`, never
billing. The existing Codex connection becomes local_cli/codex_cli; its local
session reference is never resolved by the Controller.

Existing dispatch evidence is archived as spec v0 with legacy adapter version.
Existing active dispatches expire rather than acquiring invented executable
semantics. Historical attempt billing remains NULL rather than relabeling old
accounting. New dispatches use spec v1 and immutable snapshots guarded by a
database trigger; terminal evidence is immutable too.

## Accounting and eligibility

Metered routes require an active price, a configured reservation and budget
reservation before calling any gateway. Usage must contain nonnegative integer
input/output counts. Settlement calculates authoritative cost from the captured
price version and atomically updates the running attempt and job budget. Billing
mode must match the attempt. Missing pricing fails before execution; missing
usage or an over-ceiling result fails closed and keeps the reservation for
operator reconciliation. A cost class named `free` cannot bypass metered billing.

Free, subscription and local attempts record zero incremental cost without
requiring token pricing or a budget reservation. Optional usage is telemetry.
The legacy route `pricing_key` remains a required schema field, but no active
pricing row is looked up for these three billing modes.

Worker routes require enabled route and connection, available circuit breaker,
online Worker, heartbeat younger than 90 seconds, a connection adapter and that
adapter in the Worker's advertised capabilities. local_cli requires a Worker
binding. Windows advertises only synthetic_test; codex_cli is therefore ineligible.

## Execution and ownership

`RemoteWorkerGateway.complete(model, prompt)` snapshots tenant, Worker, route,
connection, model, adapter, adapter version, spec version, prompt, timeout,
absolute deadline and a tenant-scoped UUID idempotency key. No credentials,
session, executable, command, shell, arbitrary arguments, environment or working
directory are carried in the dispatch. Obvious secret payloads are rejected.

Concurrent creation with the same tenant/key returns one dispatch. Reusing that
key with different caller-supplied identity or input fails. Route/connection
edits do not alter an existing snapshot. Claims are tenant/Worker scoped, use
row locks with SKIP LOCKED and fence execution with claim_version 1. Claimed
dispatches are never automatically reclaimed.

Deadline and lease are distinct: reaching the deadline expires the dispatch;
losing a lease before its deadline fails it with LEASE_EXPIRED. Both fence
complete/fail. Reaping and cancellation are idempotent; targeted result reads
reap their dispatch even when other expired work has accumulated. Reaping runs
on claims/result reads and is also callable by the Controller. There is no
separate retry engine or new background service.

Gateway polling is bounded (at most 65 seconds), has jitter/backoff and never
recreates a dispatch after a connectivity error. Terminal failures and timeout
produce typed, fixed-code errors. Only the Controller Executor selects fallback.
LiteLLM transport continues to use LiteLLMGateway.

## Windows local invariants

LocalModelAdapter, AdapterRegistry and AdapterResult define the adapter contract.
Only synthetic_test version 1.0 is allowlisted and returns REMOTE_ADAPTER_OK.
Unknown adapters/spec versions/incompatible versions fail closed. The client
rejects unexpected execution fields and bounds response size. Local limits are
64 KiB prompt, 64 KiB output, 60 seconds and one concurrent execution. Deadline
checks use both wall-clock timestamps and a conservative monotonic limit derived
from Controller time, allowing for network round-trip time.

A per-Worker SQLite execution journal under LOCALAPPDATA/DevAI commits a running
record before invoking the adapter. Completed duplicates reuse the cached result;
uncertain execution after a crash is never rerun. The journal stores a snapshot
fingerprint, bounded result and error code; it does not store the prompt or token.
Preserve this journal across Worker restarts. Deleting it removes the local
crash/deduplication evidence; Controller claim fencing remains in effect.

Worker credentials continue to use the existing DPAPI CredentialStore. No token
is passed in process arguments, dispatched, logged or stored in Git. Heartbeats
advertise the local adapter allowlist. Connectivity and result-submission retry
do not rerun the adapter and do not select another model.

Future process adapter policy is local: absolute executable/cwd, local argument
tuple, prompt via stdin, shell=False, minimal environment, bounded/redacted
streams and local limits the Controller cannot raise. ProcessTreeLauncher and
ProcessTreeSession require containment before code runs: suspended Windows child
assigned to a kill-on-close Job Object before resume, or a dedicated POSIX process
group. Timeout, cancellation, errors and normal parent exit must terminate and
wait for descendants. The only launcher implementation is disabled: no raw Popen
fallback exists and this checkpoint launches no model subprocess.

## Validation and operator commands

VPS: set DEVAI_TEST_DATABASE_URL from the existing runtime environment without
printing it, set PYTHONPATH=controller and run:

```sh
.venv/bin/python -m unittest discover -s tests -v
```

Windows (no PostgreSQL/client DB credentials):

```powershell
$env:PYTHONPATH='tests'
py -3 -m unittest test_worker_agent test_worker_adapters -v
```

PostgreSQL integration fixtures use rollback, or isolated random tenants with
explicit cleanup for multi-connection races. Coverage includes capability gates,
immutability, concurrent idempotency/claim/reaper, deadline/lease fences,
cancellation, cross-tenant auth, wrong claim version, secret rejection, billing
fail-closed behavior, incompatible versions, injection, local limits,
crash recovery and gateway reconnect/timeout ownership.

`tests/run_synthetic_e2e.py` is an operator-only real Windows test. It takes no
credential arguments, requires the existing private API and connected Windows
Worker, enables a dedicated synthetic/local fixture temporarily, verifies the
GatewayResult and disables both route and connection afterward. It retains the
successful dispatch as evidence; synthetic routes must stay disabled outside
this test so synthetic responses cannot serve production model fallback.

Acceptance evidence on 2026-09-30 after recovery from a Windows power outage:
dispatch `b0967d91-0d55-4b8c-8fbc-b493231edd8f`, succeeded, claim_version 1,
spec_version 1, adapter_version 1.0, REMOTE_ADAPTER_OK, completed before deadline.
Reusing its idempotency key returned the same dispatch. Earlier accepted dispatch
`a0ac6e9a-cb3e-450d-a073-3365104c0df3` and its completed local journal record
survived the Worker restart. VPS suite: 62 tests,
61 passed and one Windows-only DPAPI skip. Windows suite: 15 passed including
DPAPI. Migration trial rolled back successfully before atomic application.
Only the existing Worker API binding 100.91.132.78:8765 is used.

## Remaining work before real process execution

Implement and test Job Object/process-group containment, actual subprocess
stream capture and Controller cancellation propagation before registering any
process adapter. Review durable journal retention/permissions and Windows
autostart packaging when deploying a persistent Worker service. Missing metered
usage requires authoritative operator reconciliation; it must never be silently
charged as zero. At-most-once execution deliberately trades uncertain crash
availability for avoiding duplicate external side effects.

Local baselines cannot anchor trust against root compromise. No security
baseline is reconciled by this checkpoint; any expected AIDE change caused by
authorized DevAI source updates needs a separately authorized infrastructure
reconciliation. No Tailscale, OCI, Telegram or Security Observability setting
is modified here.
