# Acceptance evidence — checkpoint OPEN

Validated on 2026-09-30 from DevAI `4cc5ca8`, branch
`windows-worker-execution-hardening`, implementation commit `114d6a4`.
The Controller was fast-forwarded to that implementation. Migration 015 was
applied transactionally; the Worker API restarted healthy on its existing private
binding, and `devai-accounting-reconciliation.timer` is enabled/active. Windows
service installation and its acceptance gates remain pending.

| Gate | Result |
| --- | --- |
| Complete VPS suite, disposable DB with 001–015 | PASS: 82 tests, 72 passed, 10 Windows-only skipped; DB destroyed |
| Native Windows/Worker suite | PASS: 28 tests, no skipped tests or warnings |
| Parent → child → grandchild cancellation | PASS: all in Job, all terminated |
| Timeout and bounded output | PASS: entire Job terminated |
| Crash-style Job handle loss/recovery | PASS locally; not proof of SCM service recovery |
| cwd/executable/extra argv/environment allowlist | PASS |
| Junction escape and no-follow cleanup | PASS |
| AppContainer profile/registry/ACL escape | PASS under native test identity |
| Worker secret absent from child environment | PASS |
| Private API/PG/Paperclip/LAN/Tailscale peer network | PASS: Windows denied payload connections |
| Loopback | PASS: reachable control listener, payload cannot connect/accept |
| Worker auth, tenant scope, claim version, stale lease/deadline | PASS in isolated VPS suite |
| Controller cancellation and terminal receipt | PASS in protocol/agent tests; live service end-to-end pending |
| Unconfirmed termination blocks fallback | PASS |
| Metered recovery/review/final/late evidence, cross-tenant, append-only audit | PASS |
| Native startup probes | PASS under test identity; installed service identity pending |
| Dedicated service identity / hard VHDX quota / protected installed ACL | PENDING actual installation |
| SCM delayed start, failure recovery, graceful shutdown | PENDING actual service tests |
| Reboot online before manual login | PENDING real Windows reboot |
| Secret scan | PASS: 101 source files, 12 local output files; actual Worker token compared only in memory |
| Existing production state | No active dispatches, funded reservations or running metered attempts observed |
| Controller migration/timer deployment | PASS: 015 applied, accounting sweep success, API health ok |
| Pre-migration backup/real restore | PASS: private 0600 archive, five core tables checked in temporary DB, DB destroyed |

Migration 015 is now immutable, SHA-256
`56f67ca027814c1e8827171205ddd5a4f098f55b6e4a88aa580270e1d6c92daf`.
Further schema corrections must use 016. The pre-015 snapshot is managed at
`/home/ubuntu/.local/state/devai-hardening-backups/20260930T221110Z-pre015.dump`,
with directory 0700 and file 0600. It supplements existing backups and must be
retained until final deployment acceptance; do not restore it over production
merely to revert code. It was genuinely restored to a disposable database, checked
against five core table counts, then that temporary database was destroyed.

Final observed application bindings: PostgreSQL `127.0.0.1:5432`, Paperclip
`127.0.0.1:3100`, Worker API `100.91.132.78:8765`, Tailscale Serve/private 443.
LiteLLM remains absent. SSH retains its existing `0.0.0.0/[::]:22` private firewall
policy; this checkpoint did not change its binding or any OCI/UFW/Tailscale rules.
The accounting timer has no listener. Existing DNS and Tailscale transport
listeners are unchanged by deployment.

The elevated installer attempt did not receive Windows elevation
(`ELEVATION_NOT_GRANTED`, InvalidOperationException). No DevAIWorker services were
created. This is a missing OS installation gate, not an accepted bypass or a passed
deployment. A private, machine-DPAPI package and reviewed installer are prepared
outside Git. A non-secret personal ACL fixture was created by that managed package
preparation; no existing credential was modified or rotated.

To continue, run the prepared installer with actual administrator consent, verify
the installed identity's native startup report, then perform token cutover,
live E2E/service recovery and a real reboot proof. Do not advertise
this checkpoint complete or enable any model adapter while those gates are open.
