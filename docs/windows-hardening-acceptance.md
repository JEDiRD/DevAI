# Acceptance evidence — checkpoint OPEN

Validated on 2026-09-30 from DevAI `4cc5ca8`, branch
`windows-worker-execution-hardening`. Production remains at `4cc5ca8`.
Migration 015 and new systemd units are staged, not applied/enabled in production.

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

The elevated installer attempt did not receive Windows elevation
(`ELEVATION_NOT_GRANTED`, InvalidOperationException). No DevAIWorker services were
created. This is a missing OS installation gate, not an accepted bypass or a passed
deployment. A private, machine-DPAPI package and reviewed installer are prepared
outside Git. A non-secret personal ACL fixture was created by that managed package
preparation; no existing credential was modified or rotated.

To continue, run the prepared installer with actual administrator consent, verify
the installed identity's native startup report, then perform Controller deployment,
token cutover, live E2E/service recovery and a real reboot proof. Do not advertise
this checkpoint complete or enable any model adapter while those gates are open.
