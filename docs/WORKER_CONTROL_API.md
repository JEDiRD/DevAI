# Worker Control API

Workers connect to the Controller through four authenticated `POST` routes:

| Route | Request | Success |
| --- | --- | --- |
| `/v1/worker/heartbeat` | Optional `platform`, `architecture`, adapter `capabilities` | `204` |
| `/v1/worker/claim` | Empty | `200` with one dispatch, or `204` if none |
| `/v1/worker/dispatches/{id}/complete` | `claim_version`, `content`, optional usage and provider request ID | `204` |
| `/v1/worker/dispatches/{id}/fail` | `claim_version`, `error` | `204` |

Every call requires `Authorization: Bearer <worker-token>`. The token resolves
the tenant and Worker node; request bodies cannot select either identity.
A missing, expired, or revoked token returns `401`, as does a token belonging
to a disabled Worker or suspended tenant. A lost or foreign dispatch lease
returns `409` without exposing the dispatch owner.
Claims require an online Worker with a heartbeat younger than 90 seconds and
the dispatch adapter in its capabilities. Claim responses include the immutable
ExecutionSpec, absolute deadline and Controller time. Results require an unexpired
lease and deadline as well as the correct claim_version; stale work is never
automatically reclaimed. See [Execution Adapter Foundation](EXECUTION_ADAPTER_FOUNDATION.md).

Controller administration provisions credentials through
`devai.worker_identity.issue_worker_token(tenant_id, worker_node_id)`, revokes
them with `revoke_worker_token(tenant_id, worker_node_id, token_id)`, and
atomically replaces one credential with
`rotate_worker_token(tenant_id, worker_node_id, token_id)`. The issuance and
rotation calls return the secret once. Deliver it to the Worker through an
approved private channel; keep it out of logs and source control. PostgreSQL
stores only its SHA-256 digest in `worker_tokens`.

The ASGI application is `devai.worker_api:app`. For local development, load
`DEVAI_DATABASE_URL`, set `PYTHONPATH=controller`, and bind Uvicorn to
`127.0.0.1`. Configure private networking and TLS before exposing the API to
a remote Worker. No Worker requires PostgreSQL credentials.

Apply migrations through `014_execution_adapter_foundation.sql` before starting
the current API/Worker pair. Run the
full suite, including database integration tests, with
`DEVAI_TEST_DATABASE_URL` pointing to a PostgreSQL database with migrations
001–014 applied. Integration fixtures roll back, or use isolated random tenants
with explicit cleanup for true concurrent connection tests.
