# Private Worker network checkpoint

The Controller service runs `devai.worker_api:app` on TCP port `8765`, bound
only to the current IPv4 address returned by `tailscale ip -4`. The repository
contains `deploy/devai-worker-api.service` and its launcher script. Install
the unit under `/etc/systemd/system/`, reload systemd, and enable the service
only on a host with Tailscale connected. No OCI public ingress rule is needed.
`GET /healthz` returns only `{"status":"ok"}` when PostgreSQL is reachable,
or a generic `503` otherwise. Worker calls require their bearer token.

The Windows agent uses only outbound HTTP over the Tailscale address. Its
configuration is JSON, for example:

```json
{
  "worker_id": "20000000-0000-4000-8000-000000000001",
  "api_base_url": "http://100.91.132.78:8765",
  "heartbeat_seconds": 30,
  "poll_seconds": 5
}
```

`credential_path` may be set to an absolute path. If omitted, the agent uses
`%LOCALAPPDATA%\DevAI\worker-token.dpapi`. The token is encrypted with
Windows DPAPI for the current user and is never put in the JSON config or
process arguments. Provision it through a trusted stdin pipe using
`py -3 -m worker_agent.provision --worker-id <uuid>`; the provisioner rejects
an interactive prompt and does not echo the token. Then run
`py -3 -m worker_agent --config <config.json>`.

The agent sends heartbeat on a separate thread, polls for its own dispatches,
and retries connectivity with bounded backoff. It does not retry handler
execution after a submission error; it resends only the same result with the
same `claim_version` until the lease or execution deadline expires. The local
AdapterRegistry currently allowlists only `synthetic_test` version 1.0, returning
`REMOTE_ADAPTER_OK`. Heartbeat advertises this capability. Unknown adapters and
incompatible execution versions fail closed. A durable per-Worker execution
journal prevents duplicate execution across submission retries and restarts.
See [Execution Adapter Foundation](EXECUTION_ADAPTER_FOUNDATION.md) for the
immutable spec, local limits and requirements for future process adapters.

The Worker has no PostgreSQL connection string. PostgreSQL should remain bound
to loopback on the Controller host. The API has no public listener and should
be reached only through the private Tailscale address.
