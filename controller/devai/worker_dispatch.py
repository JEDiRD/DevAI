"""Tenant-scoped immutable queue. Lost leases never cause automatic re-execution."""
from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID, uuid4
import json
from .db import connect

MAX_PROMPT_BYTES = MAX_OUTPUT_BYTES = 65536
MAX_TIMEOUT_SECONDS = 60
SPEC_VERSION = 1


class DispatchUnavailable(RuntimeError):
    pass


class DispatchLeaseLost(RuntimeError):
    pass


class DispatchConflict(RuntimeError):
    pass


@dataclass(frozen=True)
class WorkerDispatch:
    id: UUID
    tenant_id: UUID
    worker_node_id: UUID
    route_key: str
    gateway_model: str
    prompt: str = field(repr=False)
    claim_version: int
    lease_expires_at: datetime
    connection_id: UUID
    adapter_key: str
    execution_timeout_seconds: int
    spec_version: int
    adapter_version: str
    deadline_at: datetime
    idempotency_key: UUID


def _reap(cur, tenant_id, limit=100, dispatch_id=None):
    cur.execute("""
        WITH stale AS (
            SELECT id FROM worker_dispatches WHERE tenant_id=%s
            AND (%s::uuid IS NULL OR id=%s)
            AND status IN ('pending','claimed')
            AND (deadline_at<=clock_timestamp() OR
                (status='claimed' AND lease_expires_at<=clock_timestamp()))
            ORDER BY deadline_at FOR UPDATE SKIP LOCKED LIMIT %s
        ) UPDATE worker_dispatches d SET
            status=CASE WHEN deadline_at<=clock_timestamp() THEN 'expired' ELSE 'failed' END,
            error=CASE WHEN deadline_at<=clock_timestamp() THEN 'DEADLINE_EXCEEDED' ELSE 'LEASE_EXPIRED' END,
            completed_at=clock_timestamp(), lease_expires_at=NULL
        FROM stale WHERE d.id=stale.id
    """, (tenant_id, dispatch_id, dispatch_id, limit))
    return cur.rowcount


def reap_dispatches(*, tenant_id: UUID, limit: int = 100) -> int:
    if not 1 <= limit <= 1000:
        raise ValueError('INVALID_REAPER_LIMIT')
    with connect() as conn, conn.cursor() as cur:
        return _reap(cur, tenant_id, limit)


def create_dispatch(*, tenant_id: UUID, worker_node_id: UUID, route_key: str,
                    prompt: str, gateway_model: str | None = None,
                    connection_id: UUID | None = None,
                    idempotency_key: UUID | None = None) -> UUID:
    if not isinstance(prompt, str) or len(prompt.encode('utf-8')) > MAX_PROMPT_BYTES:
        raise DispatchUnavailable('PROMPT_LIMIT_EXCEEDED')
    import re
    if re.search(r'devai_wkr_|-----BEGIN [A-Z ]*PRIVATE KEY|(?i:Bearer\s+\S+|(?:api[_-]?key|password|secret|token)\s*[=:])',prompt):
        raise DispatchUnavailable('SECRET_PAYLOAD_REJECTED')
    key = idempotency_key or uuid4()
    with connect() as conn, conn.cursor() as cur:
        cur.execute("""SELECT id,worker_node_id,route_key,prompt,gateway_model,connection_id
            FROM worker_dispatches WHERE tenant_id=%s AND idempotency_key=%s""", (tenant_id, key))
        existing = cur.fetchone()
        if existing:
            return _existing(existing, worker_node_id, route_key, prompt, gateway_model, connection_id)
        cur.execute("""
            SELECT c.id,c.adapter_key,r.gateway_model,c.config
            FROM provider_routes r JOIN provider_connections c
              ON c.tenant_id=r.tenant_id AND c.id=r.connection_id
            JOIN worker_nodes n ON n.tenant_id=c.tenant_id AND n.id=c.worker_node_id
            WHERE r.tenant_id=%s AND r.route_key=%s AND c.worker_node_id=%s
              AND r.enabled AND c.enabled AND c.transport='local_cli'
              AND (r.cooldown_until IS NULL OR r.cooldown_until<=clock_timestamp())
              AND n.status='online' AND n.last_seen_at>clock_timestamp()-interval '90 seconds'
              AND c.adapter_key IS NOT NULL AND n.capabilities ? c.adapter_key
            FOR SHARE OF r,c,n
        """, (tenant_id, route_key, worker_node_id))
        row = cur.fetchone()
        if row is None or (connection_id is not None and row[0] != connection_id) or (gateway_model is not None and row[2] != gateway_model):
            raise DispatchUnavailable('ROUTE_NOT_ELIGIBLE')
        config = row[3] if isinstance(row[3], dict) else json.loads(row[3])
        timeout = config.get('execution_timeout_seconds', 30)
        version = config.get('adapter_version', '1.0')
        if type(timeout) is not int or not 1 <= timeout <= MAX_TIMEOUT_SECONDS or not isinstance(version, str) or not 1 <= len(version) <= 40:
            raise DispatchUnavailable('INVALID_EXECUTION_LIMITS')
        dispatch_id = uuid4()
        cur.execute("""
            INSERT INTO worker_dispatches (id,tenant_id,worker_node_id,route_key,prompt,
                connection_id,adapter_key,gateway_model,execution_timeout_seconds,
                spec_version,adapter_version,deadline_at,idempotency_key)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                clock_timestamp()+(%s*interval '1 second'),%s)
            ON CONFLICT (tenant_id,idempotency_key) DO NOTHING RETURNING id
        """, (dispatch_id, tenant_id, worker_node_id, route_key, prompt, row[0], row[1], row[2], timeout, SPEC_VERSION, version, timeout, key))
        inserted = cur.fetchone()
        if inserted:
            return inserted[0]
        cur.execute("""SELECT id,worker_node_id,route_key,prompt,gateway_model,connection_id
            FROM worker_dispatches WHERE tenant_id=%s AND idempotency_key=%s""", (tenant_id, key))
        return _existing(cur.fetchone(), worker_node_id, route_key, prompt, gateway_model, connection_id)


def _existing(row, worker, route, prompt, model, connection):
    if row is None or row[1:4] != (worker, route, prompt) or (model is not None and row[4] != model) or (connection is not None and row[5] != connection):
        raise DispatchConflict('IDEMPOTENCY_CONFLICT')
    return row[0]


def claim_next_dispatch(*, tenant_id: UUID, worker_node_id: UUID,
                        lease_seconds: int = 120) -> WorkerDispatch | None:
    if type(lease_seconds) is not int or not 1 <= lease_seconds <= 120:
        raise ValueError('INVALID_LEASE_LIMIT')
    with connect() as conn, conn.cursor() as cur:
        _reap(cur, tenant_id)
        cur.execute("""
            WITH candidate AS (
                SELECT d.id FROM worker_dispatches d JOIN worker_nodes n
                  ON n.tenant_id=d.tenant_id AND n.id=d.worker_node_id
                WHERE d.tenant_id=%s AND d.worker_node_id=%s AND d.status='pending'
                  AND d.claim_version=0 AND d.deadline_at>clock_timestamp()
                  AND n.status='online' AND n.last_seen_at>clock_timestamp()-interval '90 seconds'
                  AND n.capabilities ? d.adapter_key
                ORDER BY d.created_at,d.id FOR UPDATE OF d SKIP LOCKED LIMIT 1
            ) UPDATE worker_dispatches d SET status='claimed',claim_version=1,
                claimed_at=clock_timestamp(),lease_expires_at=LEAST(d.deadline_at,
                    clock_timestamp()+(%s*interval '1 second'))
            FROM candidate WHERE d.id=candidate.id
            RETURNING d.id,d.tenant_id,d.worker_node_id,d.route_key,d.gateway_model,
                d.prompt,d.claim_version,d.lease_expires_at,d.connection_id,d.adapter_key,
                d.execution_timeout_seconds,d.spec_version,d.adapter_version,d.deadline_at,d.idempotency_key
        """, (tenant_id, worker_node_id, lease_seconds))
        row = cur.fetchone()
    return WorkerDispatch(*row) if row else None


def complete_dispatch(*, tenant_id: UUID, dispatch_id: UUID, worker_node_id: UUID,
                      claim_version: int, content: str, prompt_tokens=None,
                      completion_tokens=None, provider_request_id=None) -> None:
    if not isinstance(content, str) or len(content.encode('utf-8')) > MAX_OUTPUT_BYTES:
        raise DispatchUnavailable('OUTPUT_LIMIT_EXCEEDED')
    for count in (prompt_tokens, completion_tokens):
        if count is not None and (type(count) is not int or count < 0):
            raise DispatchUnavailable('INVALID_USAGE')
    with connect() as conn, conn.cursor() as cur:
        cur.execute("""UPDATE worker_dispatches SET status='succeeded',result_content=%s,
            prompt_tokens=%s,completion_tokens=%s,provider_request_id=%s,
            completed_at=clock_timestamp(),lease_expires_at=NULL
            WHERE tenant_id=%s AND id=%s AND worker_node_id=%s AND claim_version=%s
            AND status='claimed' AND lease_expires_at>clock_timestamp()
            AND deadline_at>clock_timestamp()""", (content, prompt_tokens, completion_tokens,
            provider_request_id, tenant_id, dispatch_id, worker_node_id, claim_version))
        if cur.rowcount != 1:
            raise DispatchLeaseLost('DISPATCH_LEASE_UNAVAILABLE')


def fail_dispatch(*, tenant_id: UUID, dispatch_id: UUID, worker_node_id: UUID,
                  claim_version: int, error: str) -> None:
    import re
    safe_code = error if re.fullmatch(r'[A-Z][A-Z0-9_]{0,79}', error) else 'WORKER_EXECUTION_FAILED'
    with connect() as conn, conn.cursor() as cur:
        cur.execute("""UPDATE worker_dispatches SET status='failed',error=%s,
            completed_at=clock_timestamp(),lease_expires_at=NULL
            WHERE tenant_id=%s AND id=%s AND worker_node_id=%s AND claim_version=%s
            AND status='claimed' AND lease_expires_at>clock_timestamp()
            AND deadline_at>clock_timestamp()""", (safe_code, tenant_id, dispatch_id, worker_node_id, claim_version))
        if cur.rowcount != 1:
            raise DispatchLeaseLost('DISPATCH_LEASE_UNAVAILABLE')


def cancel_dispatch(*, tenant_id: UUID, dispatch_id: UUID) -> bool:
    with connect() as conn, conn.cursor() as cur:
        _reap(cur, tenant_id,dispatch_id=dispatch_id)
        cur.execute("""UPDATE worker_dispatches SET status='cancelled',error='CONTROLLER_CANCELLED',
            completed_at=clock_timestamp(),lease_expires_at=NULL WHERE tenant_id=%s AND id=%s
            AND status IN ('pending','claimed') AND deadline_at>clock_timestamp()""", (tenant_id, dispatch_id))
        return cur.rowcount == 1


def get_dispatch_result(dispatch_id: UUID, *, tenant_id: UUID):
    with connect() as conn, conn.cursor() as cur:
        _reap(cur, tenant_id,dispatch_id=dispatch_id)
        cur.execute("""SELECT status,result_content,prompt_tokens,completion_tokens,
            provider_request_id,error FROM worker_dispatches WHERE tenant_id=%s AND id=%s""", (tenant_id, dispatch_id))
        row = cur.fetchone()
    if row is None:
        raise DispatchUnavailable('DISPATCH_NOT_FOUND')
    return row


def execution_status(*, tenant_id, worker_node_id, dispatch_id, claim_version):
    with connect() as conn, conn.cursor() as cur:
        _reap(cur, tenant_id, dispatch_id=dispatch_id)
        cur.execute('''SELECT status FROM worker_dispatches WHERE tenant_id=%s AND worker_node_id=%s
            AND id=%s AND claim_version=%s AND claim_version>=1''',
            (tenant_id, worker_node_id, dispatch_id, claim_version))
        row = cur.fetchone()
        if row is None:
            raise DispatchLeaseLost('DISPATCH_AUTHORITY_UNAVAILABLE')
        return row[0]


def acknowledge_termination(*, tenant_id, worker_node_id, dispatch_id, claim_version):
    with connect() as conn, conn.cursor() as cur:
        _reap(cur, tenant_id, dispatch_id=dispatch_id)
        cur.execute('''INSERT INTO worker_dispatch_terminations(dispatch_id,tenant_id,worker_node_id,claim_version)
            SELECT id,tenant_id,worker_node_id,claim_version FROM worker_dispatches
            WHERE tenant_id=%s AND worker_node_id=%s AND id=%s AND claim_version=%s AND claim_version>=1
            AND status IN ('succeeded','failed','expired','cancelled')
            ON CONFLICT (dispatch_id) DO NOTHING RETURNING dispatch_id''',
            (tenant_id, worker_node_id, dispatch_id, claim_version))
        if cur.fetchone() is None:
            cur.execute('''SELECT 1 FROM worker_dispatch_terminations WHERE dispatch_id=%s
                AND tenant_id=%s AND worker_node_id=%s AND claim_version=%s''',
                (dispatch_id, tenant_id, worker_node_id, claim_version))
            if cur.fetchone() is None:
                raise DispatchLeaseLost('TERMINATION_ACK_REJECTED')


def termination_confirmed(*, tenant_id, dispatch_id):
    with connect() as conn, conn.cursor() as cur:
        cur.execute('''SELECT d.claim_version,t.dispatch_id IS NOT NULL
            FROM worker_dispatches d LEFT JOIN worker_dispatch_terminations t
              ON t.dispatch_id=d.id AND t.tenant_id=d.tenant_id AND t.claim_version=d.claim_version
            WHERE d.id=%s AND d.tenant_id=%s''', (dispatch_id, tenant_id))
        row = cur.fetchone()
        if row is None:
            raise DispatchUnavailable('DISPATCH_NOT_FOUND')
        return row[0] == 0 or row[1]
