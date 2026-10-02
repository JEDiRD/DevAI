"""Recover accounting evidence only. Never retry an execution or invent actual cost."""
from decimal import Decimal
import re
from uuid import uuid4

from .db import connect
from .pricing import ModelPrice, calculate_cost, PricingNotConfigured


class ReconciliationError(RuntimeError):
    pass


def _event(cur, case_id, action, actor, evidence=None, actual=None):
    if not re.fullmatch(r'(?:controller|accounting-timer|operator|provider-import|operator:[a-f0-9]{64})', actor) or (evidence is not None and not re.fullmatch(r'[a-f0-9]{64}', evidence)):
        raise ReconciliationError('INVALID_AUDIT_IDENTITY')
    cur.execute('INSERT INTO metered_reconciliation_events(case_id,action,actor,evidence_sha256,actual_cost_usd) VALUES (%s,%s,%s,%s,%s)',
                (case_id, action, actor, evidence, actual))


def start_metered_attempt(*, job_id, task_id, number, route, model, price, reservation,
                          tenant_id):
    if not isinstance(reservation,Decimal) or not reservation.is_finite() or reservation < 0:
        raise ReconciliationError('INVALID_RESERVATION')
    identifier = uuid4()
    with connect() as conn, conn.cursor() as cur:
        cur.execute('SELECT input_per_million_usd,output_per_million_usd FROM model_pricing WHERE pricing_key=%s AND version=%s AND active', (price.pricing_key, price.version))
        snapshot = cur.fetchone()
        if snapshot is None or snapshot != (price.input_per_million_usd,price.output_per_million_usd):
            raise PricingNotConfigured('METERED_PRICING_UNAVAILABLE')
        # (A) Budget reservation carries its own tenant scope: the budget is
        # only reserved for a job owned by tenant_id. The funds guard,
        # arithmetic and exception semantics are unchanged.
        cur.execute(f'''UPDATE job_budgets SET reserved_usd=reserved_usd+%s,updated_at=clock_timestamp()
            WHERE job_id=%s AND reserved_usd+spent_usd+recovery_exposure_usd+unpriced_exposure_usd+%s<=limit_usd
            AND EXISTS (SELECT 1 FROM jobs j WHERE j.id=job_budgets.job_id AND j.tenant_id=%s)''',
            (reservation, job_id, reservation, tenant_id))
        if cur.rowcount != 1:
            raise ReconciliationError('METERED_BUDGET_DENIED')
        # (B) Attempt creation independently proves job, task, task-in-job
        # and tenant in the INSERT ... SELECT itself.
        cur.execute(f'''INSERT INTO execution_attempts(id,job_id,task_id,attempt_number,route_key,provider,
            gateway_model,billing_mode,status,started_at,pricing_key,pricing_version,reserved_cost_usd,
            input_price_snapshot,output_price_snapshot,accounting_due_at)
            SELECT %s,j.id,t.id,%s,%s,%s,%s,'metered','running',clock_timestamp(),%s,%s,%s,%s,%s,
                clock_timestamp()+interval '15 minutes'
            FROM jobs j JOIN tasks t ON t.job_id=j.id
            WHERE j.id=%s AND t.id=%s AND t.job_id=j.id AND j.tenant_id=%s''',
            (identifier, number, route.key, route.provider, model, price.pricing_key, price.version,
             reservation, *snapshot, job_id, task_id, tenant_id))
        if cur.rowcount != 1:
            # Rolls back the reservation above: both statements share this
            # transaction, so no partial reservation survives.
            raise ReconciliationError('ATTEMPT_SCOPE_INVALID')
    return identifier


def _open(cur, attempt_id, *, result_success=False, tenant_id):
    # Lock order is case -> attempt -> budget throughout resolution. Opening a new
    # case first locks attempt; a resolution cannot exist until its insert commits.
    #
    # AUTHORIZATION uses the caller-supplied tenant_id only. The tenant_id read
    # from the attempt's job row below is ATTRIBUTION (which tenant the opened
    # case is recorded against) and must never stand in for authorization.
    cur.execute('''SELECT id FROM metered_reconciliations m
        JOIN execution_attempts a ON a.id = m.attempt_id
        JOIN jobs j ON j.id = a.job_id
        WHERE m.attempt_id=%s AND j.tenant_id=%s''', (attempt_id, tenant_id))
    previous = cur.fetchone()
    if previous:
        return previous[0]
    # Authorization gate: the attempt must belong to the supplied tenant.
    cur.execute('''SELECT a.job_id,j.tenant_id,a.reserved_cost_usd,a.billing_mode,a.status
        FROM execution_attempts a JOIN jobs j ON j.id=a.job_id
        WHERE a.id=%s AND j.tenant_id=%s FOR UPDATE OF a''', (attempt_id, tenant_id))
    row = cur.fetchone()
    cur.execute('''SELECT id FROM metered_reconciliations m
        JOIN execution_attempts a ON a.id = m.attempt_id
        JOIN jobs j ON j.id = a.job_id
        WHERE m.attempt_id=%s AND j.tenant_id=%s''', (attempt_id, tenant_id))
    raced = cur.fetchone()
    if raced:
        return raced[0]
    if row is None or row[3:] != ('metered', 'running') or row[2] is None:
        raise ReconciliationError('METERED_ATTEMPT_NOT_RECOVERABLE')
    job, attributed_tenant, exposure = row[:3]
    identifier = uuid4()
    # Case INSERT: attribution only, and only reached after the gate proved
    # the attempt belongs to tenant_id.
    cur.execute(f'''INSERT INTO metered_reconciliations(id,tenant_id,job_id,attempt_id,status,exposure_usd,result_success)
        SELECT %s,%s,job,%s,'recoverable',%s,%s
        WHERE EXISTS (SELECT 1 FROM execution_attempts a JOIN jobs j ON j.id=a.job_id
            WHERE a.id=%s AND a.job_id=%s AND j.tenant_id=%s)''',
        (identifier, attributed_tenant, attempt_id, exposure, result_success,
         attempt_id, job, tenant_id))
    if cur.rowcount != 1:
        raise ReconciliationError('RECOVERY_CASE_SCOPE_INVALID')
    # Budget mutation: directly tenant-scoped, not job-id only.
    cur.execute(f'''UPDATE job_budgets SET reserved_usd=reserved_usd-%s,
        recovery_exposure_usd=recovery_exposure_usd+%s,updated_at=clock_timestamp()
        WHERE job_id=%s AND reserved_usd>=%s
        AND EXISTS (SELECT 1 FROM jobs j WHERE j.id=job_budgets.job_id AND j.tenant_id=%s)''',
        (exposure, exposure, job, exposure, tenant_id))
    if cur.rowcount != 1:
        raise ReconciliationError('RECOVERY_BUDGET_TRANSFER_FAILED')
    # Attempt mutation: directly tenant-scoped through attempt -> job -> tenant.
    cur.execute(f'''UPDATE execution_attempts SET status='failed',
        error_message='METERED_USAGE_PENDING',finished_at=clock_timestamp()
        WHERE id=%s AND EXISTS (SELECT 1 FROM jobs j
            WHERE j.id=execution_attempts.job_id AND j.tenant_id=%s)''', (attempt_id, tenant_id))
    if cur.rowcount != 1:
        raise ReconciliationError('RECOVERY_ATTEMPT_SCOPE_INVALID')
    _event(cur, identifier, 'opened', 'controller')
    return identifier


def defer_missing_usage(*, attempt_id, result_success, tenant_id):
    with connect() as conn, conn.cursor() as cur:
        return _open(cur, attempt_id, result_success=result_success, tenant_id=tenant_id)


def _resolve(cur, tenant_id, case_id, *, actor, usage=None, statement_cost=None, evidence=None, unrecoverable=False):
    cur.execute('''SELECT job_id,attempt_id,status,exposure_usd,result_success,resolution
        FROM metered_reconciliations WHERE tenant_id=%s AND id=%s FOR UPDATE''', (tenant_id, case_id))
    case = cur.fetchone()
    if case is None:
        raise ReconciliationError('CASE_NOT_FOUND')
    job, attempt, status, exposure, success, previous = case
    late = status == 'resolved' and previous == 'unrecoverable_exposure' and (usage is not None or statement_cost is not None)
    if status == 'resolved' and not late:
        return False  # Idempotent: already resolved evidence cannot spend twice.
    cur.execute('''SELECT pricing_key,pricing_version,input_price_snapshot,output_price_snapshot
        FROM execution_attempts WHERE id=%s AND job_id=%s AND billing_mode='metered' FOR UPDATE''', (attempt, job))
    snapshot = cur.fetchone()
    if snapshot is None:
        raise ReconciliationError('ACCOUNTING_SCOPE_INVALID')
    pt = ct = None
    if usage is not None:
        pt, ct = usage
        if snapshot[2] is None or snapshot[3] is None:
            raise ReconciliationError('PRICE_SNAPSHOT_MISSING')
        actual = calculate_cost(ModelPrice(*snapshot), pt, ct)
        resolution = 'usage'
    elif statement_cost is not None:
        if evidence is None or not isinstance(statement_cost, Decimal) or not statement_cost.is_finite() or statement_cost<0:
            raise ReconciliationError('AUTHORITATIVE_STATEMENT_REQUIRED')
        actual, resolution = statement_cost, 'provider_statement'
    elif unrecoverable:
        actual, resolution = None, 'unrecoverable_exposure'
    else:
        raise ReconciliationError('RESOLUTION_EVIDENCE_REQUIRED')
    if actual is not None and evidence is None:
        raise ReconciliationError('AUTHORITATIVE_EVIDENCE_REQUIRED')
    # Unrecoverable evidence is an explicit exposure allocation, NOT invented cost.
    source = 'unpriced_exposure_usd' if late else 'recovery_exposure_usd'
    allocation = exposure if actual is None else Decimal(0)
    assignments = ('unpriced_exposure_usd=unpriced_exposure_usd-%s,spent_usd=spent_usd+%s'
        if late else 'recovery_exposure_usd=recovery_exposure_usd-%s,spent_usd=spent_usd+%s,unpriced_exposure_usd=unpriced_exposure_usd+%s')
    amounts = (exposure, actual or Decimal(0)) if late else (exposure, actual or Decimal(0), allocation)
    cur.execute(f'''UPDATE job_budgets SET {assignments},updated_at=clock_timestamp()
        WHERE job_id=%s AND {source}>=%s''', (*amounts, job, exposure))
    if cur.rowcount != 1:
        raise ReconciliationError('RESOLUTION_BUDGET_FAILED')
    cur.execute('''UPDATE execution_attempts SET reconciled_cost_usd=%s,prompt_tokens=%s,completion_tokens=%s,
        status=%s,error_message=%s WHERE id=%s''', (actual, pt, ct,
        'succeeded' if actual is not None and success else 'failed',
        None if actual is not None else 'METERED_USAGE_UNRECOVERABLE', attempt))
    cur.execute("UPDATE metered_reconciliations SET status='resolved',resolution=%s,actual_cost_usd=%s,resolved_at=clock_timestamp() WHERE id=%s", (resolution, actual, case_id))
    _event(cur, case_id, ('late_usage' if usage is not None else 'late_statement') if late else resolution, actor, evidence, actual)
    return True


def resolve_case(*, tenant_id, case_id, actor, usage=None, statement_cost=None, evidence_sha256=None, unrecoverable=False):
    if sum((usage is not None, statement_cost is not None, unrecoverable)) != 1:
        raise ReconciliationError('AMBIGUOUS_RESOLUTION')
    with connect() as conn, conn.cursor() as cur:
        return _resolve(cur, tenant_id, case_id, actor=actor, usage=usage,
            statement_cost=statement_cost, evidence=evidence_sha256, unrecoverable=unrecoverable)


def sweep(*, limit=100):
    # TRUSTED_INTERNAL_CROSS_TENANT_REAPER.
    #
    # Authority for this function is the host-local service/timer execution
    # boundary, NOT any tenant value stored in a row. It intentionally scans
    # work across tenants and is reached through no network API.
    #
    # The tenant_id selected below is therefore RESOURCE SCOPE BINDING: it
    # travels with the attempt this reaper has already selected for
    # maintenance, so _open's SQL stays constrained to exactly that
    # resource's own tenant. It is not authentication, and it is not
    # interchangeable with the observer path, where tenant_id arrives from an
    # already-authorized RuntimeTask context.
    #
    # The join to jobs only projects the owning tenant through the existing
    # attempt -> job ownership relation (job_id is NOT NULL REFERENCES jobs),
    # so it never removes a candidate. Eligibility predicates, ordering, LIMIT
    # and locking are unchanged: FOR UPDATE OF a keeps the lock target exactly
    # as it was (execution_attempts only).
    if type(limit) is not int or not 1<=limit<=1000:
        raise ReconciliationError('INVALID_SWEEP_LIMIT')
    counts = {'opened':0,'review_required':0,'resolved_unpriced':0}
    with connect() as conn, conn.cursor() as cur:
        cur.execute('''SELECT a.id, j.tenant_id FROM execution_attempts a JOIN jobs j ON j.id=a.job_id
            WHERE a.billing_mode='metered' AND a.status='running'
            AND a.accounting_due_at<=clock_timestamp() AND a.reserved_cost_usd IS NOT NULL
            ORDER BY a.accounting_due_at LIMIT %s FOR UPDATE OF a SKIP LOCKED''', (limit,))
        for attempt, owner_tenant in cur.fetchall():
            _open(cur, attempt, tenant_id=owner_tenant)
            counts['opened']+=1
        cur.execute('''SELECT id,tenant_id,status,resolve_by<=clock_timestamp() FROM metered_reconciliations
            WHERE status<>'resolved' AND (recover_until<=clock_timestamp() OR resolve_by<=clock_timestamp())
            ORDER BY resolve_by LIMIT %s FOR UPDATE SKIP LOCKED''', (limit,))
        for identifier, tenant, status, expired in cur.fetchall():
            if expired:
                _resolve(cur, tenant, identifier, actor='accounting-timer', unrecoverable=True)
                counts['resolved_unpriced']+=1
            elif status=='recoverable':
                cur.execute("UPDATE metered_reconciliations SET status='review_required' WHERE id=%s", (identifier,))
                _event(cur, identifier, 'review_required', 'accounting-timer')
                counts['review_required']+=1
    return counts


if __name__ == '__main__':
    import argparse
    import hashlib
    import json
    import os
    import sys
    from uuid import UUID
    parser=argparse.ArgumentParser()
    parser.add_argument('--resolve-stdin',action='store_true')
    args=parser.parse_args()
    if not args.resolve_stdin:
        print(json.dumps(sweep()))  # Counts only, never secrets or untrusted evidence.
    else:
        try:
            raw=sys.stdin.buffer.read(8193)
            if len(raw)>8192: raise ReconciliationError('INPUT_TOO_LARGE')
            data=json.loads(raw)
            allowed={'tenant_id','case_id','usage','statement_cost','evidence_sha256','unrecoverable'}
            if not isinstance(data,dict) or set(data)-allowed: raise ReconciliationError('INVALID_RESOLUTION_INPUT')
            actor='operator:'+hashlib.sha256(('uid:'+str(os.getuid())).encode()).hexdigest()
            changed=resolve_case(tenant_id=UUID(data['tenant_id']),case_id=UUID(data['case_id']),actor=actor,
                usage=tuple(data['usage']) if data.get('usage') is not None else None,
                statement_cost=Decimal(data['statement_cost']) if data.get('statement_cost') is not None else None,
                evidence_sha256=data.get('evidence_sha256'),unrecoverable=data.get('unrecoverable') is True)
            print(json.dumps({'resolved':True,'changed':changed}))
        except Exception:
            print('RESOLUTION_REJECTED',file=sys.stderr)
            sys.exit(1)
