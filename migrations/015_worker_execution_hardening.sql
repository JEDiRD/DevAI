-- Earlier applied migrations remain immutable.
ALTER TABLE job_budgets
    ADD COLUMN recovery_exposure_usd NUMERIC(18,8) NOT NULL DEFAULT 0 CHECK (recovery_exposure_usd>=0),
    ADD COLUMN unpriced_exposure_usd NUMERIC(18,8) NOT NULL DEFAULT 0 CHECK (unpriced_exposure_usd>=0);
ALTER TABLE execution_attempts
    ADD COLUMN input_price_snapshot NUMERIC(18,8) CHECK (input_price_snapshot>=0),
    ADD COLUMN output_price_snapshot NUMERIC(18,8) CHECK (output_price_snapshot>=0),
    ADD COLUMN accounting_due_at TIMESTAMPTZ;
CREATE TABLE worker_dispatch_terminations (
    dispatch_id UUID PRIMARY KEY REFERENCES worker_dispatches(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    worker_node_id UUID NOT NULL,
    claim_version BIGINT NOT NULL CHECK (claim_version>=1),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (tenant_id,worker_node_id) REFERENCES worker_nodes(tenant_id,id)
);
CREATE TABLE metered_reconciliations (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    job_id UUID NOT NULL REFERENCES jobs(id),
    attempt_id UUID NOT NULL UNIQUE REFERENCES execution_attempts(id),
    status TEXT NOT NULL CHECK (status IN ('recoverable','review_required','resolved')),
    exposure_usd NUMERIC(18,8) NOT NULL CHECK (exposure_usd>=0),
    result_success BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    recover_until TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()+interval '15 minutes',
    resolve_by TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()+interval '24 hours',
    resolution TEXT CHECK (resolution IN ('usage','provider_statement','unrecoverable_exposure')),
    actual_cost_usd NUMERIC(18,8) CHECK (actual_cost_usd>=0),
    resolved_at TIMESTAMPTZ,
    CHECK ((status='resolved')=(resolved_at IS NOT NULL)),
    CHECK ((status='resolved')=(resolution IS NOT NULL))
);
CREATE INDEX metered_reconciliation_due ON metered_reconciliations(resolve_by)
    WHERE status<>'resolved';
CREATE TABLE metered_reconciliation_events (
    id BIGSERIAL PRIMARY KEY,
    case_id UUID NOT NULL REFERENCES metered_reconciliations(id),
    at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    action TEXT NOT NULL CHECK (action IN ('opened','review_required','usage','provider_statement','unrecoverable_exposure','late_usage','late_statement')),
    actor TEXT NOT NULL CHECK (actor ~ '^[A-Za-z0-9_.:-]{1,80}$'),
    evidence_sha256 TEXT CHECK (evidence_sha256 ~ '^[a-f0-9]{64}$'),
    actual_cost_usd NUMERIC(18,8) CHECK (actual_cost_usd>=0)
);
CREATE FUNCTION reject_metered_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'METERED_AUDIT_APPEND_ONLY';
END;
$$;
CREATE TRIGGER metered_audit_append_only BEFORE UPDATE OR DELETE
    ON metered_reconciliation_events FOR EACH ROW EXECUTE FUNCTION reject_metered_audit_mutation();
