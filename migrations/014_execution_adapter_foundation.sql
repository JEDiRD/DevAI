-- Execution/accounting foundation only. Earlier migrations remain immutable.
ALTER TABLE provider_routes ADD COLUMN billing_mode TEXT NOT NULL DEFAULT 'metered'
    CHECK (billing_mode IN ('free','metered','subscription','local'));
UPDATE provider_routes SET billing_mode = CASE route_key
    WHEN 'openrouter/free' THEN 'free'
    WHEN 'codex/frontier' THEN 'subscription'
    ELSE 'metered' END;
UPDATE provider_routes SET billing_mode='local' WHERE provider='synthetic';
-- Synthetic fixtures must never become a production model fallback.
UPDATE provider_routes SET enabled=FALSE WHERE provider='synthetic';
ALTER TABLE provider_connections ADD COLUMN adapter_key TEXT;
UPDATE provider_connections c SET transport='local_cli', adapter_key='codex_cli'
WHERE EXISTS (SELECT 1 FROM provider_routes r WHERE r.tenant_id=c.tenant_id
    AND r.connection_id=c.id AND r.route_key='codex/frontier');
UPDATE provider_connections c SET adapter_key='synthetic_test'
WHERE c.transport='local_cli' AND EXISTS (SELECT 1 FROM provider_routes r
    WHERE r.tenant_id=c.tenant_id AND r.connection_id=c.id AND r.provider='synthetic');
ALTER TABLE execution_attempts ADD COLUMN billing_mode TEXT
    CHECK (billing_mode IN ('free','metered','subscription','local'));
ALTER TABLE worker_dispatches
    ADD COLUMN connection_id UUID,
    ADD COLUMN adapter_key TEXT,
    ADD COLUMN execution_timeout_seconds INTEGER,
    ADD COLUMN spec_version INTEGER,
    ADD COLUMN adapter_version TEXT,
    ADD COLUMN deadline_at TIMESTAMPTZ,
    ADD COLUMN idempotency_key UUID;
-- Existing evidence is archived as v0; never execute old mutable specifications.
UPDATE worker_dispatches d SET connection_id=r.connection_id,
    adapter_key=COALESCE(c.adapter_key,'legacy_unconfigured'),
    execution_timeout_seconds=60, spec_version=0, adapter_version='legacy',
    deadline_at=d.created_at+interval '60 seconds', idempotency_key=d.id
FROM provider_routes r JOIN provider_connections c
    ON c.tenant_id=r.tenant_id AND c.id=r.connection_id
WHERE r.tenant_id=d.tenant_id AND r.route_key=d.route_key;
UPDATE worker_dispatches SET status='expired', completed_at=clock_timestamp(),
    lease_expires_at=NULL, error='LEGACY_SPEC_EXPIRED'
WHERE status IN ('pending','claimed');
ALTER TABLE worker_dispatches
    ALTER COLUMN connection_id SET NOT NULL,
    ALTER COLUMN adapter_key SET NOT NULL,
    ALTER COLUMN execution_timeout_seconds SET NOT NULL,
    ALTER COLUMN spec_version SET NOT NULL,
    ALTER COLUMN adapter_version SET NOT NULL,
    ALTER COLUMN deadline_at SET NOT NULL,
    ALTER COLUMN idempotency_key SET NOT NULL,
    ADD CONSTRAINT dispatch_connection_fk FOREIGN KEY (tenant_id,connection_id)
        REFERENCES provider_connections(tenant_id,id) ON DELETE RESTRICT,
    ADD CONSTRAINT dispatch_timeout_check CHECK (execution_timeout_seconds BETWEEN 1 AND 60),
    ADD CONSTRAINT dispatch_spec_version_check CHECK (spec_version>=0),
    ADD CONSTRAINT dispatch_prompt_size_check CHECK (octet_length(prompt)<=65536),
    ADD CONSTRAINT dispatch_output_size_check CHECK (result_content IS NULL OR octet_length(result_content)<=65536),
    ADD CONSTRAINT dispatch_idempotency_unique UNIQUE(tenant_id,idempotency_key);
CREATE INDEX idx_dispatch_deadline ON worker_dispatches(deadline_at)
    WHERE status IN ('pending','claimed');
CREATE FUNCTION guard_dispatch_spec() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.id,NEW.tenant_id,NEW.worker_node_id,NEW.route_key,NEW.connection_id,
           NEW.adapter_key,NEW.gateway_model,NEW.prompt,NEW.execution_timeout_seconds,
           NEW.spec_version,NEW.adapter_version,NEW.deadline_at,NEW.idempotency_key,NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id,OLD.tenant_id,OLD.worker_node_id,OLD.route_key,OLD.connection_id,
           OLD.adapter_key,OLD.gateway_model,OLD.prompt,OLD.execution_timeout_seconds,
           OLD.spec_version,OLD.adapter_version,OLD.deadline_at,OLD.idempotency_key,OLD.created_at) THEN
        RAISE EXCEPTION 'IMMUTABLE_EXECUTION_SPEC';
    END IF;
    IF OLD.status IN ('succeeded','failed','cancelled','expired') AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'IMMUTABLE_TERMINAL_DISPATCH';
    END IF;
    IF NEW.status='claimed' AND (
        OLD.status NOT IN ('pending','claimed') OR
        (OLD.status='pending' AND (OLD.claim_version<>0 OR NEW.claim_version<>1)) OR
        (OLD.status='claimed' AND NEW.claim_version<>OLD.claim_version)) THEN
        RAISE EXCEPTION 'DISPATCH_ALREADY_CLAIMED';
    END IF;
    IF OLD.status IN ('pending','claimed') AND NEW.status IN ('claimed','succeeded')
       AND NEW.deadline_at<=clock_timestamp() THEN
        RAISE EXCEPTION 'DISPATCH_DEADLINE_REACHED';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER worker_dispatch_spec_immutable BEFORE UPDATE ON worker_dispatches
    FOR EACH ROW EXECUTE FUNCTION guard_dispatch_spec();
