CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,

    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'suspended', 'disabled')),

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO tenants (
    id,
    slug,
    name
)
VALUES (
    '00000000-0000-4000-8000-000000000001',
    'dev-ai-lab',
    'Dev AI Lab'
)
ON CONFLICT (id) DO NOTHING;


ALTER TABLE jobs
    ADD COLUMN IF NOT EXISTS tenant_id UUID;

UPDATE jobs
SET tenant_id = '00000000-0000-4000-8000-000000000001'
WHERE tenant_id IS NULL;

ALTER TABLE jobs
    ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE jobs
    ALTER COLUMN tenant_id
    SET DEFAULT '00000000-0000-4000-8000-000000000001';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'jobs_tenant_fk'
    ) THEN
        ALTER TABLE jobs
            ADD CONSTRAINT jobs_tenant_fk
            FOREIGN KEY (tenant_id)
            REFERENCES tenants(id)
            ON DELETE RESTRICT;
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS idx_jobs_tenant
    ON jobs(tenant_id);


ALTER TABLE provider_routes
    ADD COLUMN IF NOT EXISTS tenant_id UUID;

UPDATE provider_routes
SET tenant_id = '00000000-0000-4000-8000-000000000001'
WHERE tenant_id IS NULL;

ALTER TABLE provider_routes
    ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE provider_routes
    ALTER COLUMN tenant_id
    SET DEFAULT '00000000-0000-4000-8000-000000000001';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'provider_routes_tenant_fk'
    ) THEN
        ALTER TABLE provider_routes
            ADD CONSTRAINT provider_routes_tenant_fk
            FOREIGN KEY (tenant_id)
            REFERENCES tenants(id)
            ON DELETE RESTRICT;
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS idx_provider_routes_tenant
    ON provider_routes(tenant_id);
