-- Stop silently assigning new records to the bootstrap tenant.
ALTER TABLE jobs
    ALTER COLUMN tenant_id DROP DEFAULT;

ALTER TABLE provider_routes
    ALTER COLUMN tenant_id DROP DEFAULT;

-- A route key is unique inside a tenant, not globally.
ALTER TABLE provider_routes
    DROP CONSTRAINT IF EXISTS provider_routes_pkey;

ALTER TABLE provider_routes
    ADD CONSTRAINT provider_routes_pkey
    PRIMARY KEY (tenant_id, route_key);

CREATE INDEX IF NOT EXISTS idx_provider_routes_tenant_enabled_priority
    ON provider_routes(tenant_id, enabled, priority);

CREATE INDEX IF NOT EXISTS idx_provider_routes_tenant_cooldown
    ON provider_routes(tenant_id, cooldown_until);
