CREATE TABLE worker_nodes (
    id UUID PRIMARY KEY,

    tenant_id UUID NOT NULL
        REFERENCES tenants(id)
        ON DELETE RESTRICT,

    name TEXT NOT NULL,

    status TEXT NOT NULL DEFAULT 'offline'
        CHECK (
            status IN (
                'offline',
                'online',
                'draining',
                'disabled'
            )
        ),

    platform TEXT,

    architecture TEXT,

    -- Arbitrary declared capabilities:
    -- ["codex_cli", "ollama", "docker", "gpu", ...]
    capabilities JSONB NOT NULL DEFAULT '[]'::jsonb,

    last_seen_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (tenant_id, name),
    UNIQUE (tenant_id, id)
);


ALTER TABLE provider_connections
    ADD COLUMN worker_node_id UUID;


ALTER TABLE provider_connections
    ADD CONSTRAINT provider_connections_worker_node_fk
    FOREIGN KEY (
        tenant_id,
        worker_node_id
    )
    REFERENCES worker_nodes (
        tenant_id,
        id
    )
    ON DELETE RESTRICT;


CREATE INDEX idx_worker_nodes_tenant_status
    ON worker_nodes (
        tenant_id,
        status
    );
