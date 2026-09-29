CREATE TABLE worker_dispatches (
    id UUID PRIMARY KEY,

    tenant_id UUID NOT NULL,
    worker_node_id UUID NOT NULL,

    route_key TEXT NOT NULL,
    gateway_model TEXT NOT NULL,

    prompt TEXT NOT NULL,

    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (
            status IN (
                'pending',
                'claimed',
                'succeeded',
                'failed',
                'cancelled',
                'expired'
            )
        ),

    claim_version BIGINT NOT NULL DEFAULT 0,
    claimed_at TIMESTAMPTZ,
    lease_expires_at TIMESTAMPTZ,

    result_content TEXT,
    prompt_tokens INTEGER,
    completion_tokens INTEGER,
    provider_request_id TEXT,

    error TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,

    CONSTRAINT worker_dispatch_worker_fk
        FOREIGN KEY (
            tenant_id,
            worker_node_id
        )
        REFERENCES worker_nodes (
            tenant_id,
            id
        )
        ON DELETE RESTRICT,

    CONSTRAINT worker_dispatch_route_fk
        FOREIGN KEY (
            tenant_id,
            route_key
        )
        REFERENCES provider_routes (
            tenant_id,
            route_key
        )
        ON DELETE RESTRICT
);

CREATE INDEX idx_worker_dispatch_pending
    ON worker_dispatches (
        tenant_id,
        worker_node_id,
        status,
        created_at
    );

CREATE INDEX idx_worker_dispatch_lease
    ON worker_dispatches (
        status,
        lease_expires_at
    );
