CREATE TABLE worker_tokens (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    worker_node_id UUID NOT NULL,
    token_hash BYTEA NOT NULL UNIQUE
        CHECK (octet_length(token_hash) = 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,

    CONSTRAINT worker_tokens_worker_fk
        FOREIGN KEY (tenant_id, worker_node_id)
        REFERENCES worker_nodes (tenant_id, id)
        ON DELETE RESTRICT
);

CREATE INDEX idx_worker_tokens_worker
    ON worker_tokens (tenant_id, worker_node_id);
