ALTER TABLE tasks
    ADD COLUMN IF NOT EXISTS lease_owner UUID,
    ADD COLUMN IF NOT EXISTS lease_version BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS checkpoint_seq BIGINT NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS task_checkpoints (
    id UUID PRIMARY KEY,
    task_id UUID NOT NULL
        REFERENCES tasks(id) ON DELETE CASCADE,

    sequence BIGINT NOT NULL CHECK (sequence > 0),
    lease_version BIGINT NOT NULL CHECK (lease_version > 0),

    payload JSONB NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE(task_id, sequence)
);

CREATE INDEX IF NOT EXISTS idx_task_checkpoints_latest
    ON task_checkpoints(task_id, sequence DESC);

CREATE INDEX IF NOT EXISTS idx_tasks_lease_expiry
    ON tasks(lease_expires_at);
