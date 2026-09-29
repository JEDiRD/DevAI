ALTER TABLE tasks
    ADD COLUMN IF NOT EXISTS requires_approval BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS approved_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS approved_by TEXT;

ALTER TABLE tasks
    ADD CONSTRAINT task_approval_consistency
    CHECK (
        requires_approval = FALSE
        OR approved_at IS NULL
        OR approved_by IS NOT NULL
    );
