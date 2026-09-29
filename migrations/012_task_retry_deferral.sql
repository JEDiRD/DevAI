ALTER TABLE tasks
    ADD COLUMN next_attempt_at TIMESTAMPTZ;

CREATE INDEX idx_tasks_pending_retry
    ON tasks(job_id, next_attempt_at, external_id)
    WHERE status = 'pending';
