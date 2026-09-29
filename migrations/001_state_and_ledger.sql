CREATE TABLE IF NOT EXISTS jobs (
    id UUID PRIMARY KEY,
    objective TEXT NOT NULL,
    status TEXT NOT NULL
        CHECK (status IN (
            'pending',
            'planning',
            'running',
            'waiting_approval',
            'completed',
            'failed',
            'cancelled'
        )),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS tasks (
    id UUID PRIMARY KEY,
    job_id UUID NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,

    external_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,

    capability TEXT NOT NULL
        CHECK (capability IN ('basic', 'strong', 'frontier')),

    risk TEXT NOT NULL
        CHECK (risk IN ('low', 'medium', 'high', 'critical')),

    needs_review BOOLEAN NOT NULL DEFAULT FALSE,

    status TEXT NOT NULL
        CHECK (status IN (
            'pending',
            'running',
            'waiting_approval',
            'completed',
            'failed',
            'cancelled'
        )),

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE(job_id, external_id)
);

CREATE TABLE IF NOT EXISTS task_dependencies (
    task_id UUID NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    depends_on_task_id UUID NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,

    PRIMARY KEY(task_id, depends_on_task_id),

    CHECK (task_id <> depends_on_task_id)
);

CREATE TABLE IF NOT EXISTS execution_attempts (
    id UUID PRIMARY KEY,
    job_id UUID NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    task_id UUID NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,

    attempt_number INTEGER NOT NULL CHECK (attempt_number > 0),

    route_key TEXT NOT NULL,
    provider TEXT NOT NULL,
    gateway_model TEXT NOT NULL,

    status TEXT NOT NULL
        CHECK (status IN (
            'reserved',
            'running',
            'succeeded',
            'failed',
            'cancelled'
        )),

    request_id TEXT,
    provider_request_id TEXT,

    prompt_tokens BIGINT CHECK (prompt_tokens IS NULL OR prompt_tokens >= 0),
    completion_tokens BIGINT CHECK (completion_tokens IS NULL OR completion_tokens >= 0),

    estimated_cost_usd NUMERIC(18,8)
        CHECK (estimated_cost_usd IS NULL OR estimated_cost_usd >= 0),

    reconciled_cost_usd NUMERIC(18,8)
        CHECK (reconciled_cost_usd IS NULL OR reconciled_cost_usd >= 0),

    error_code TEXT,
    error_message TEXT,

    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE(task_id, attempt_number),
    UNIQUE(request_id)
);

CREATE INDEX IF NOT EXISTS idx_tasks_job
    ON tasks(job_id);

CREATE INDEX IF NOT EXISTS idx_tasks_status
    ON tasks(status);

CREATE INDEX IF NOT EXISTS idx_attempts_job
    ON execution_attempts(job_id);

CREATE INDEX IF NOT EXISTS idx_attempts_task
    ON execution_attempts(task_id);

CREATE INDEX IF NOT EXISTS idx_attempts_status
    ON execution_attempts(status);
