CREATE TABLE IF NOT EXISTS job_budgets (
    job_id UUID PRIMARY KEY
        REFERENCES jobs(id) ON DELETE CASCADE,

    limit_usd NUMERIC(18,8) NOT NULL
        CHECK (limit_usd > 0),

    reserved_usd NUMERIC(18,8) NOT NULL DEFAULT 0
        CHECK (reserved_usd >= 0),

    spent_usd NUMERIC(18,8) NOT NULL DEFAULT 0
        CHECK (spent_usd >= 0),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_job_budgets_updated
    ON job_budgets(updated_at);
