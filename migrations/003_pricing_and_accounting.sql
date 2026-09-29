CREATE TABLE IF NOT EXISTS model_pricing (
    pricing_key TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),

    input_per_million_usd NUMERIC(18,8) NOT NULL
        CHECK (input_per_million_usd >= 0),

    output_per_million_usd NUMERIC(18,8) NOT NULL
        CHECK (output_per_million_usd >= 0),

    active BOOLEAN NOT NULL DEFAULT FALSE,
    effective_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (pricing_key, version)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_model_pricing_one_active
    ON model_pricing(pricing_key)
    WHERE active;

ALTER TABLE execution_attempts
    ADD COLUMN IF NOT EXISTS pricing_key TEXT,
    ADD COLUMN IF NOT EXISTS pricing_version INTEGER,
    ADD COLUMN IF NOT EXISTS reserved_cost_usd NUMERIC(18,8)
        CHECK (
            reserved_cost_usd IS NULL
            OR reserved_cost_usd >= 0
        );
