CREATE TABLE IF NOT EXISTS provider_routes (
    route_key TEXT PRIMARY KEY,

    provider TEXT NOT NULL,
    gateway_model TEXT NOT NULL,

    capability TEXT NOT NULL
        CHECK (capability IN ('basic', 'strong', 'frontier')),

    cost_class TEXT NOT NULL
        CHECK (cost_class IN ('free', 'standard', 'premium')),

    priority INTEGER NOT NULL DEFAULT 100,

    pricing_key TEXT NOT NULL,

    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    failure_threshold INTEGER NOT NULL DEFAULT 2
        CHECK (failure_threshold > 0),

    cooldown_seconds INTEGER NOT NULL DEFAULT 300
        CHECK (cooldown_seconds > 0),

    consecutive_failures INTEGER NOT NULL DEFAULT 0
        CHECK (consecutive_failures >= 0),

    cooldown_until TIMESTAMPTZ,

    last_error TEXT,
    last_failure_at TIMESTAMPTZ,
    last_success_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_provider_routes_enabled
    ON provider_routes(enabled);

CREATE INDEX IF NOT EXISTS idx_provider_routes_cooldown
    ON provider_routes(cooldown_until);
