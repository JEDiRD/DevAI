CREATE TABLE provider_connections (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL
        REFERENCES tenants(id)
        ON DELETE RESTRICT,

    name TEXT NOT NULL,

    transport TEXT NOT NULL
        CHECK (
            transport IN (
                'litellm',
                'remote_http',
                'openai_compatible',
                'local_http',
                'local_cli'
            )
        ),

    auth_type TEXT NOT NULL
        CHECK (
            auth_type IN (
                'api_key',
                'oauth',
                'service_account',
                'subscription_session',
                'local_none'
            )
        ),

    -- Reference only. Never store the actual secret here.
    credential_ref TEXT,

    endpoint TEXT,

    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    config JSONB NOT NULL DEFAULT '{}'::jsonb,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (tenant_id, name),
    UNIQUE (tenant_id, id)
);


ALTER TABLE provider_routes
    ADD COLUMN connection_id UUID;


-- Current private installation:
-- OpenRouter + Gemini currently travel through the same local LiteLLM.
INSERT INTO provider_connections (
    id,
    tenant_id,
    name,
    transport,
    auth_type,
    credential_ref,
    endpoint
)
VALUES (
    '10000000-0000-4000-8000-000000000001',
    '00000000-0000-4000-8000-000000000001',
    'Local LiteLLM Gateway',
    'litellm',
    'api_key',
    'env:DEVAI_LITELLM_MASTER_KEY',
    'http://127.0.0.1:4000'
)
ON CONFLICT (id) DO NOTHING;


-- Codex will eventually use the authenticated local CLI/session,
-- independently of LiteLLM.
INSERT INTO provider_connections (
    id,
    tenant_id,
    name,
    transport,
    auth_type,
    credential_ref
)
VALUES (
    '10000000-0000-4000-8000-000000000002',
    '00000000-0000-4000-8000-000000000001',
    'Local Codex CLI',
    'local_cli',
    'subscription_session',
    'session:codex'
)
ON CONFLICT (id) DO NOTHING;


UPDATE provider_routes
SET connection_id =
    '10000000-0000-4000-8000-000000000001'
WHERE tenant_id =
      '00000000-0000-4000-8000-000000000001'
  AND route_key IN (
      'openrouter/free',
      'gemini/standard'
  );


UPDATE provider_routes
SET connection_id =
    '10000000-0000-4000-8000-000000000002'
WHERE tenant_id =
      '00000000-0000-4000-8000-000000000001'
  AND route_key = 'codex/frontier';


ALTER TABLE provider_routes
    ALTER COLUMN connection_id SET NOT NULL;


ALTER TABLE provider_routes
    ADD CONSTRAINT provider_routes_connection_fk
    FOREIGN KEY (
        tenant_id,
        connection_id
    )
    REFERENCES provider_connections (
        tenant_id,
        id
    )
    ON DELETE RESTRICT;


CREATE INDEX idx_provider_connections_tenant
    ON provider_connections(
        tenant_id,
        enabled
    );

CREATE INDEX idx_provider_routes_connection
    ON provider_routes(
        tenant_id,
        connection_id
    );
