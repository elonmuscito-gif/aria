CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE api_keys (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  key_hash    TEXT NOT NULL UNIQUE,
  key_sha256  TEXT UNIQUE, -- Usado por el Fast Path de auth.ts
  label       TEXT NOT NULL,
  owner_email TEXT NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  revoked_at  TIMESTAMPTZ
);

CREATE INDEX idx_api_keys_hash   ON api_keys (key_hash);
-- Índice ultra-rápido para la autenticación O(1)
CREATE INDEX idx_api_keys_sha256 ON api_keys (key_sha256) WHERE key_sha256 IS NOT NULL;

CREATE TABLE agents (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  did         TEXT NOT NULL UNIQUE,
  name        TEXT NOT NULL,
  scope       TEXT[] NOT NULL,
  api_key_id  UUID NOT NULL REFERENCES api_keys(id),
  public_key  TEXT NOT NULL,
  secret_hash TEXT NOT NULL,
  hmac_key    TEXT, -- Guarda la clave cruda (V1) o el partialAKey derivado (V2 DTS)
  meta        JSONB,
  signing_version INT NOT NULL DEFAULT 1,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen   TIMESTAMPTZ
);

CREATE INDEX idx_agents_did        ON agents (did);
CREATE INDEX idx_agents_api_key_id ON agents (api_key_id);

CREATE TABLE events (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id          TEXT NOT NULL UNIQUE,
  agent_id          UUID NOT NULL REFERENCES agents(id),
  action            TEXT NOT NULL,
  outcome           TEXT NOT NULL CHECK (outcome IN ('success', 'error', 'anomaly')),
  within_scope      BOOLEAN NOT NULL,
  server_within_scope BOOLEAN NOT NULL DEFAULT FALSE, -- <-- LA COLUMNA FALTANTE
  duration_ms       INT NOT NULL,
  signature         TEXT NOT NULL,
  signature_valid   BOOLEAN NOT NULL DEFAULT TRUE,
  error             TEXT,
  meta              JSONB,
  recorded_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  client_ts         TIMESTAMPTZ NOT NULL
);

-- Inmutabilidad legal: Ni UPDATE ni DELETE permitidos.
CREATE RULE no_update_events AS ON UPDATE TO events DO INSTEAD NOTHING;
CREATE RULE no_delete_events AS ON DELETE TO events DO INSTEAD NOTHING;

CREATE INDEX idx_events_agent_id    ON events (agent_id);
CREATE INDEX idx_events_recorded_at ON events (recorded_at DESC);
CREATE INDEX idx_events_outcome     ON events (outcome);
CREATE INDEX idx_events_action      ON events (action);

-- 🚀 COVERING INDEX: Hace que el cálculo de reputación en reputation.ts sea instantáneo.
-- Al incluir el agent_id y el outcome en el mismo índice, Postgres no necesita leer la tabla real.
CREATE INDEX idx_events_agent_outcome ON events (agent_id, outcome);

CREATE TABLE anomalies (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id     UUID NOT NULL REFERENCES events(id),
  agent_id     UUID NOT NULL REFERENCES agents(id),
  action       TEXT NOT NULL,
  detected_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  acknowledged BOOLEAN NOT NULL DEFAULT FALSE
);

-- Índice arreglado
CREATE INDEX idx_anomalies_agent_id ON anomalies (agent_id);