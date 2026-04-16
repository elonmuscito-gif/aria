-- ARIA Database Schema + Migrations Combined
-- Run this entire block in Railway Query Editor

-- ============================================
-- SCHEMA (base tables)
-- ============================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- API Keys table
CREATE TABLE IF NOT EXISTS api_keys (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  key_hash    TEXT NOT NULL UNIQUE,
  key_sha256  TEXT UNIQUE,
  label       TEXT NOT NULL,
  owner_email TEXT NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  revoked_at  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_api_keys_hash   ON api_keys (key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_sha256 ON api_keys (key_sha256) WHERE key_sha256 IS NOT NULL;

-- Agents table
CREATE TABLE IF NOT EXISTS agents (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  did             TEXT NOT NULL UNIQUE,
  name            TEXT NOT NULL,
  scope           TEXT[] NOT NULL,
  api_key_id      UUID NOT NULL REFERENCES api_keys(id),
  public_key      TEXT NOT NULL,
  secret_hash     TEXT NOT NULL,
  hmac_key       TEXT,
  meta           JSONB,
  signing_version INT NOT NULL DEFAULT 1,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen       TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_agents_did        ON agents (did);
CREATE INDEX IF NOT EXISTS idx_agents_api_key_id ON agents (api_key_id);

-- Events table
CREATE TABLE IF NOT EXISTS events (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id          TEXT NOT NULL UNIQUE,
  agent_id          UUID NOT NULL REFERENCES agents(id),
  action            TEXT NOT NULL,
  outcome           TEXT NOT NULL CHECK (outcome IN ('success', 'error', 'anomaly')),
  within_scope      BOOLEAN NOT NULL,
  server_within_scope BOOLEAN NOT NULL DEFAULT FALSE,
  duration_ms       INT NOT NULL,
  signature         TEXT NOT NULL,
  signature_valid   BOOLEAN NOT NULL DEFAULT TRUE,
  error             TEXT,
  meta              JSONB,
  recorded_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  client_ts         TIMESTAMPTZ NOT NULL
);

-- Event immutability rules
DROP RULE IF EXISTS no_update_events AS ON UPDATE TO events;
DROP RULE IF EXISTS no_delete_events AS ON DELETE TO events;
CREATE RULE no_update_events AS ON UPDATE TO events DO INSTEAD NOTHING;
CREATE RULE no_delete_events AS ON DELETE TO events DO INSTEAD NOTHING;

CREATE INDEX IF NOT EXISTS idx_events_agent_id    ON events (agent_id);
CREATE INDEX IF NOT EXISTS idx_events_recorded_at ON events (recorded_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_outcome     ON events (outcome);
CREATE INDEX IF NOT EXISTS idx_events_action      ON events (action);
CREATE INDEX IF NOT EXISTS idx_events_agent_outcome ON events (agent_id, outcome);

-- Anomalies table
CREATE TABLE IF NOT EXISTS anomalies (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id     UUID NOT NULL REFERENCES events(id),
  agent_id     UUID NOT NULL REFERENCES agents(id),
  action       TEXT NOT NULL,
  detected_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  acknowledged BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_anomalies_agent_id ON anomalies (agent_id);

-- ============================================
-- MIGRATION 001: Server-side event verification
-- ============================================
ALTER TABLE anomalies ADD COLUMN IF NOT EXISTS reason TEXT NOT NULL DEFAULT 'scope_violation';

-- Create reputation_snapshots table if not exists
CREATE TABLE IF NOT EXISTS reputation_snapshots (
  id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id              UUID NOT NULL REFERENCES agents(id),
  total_events          INT NOT NULL DEFAULT 0,
  success_count        INT NOT NULL DEFAULT 0,
  error_count          INT NOT NULL DEFAULT 0,
  anomaly_count        INT NOT NULL DEFAULT 0,
  scope_violation_count INT NOT NULL DEFAULT 0,
  hardware_conflict_count INT NOT NULL DEFAULT 0,
  success_rate         TEXT,
  top_actions         TEXT,
  last_computed_at     TIMESTAMPTZ,
  UNIQUE(agent_id)
);

CREATE INDEX IF NOT EXISTS idx_events_scope_violation ON events (agent_id) WHERE server_within_scope = false;

-- ============================================
-- MIGRATION 002: Add HMAC key for per-event signature verification
-- ============================================
ALTER TABLE agents ADD COLUMN IF NOT EXISTS hmac_key TEXT;

-- ============================================
-- MIGRATION 003: Fast API key lookup via SHA-256 index
-- ============================================
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS key_sha256 TEXT;

-- ============================================
-- MIGRATION 004: Hardware conflict tracking in reputation snapshots
-- ============================================
ALTER TABLE reputation_snapshots ADD COLUMN IF NOT EXISTS hardware_conflict_count INT NOT NULL DEFAULT 0;

-- ============================================
-- MIGRATION 005: DTS signing version per agent
-- ============================================
ALTER TABLE agents ADD COLUMN IF NOT EXISTS signing_version INT NOT NULL DEFAULT 1;

-- ============================================
-- MIGRATION 006: Persist signature verification result on every event
-- ============================================
ALTER TABLE events ADD COLUMN IF NOT EXISTS signature_valid BOOLEAN NOT NULL DEFAULT true;

-- ============================================
-- Verify tables created
-- ============================================
SELECT 'api_keys' as table_name, count(*) as row_count FROM api_keys
UNION ALL
SELECT 'agents', count(*) FROM agents
UNION ALL
SELECT 'events', count(*) FROM events
UNION ALL
SELECT 'anomalies', count(*) FROM anomalies
UNION ALL
SELECT 'reputation_snapshots', count(*) FROM reputation_snapshots;