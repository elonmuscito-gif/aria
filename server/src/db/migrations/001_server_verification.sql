-- Migration 001: Server-side event verification
-- Apply this against the agentrust database BEFORE deploying the updated server.
--
-- Safe to run on an existing database:
--   - New columns are nullable or have DEFAULT values, so existing rows are unaffected.
--   - Existing reputation snapshots get scope_violation_count = 0 by default.
--   - Existing anomaly rows (none currently) would get reason = 'scope_violation' by default.

-- Track the server-computed scope verdict for every event.
-- NULL means the event was recorded before this migration (legacy row, not yet verified).
ALTER TABLE events ADD COLUMN server_within_scope BOOLEAN;

-- Categorise anomaly records by detection reason so the table is useful for more than one signal.
ALTER TABLE anomalies ADD COLUMN reason TEXT NOT NULL DEFAULT 'scope_violation';

-- Track server-detected scope violations in the reputation snapshot.
ALTER TABLE reputation_snapshots ADD COLUMN scope_violation_count INT NOT NULL DEFAULT 0;

-- Partial index: only indexes rows where the server confirmed a violation.
-- Keeps the index small; used by the reputation computation query.
CREATE INDEX idx_events_scope_violation ON events (agent_id) WHERE server_within_scope = false;
