-- Witness sources registered by the owner
CREATE TABLE IF NOT EXISTS witness_sources (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id)
    ON DELETE CASCADE,
  agent_id UUID REFERENCES agents(id)
    ON DELETE CASCADE,
  name TEXT NOT NULL,
  source_type TEXT NOT NULL,
  -- Types: 'webhook', 'manual', 'api_counter'
  action_pattern TEXT NOT NULL,
  -- e.g. 'send:email', 'process:payment', 'send:*'
  active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_witness_sources_user_id
  ON witness_sources(user_id);
CREATE INDEX IF NOT EXISTS idx_witness_sources_agent_id
  ON witness_sources(agent_id);

-- Witness checks — one per verification window
CREATE TABLE IF NOT EXISTS witness_checks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  witness_source_id UUID NOT NULL
    REFERENCES witness_sources(id) ON DELETE CASCADE,
  agent_id UUID NOT NULL
    REFERENCES agents(id) ON DELETE CASCADE,
  action_pattern TEXT NOT NULL,
  window_start TIMESTAMPTZ NOT NULL,
  window_end TIMESTAMPTZ NOT NULL,
  agent_reported INTEGER NOT NULL DEFAULT 0,
  -- What the agent reported
  witness_confirmed INTEGER,
  -- What the external source confirmed (null = unverified)
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN (
      'pending',     -- waiting for external confirmation
      'verified',    -- counts match
      'discrepancy', -- counts don't match
      'unverified'   -- no external data received
    )),
  discrepancy_delta INTEGER,
  -- agent_reported - witness_confirmed
  notes TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  resolved_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_witness_checks_agent_id
  ON witness_checks(agent_id);
CREATE INDEX IF NOT EXISTS idx_witness_checks_status
  ON witness_checks(status);
