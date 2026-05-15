CREATE TABLE IF NOT EXISTS zero_proofs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id UUID NOT NULL REFERENCES agents(id)
    ON DELETE CASCADE,
  proof_type TEXT NOT NULL
    CHECK (proof_type IN (
      'innocence',
      'consistency',
      'limits'
    )),
  claim TEXT NOT NULL,
  merkle_root TEXT NOT NULL,
  proof_data JSONB NOT NULL,
  window_start TIMESTAMPTZ NOT NULL,
  window_end TIMESTAMPTZ NOT NULL,
  verified BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_zero_proofs_agent_id
  ON zero_proofs(agent_id);
CREATE INDEX IF NOT EXISTS idx_zero_proofs_type
  ON zero_proofs(proof_type);
CREATE INDEX IF NOT EXISTS idx_zero_proofs_created
  ON zero_proofs(created_at DESC);
