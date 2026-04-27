ALTER TABLE agents
  ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES users(id);

CREATE INDEX IF NOT EXISTS idx_agents_user_id
  ON agents(user_id);

-- Link existing agents to users via api_keys table:
UPDATE agents a
SET user_id = ak.user_id
FROM api_keys ak
WHERE a.api_key_id = ak.id
AND ak.user_id IS NOT NULL;
