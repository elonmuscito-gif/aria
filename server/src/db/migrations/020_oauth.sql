ALTER TABLE users
  ADD COLUMN IF NOT EXISTS oauth_provider TEXT,
  ADD COLUMN IF NOT EXISTS oauth_id TEXT,
  ADD COLUMN IF NOT EXISTS avatar_url TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_oauth_provider_id
  ON users(oauth_provider, oauth_id)
  WHERE oauth_provider IS NOT NULL;
