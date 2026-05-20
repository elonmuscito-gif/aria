-- Add plan to users table
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS plan TEXT
    NOT NULL DEFAULT 'free'
    CHECK (plan IN ('free', 'professional', 'enterprise')),
  ADD COLUMN IF NOT EXISTS plan_started_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS plan_expires_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS stripe_customer_id TEXT,
  ADD COLUMN IF NOT EXISTS stripe_subscription_id TEXT;

-- Event usage tracking per month
CREATE TABLE IF NOT EXISTS usage_stats (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id)
    ON DELETE CASCADE,
  month TEXT NOT NULL,
  -- Format: '2026-05' (YYYY-MM)
  event_count INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(user_id, month)
);

CREATE INDEX IF NOT EXISTS idx_usage_stats_user_month
  ON usage_stats(user_id, month);
