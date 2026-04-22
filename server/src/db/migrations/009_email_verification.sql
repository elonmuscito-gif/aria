-- Migration 009: Email verification + 2FA login codes
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS email_verified          BOOLEAN     DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS confirmation_token      TEXT,
  ADD COLUMN IF NOT EXISTS confirmation_token_expires TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS verification_code       TEXT,
  ADD COLUMN IF NOT EXISTS verification_code_expires  TIMESTAMPTZ;

-- Existing users who already have active API keys are considered verified
-- (they registered before email verification was required)
UPDATE users
  SET email_verified = TRUE
  WHERE email_verified = FALSE
    AND id IN (
      SELECT DISTINCT user_id
      FROM api_keys
      WHERE user_id IS NOT NULL AND revoked_at IS NULL
    );
