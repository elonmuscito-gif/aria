-- Migration 003: Fast API key lookup via SHA-256 index
--
-- The current auth is O(n): fetches all active keys and bcrypt-compares each one.
-- Fix: store SHA-256(rawKey) for direct indexed lookup — one bcrypt compare instead of n.
--
-- NULL = key was inserted before this migration (legacy). Auth falls back to O(n) scan
-- for these rows only, and self-heals by writing key_sha256 on first successful auth.
ALTER TABLE api_keys ADD COLUMN key_sha256 TEXT;

-- Partial unique index: only covers non-NULL rows (legacy NULLs don't conflict).
CREATE UNIQUE INDEX idx_api_keys_sha256 ON api_keys (key_sha256) WHERE key_sha256 IS NOT NULL;
