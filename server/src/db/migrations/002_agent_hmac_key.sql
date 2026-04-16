-- Migration 002: Add HMAC key for per-event signature verification
--
-- hmac_key stores the raw agent secret used to sign events via HMAC-SHA256.
-- NULL = agent registered before this migration; signatures cannot be verified for these agents.
--
-- TODO: encrypt at rest in Phase 2 (AES-256 with server master key)
ALTER TABLE agents ADD COLUMN hmac_key TEXT;
