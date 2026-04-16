-- Migration 005: DTS signing version per agent
--
-- signing_version = 1 (default): classic HMAC-SHA256 with raw secret in hmac_key
-- signing_version = 2: Distributed Trust Shell — SSS-split key, XOR-HMAC signatures
--                      hmac_key stores shareA (Shamir share, not the full secret)
ALTER TABLE agents ADD COLUMN signing_version INT NOT NULL DEFAULT 1;
