-- Migration 006: Persist signature verification result on every event
--
-- Historical rows default to true so the schema change is additive.
-- New ingestions compute and store the actual verification result.
ALTER TABLE events
  ADD COLUMN IF NOT EXISTS signature_valid BOOLEAN NOT NULL DEFAULT true;
