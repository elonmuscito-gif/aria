-- Migration 004: Hardware conflict tracking in reputation snapshots
--
-- Hardware fingerprint binding is verified at event ingestion time and stored
-- as meta flags (hardware_conflict / hardware_fp_missing) in the events table.
-- This counter aggregates confirmed hardware conflicts per agent for reputation scoring.
ALTER TABLE reputation_snapshots ADD COLUMN hardware_conflict_count INT NOT NULL DEFAULT 0;
