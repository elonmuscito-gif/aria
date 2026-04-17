-- Migration 008: Archive anomalies instead of delete
-- Keeps history while keeping main table fast

CREATE TABLE IF NOT EXISTS anomalies_archive (
  LIKE anomalies INCLUDING ALL
);

ALTER TABLE anomalies_archive 
  ADD COLUMN IF NOT EXISTS archived_at 
  TIMESTAMPTZ DEFAULT NOW();