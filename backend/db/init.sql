-- PhishGuard AI — PostgreSQL init
-- SQLAlchemy creates tables on startup via init_db().
-- This file adds extra indexes for production query performance.

-- Run after first startup (tables already created by SQLAlchemy):

-- Fast lookups by domain (most common query)
CREATE INDEX IF NOT EXISTS idx_scan_results_domain     ON scan_results(domain);
CREATE INDEX IF NOT EXISTS idx_scan_results_created_at ON scan_results(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_results_verdict    ON scan_results(verdict);

CREATE INDEX IF NOT EXISTS idx_threat_feed_flagged_at  ON threat_feed(flagged_at DESC);
CREATE INDEX IF NOT EXISTS idx_threat_feed_category    ON threat_feed(category);
