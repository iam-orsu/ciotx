-- Index for fast per-license scan history queries (ORDER BY created_at DESC).
CREATE INDEX IF NOT EXISTS idx_scan_history_license_created
    ON scan_history (license_id, created_at DESC);
