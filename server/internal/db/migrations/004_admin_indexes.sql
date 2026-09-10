-- Fast aggregate queries for admin dashboard:
--   "scans today" / "scans this month" both filter on created_at.
CREATE INDEX IF NOT EXISTS idx_scan_history_created_at
    ON scan_history (created_at DESC);
