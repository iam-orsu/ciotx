-- 002_create_scan_history.sql
-- Audit trail: one row per completed scan.
-- Used by the Phase 4 admin dashboard for metrics and per-customer usage reporting.

CREATE TABLE IF NOT EXISTS scan_history (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    license_id      UUID        NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
    findings_count  INT         NOT NULL DEFAULT 0,
    critical_count  INT         NOT NULL DEFAULT 0,
    high_count      INT         NOT NULL DEFAULT 0,
    duration_ms     BIGINT      NOT NULL,
    client_version  VARCHAR(32) NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scan_history_license ON scan_history (license_id);
CREATE INDEX IF NOT EXISTS idx_scan_history_created ON scan_history (created_at DESC);
