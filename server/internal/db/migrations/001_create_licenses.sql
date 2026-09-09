-- 001_create_licenses.sql
-- Core license table: one row per customer key.
-- scan_month tracks which calendar month scans_this_month counts — avoids a background reset job.

CREATE TABLE IF NOT EXISTS licenses (
    id                   UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    license_key          VARCHAR(64) UNIQUE NOT NULL,
    organization         VARCHAR(255) NOT NULL,
    email                VARCHAR(255) NOT NULL,
    plan                 VARCHAR(32)  NOT NULL DEFAULT 'starter',  -- starter | pro | enterprise
    max_scans_per_month  INT          NOT NULL DEFAULT 50,
    scans_this_month     INT          NOT NULL DEFAULT 0,
    scan_month           VARCHAR(7)   NOT NULL DEFAULT '',          -- 'YYYY-MM', reset by app logic
    is_active            BOOLEAN      NOT NULL DEFAULT TRUE,
    expires_at           TIMESTAMPTZ,
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_licenses_key ON licenses (license_key);
CREATE INDEX IF NOT EXISTS idx_licenses_email ON licenses (email);
