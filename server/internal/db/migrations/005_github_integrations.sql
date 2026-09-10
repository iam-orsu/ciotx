-- GitHub App integration tables for Phase 6.

-- Tracks GitHub App installations (per repo or org).
-- updated whenever the installation webhook fires.
CREATE TABLE IF NOT EXISTS github_installations (
    installation_id  BIGINT      PRIMARY KEY,
    account_login    TEXT        NOT NULL,
    account_type     TEXT        NOT NULL, -- 'User' or 'Organization'
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    suspended_at     TIMESTAMPTZ,          -- NULL = active
    uninstalled_at   TIMESTAMPTZ           -- NULL = installed
);

-- Async scan jobs triggered by push webhooks.
CREATE TABLE IF NOT EXISTS scan_jobs (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    installation_id  BIGINT      NOT NULL REFERENCES github_installations(installation_id),
    repo_full_name   TEXT        NOT NULL,   -- "owner/repo"
    default_branch   TEXT        NOT NULL DEFAULT 'main',
    head_sha         TEXT        NOT NULL,   -- commit that triggered the scan
    status           TEXT        NOT NULL DEFAULT 'pending', -- pending | running | done | failed
    error_msg        TEXT,
    prs_opened       INT         NOT NULL DEFAULT 0,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    claimed_at       TIMESTAMPTZ             -- set when a worker picks it up
);

-- Fast index for the worker's "find next pending job" query.
CREATE INDEX IF NOT EXISTS idx_scan_jobs_pending
    ON scan_jobs (created_at)
    WHERE status = 'pending';
