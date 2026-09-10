-- Prevent duplicate scan jobs from GitHub webhook redeliveries.
-- GitHub retries webhook delivery when it does not receive a response within 10 seconds.
-- Without this index, a slow server response causes the same commit to be scanned twice
-- and opens duplicate security-fix PRs in the repository.
-- ON CONFLICT (repo_full_name, head_sha) DO NOTHING in EnqueueScanJob uses this index.
CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_jobs_repo_sha
    ON scan_jobs (repo_full_name, head_sha);
