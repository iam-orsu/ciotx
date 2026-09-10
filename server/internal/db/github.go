package db

import (
	"context"
	"fmt"
	"time"
)

// GitHubInstallation represents a GitHub App installation record.
type GitHubInstallation struct {
	InstallationID int64
	AccountLogin   string
	AccountType    string
	CreatedAt      time.Time
	SuspendedAt    *time.Time
	UninstalledAt  *time.Time
}

// UpsertInstallation inserts or updates a GitHub App installation record.
func UpsertInstallation(ctx context.Context, inst *GitHubInstallation) error {
	if !IsAvailable() {
		return fmt.Errorf("database unavailable")
	}
	_, err := Pool().Exec(ctx, `
		INSERT INTO github_installations
			(installation_id, account_login, account_type, suspended_at, uninstalled_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (installation_id) DO UPDATE SET
			account_login  = EXCLUDED.account_login,
			account_type   = EXCLUDED.account_type,
			suspended_at   = EXCLUDED.suspended_at,
			uninstalled_at = EXCLUDED.uninstalled_at
	`, inst.InstallationID, inst.AccountLogin, inst.AccountType,
		inst.SuspendedAt, inst.UninstalledAt)
	return err
}

// GetInstallation returns a GitHub installation record, or ErrNotFound.
func GetInstallation(ctx context.Context, installationID int64) (*GitHubInstallation, error) {
	if !IsAvailable() {
		return nil, fmt.Errorf("database unavailable")
	}
	row := Pool().QueryRow(ctx, `
		SELECT installation_id, account_login, account_type,
		       created_at, suspended_at, uninstalled_at
		FROM github_installations
		WHERE installation_id = $1
	`, installationID)
	var inst GitHubInstallation
	if err := row.Scan(
		&inst.InstallationID, &inst.AccountLogin, &inst.AccountType,
		&inst.CreatedAt, &inst.SuspendedAt, &inst.UninstalledAt,
	); err != nil {
		return nil, err
	}
	return &inst, nil
}

// ScanJob is one enqueued async scan task.
type ScanJob struct {
	ID             string
	InstallationID int64
	RepoFullName   string
	DefaultBranch  string
	HeadSHA        string
	Status         string
	ErrorMsg       *string
	PRsOpened      int
	CreatedAt      time.Time
	ClaimedAt      *time.Time
}

// EnqueueScanJob inserts a new pending scan job.
// ON CONFLICT DO NOTHING prevents duplicate jobs from GitHub webhook redeliveries
// (GitHub retries when it doesn't receive a response within 10 seconds).
func EnqueueScanJob(ctx context.Context, installationID int64, repoFullName, defaultBranch, headSHA string) error {
	if !IsAvailable() {
		return fmt.Errorf("database unavailable")
	}
	_, err := Pool().Exec(ctx, `
		INSERT INTO scan_jobs (installation_id, repo_full_name, default_branch, head_sha)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (repo_full_name, head_sha) DO NOTHING
	`, installationID, repoFullName, defaultBranch, headSHA)
	return err
}

// ResetStuckJobs resets scan jobs that have been in 'running' state for longer
// than olderThan. This recovers jobs orphaned when the server was killed mid-scan
// (OOM-kill, SIGKILL, power cycle) — they would otherwise stay stuck forever
// because workers only claim 'pending' jobs.
// Returns the number of jobs reset.
func ResetStuckJobs(ctx context.Context, olderThan time.Duration) (int64, error) {
	if !IsAvailable() {
		return 0, nil
	}
	cutoff := time.Now().Add(-olderThan)
	tag, err := Pool().Exec(ctx, `
		UPDATE scan_jobs
		SET status = 'pending', claimed_at = NULL, updated_at = NOW()
		WHERE status = 'running' AND claimed_at < $1
	`, cutoff)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// ClaimNextJob atomically claims one pending job for the calling worker.
// Returns nil, nil when no jobs are available.
func ClaimNextJob(ctx context.Context) (*ScanJob, error) {
	if !IsAvailable() {
		return nil, nil
	}
	row := Pool().QueryRow(ctx, `
		UPDATE scan_jobs
		SET status     = 'running',
		    claimed_at = NOW(),
		    updated_at = NOW()
		WHERE id = (
		    SELECT id FROM scan_jobs
		    WHERE status = 'pending'
		    ORDER BY created_at ASC
		    LIMIT 1
		    FOR UPDATE SKIP LOCKED
		)
		RETURNING id, installation_id, repo_full_name, default_branch, head_sha,
		          status, error_msg, prs_opened, created_at, claimed_at
	`)
	var j ScanJob
	if err := row.Scan(
		&j.ID, &j.InstallationID, &j.RepoFullName, &j.DefaultBranch, &j.HeadSHA,
		&j.Status, &j.ErrorMsg, &j.PRsOpened, &j.CreatedAt, &j.ClaimedAt,
	); err != nil {
		// pgx returns an error for no rows; translate to nil, nil
		return nil, nil //nolint:nilerr
	}
	return &j, nil
}

// CompleteJob marks a job done and records how many PRs were opened.
func CompleteJob(ctx context.Context, jobID string, prsOpened int) error {
	if !IsAvailable() {
		return fmt.Errorf("database unavailable")
	}
	_, err := Pool().Exec(ctx, `
		UPDATE scan_jobs
		SET status = 'done', prs_opened = $2, updated_at = NOW()
		WHERE id = $1
	`, jobID, prsOpened)
	return err
}

// FailJob marks a job failed with an error message.
func FailJob(ctx context.Context, jobID, errMsg string) error {
	if !IsAvailable() {
		return fmt.Errorf("database unavailable")
	}
	_, err := Pool().Exec(ctx, `
		UPDATE scan_jobs
		SET status = 'failed', error_msg = $2, updated_at = NOW()
		WHERE id = $1
	`, jobID, errMsg)
	return err
}
