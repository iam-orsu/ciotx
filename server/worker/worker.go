// Package worker runs the async scan-and-PR pipeline triggered by GitHub push events.
// Workers poll the scan_jobs table, process one job at a time, and open GitHub PRs
// for each confirmed security finding that the LLM can produce a fix for.
package worker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/iam-orsu/ciotx/server/internal/db"
	gh "github.com/iam-orsu/ciotx/server/internal/github"
	"github.com/iam-orsu/ciotx/server/internal/llm"
	"github.com/iam-orsu/ciotx/server/internal/types"
)

const (
	// maxPRsPerScan caps automatic PR creation so a single bad push can't
	// spam a repository with dozens of pull requests.
	maxPRsPerScan = 5

	// pollInterval controls how often idle workers check for new jobs.
	pollInterval = 10 * time.Second

	// scanTimeout is the total budget for one repo scan + PR creation.
	// Shorter than the main scan timeout because we also allocate time for fix generation.
	scanTimeout = 25 * time.Minute
)

// Start launches n worker goroutines that run until ctx is cancelled.
// Call this once at server startup after the DB and GitHub App are configured.
func Start(ctx context.Context, n int) {
	if n < 1 {
		n = 2
	}

	// Recover jobs stuck in 'running' from a previous server crash (OOM-kill, SIGKILL,
	// power cycle). Those jobs will never be claimed again because workers only query
	// for 'pending'. Reset them so they are retried by this worker pool.
	resetCtx, resetCancel := context.WithTimeout(ctx, 10*time.Second)
	defer resetCancel()
	if count, err := db.ResetStuckJobs(resetCtx, scanTimeout); err != nil {
		slog.Warn("failed to reset stuck scan jobs", "error", err)
	} else if count > 0 {
		slog.Info("reset stuck scan jobs for retry", "count", count)
	}

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			runWorker(ctx, id)
		}(i + 1)
	}
	// wg.Wait() is intentionally not called here — workers run for the process lifetime.
}

func runWorker(ctx context.Context, id int) {
	slog.Info("scan worker started", "worker", id)
	for {
		// Use NewTimer + explicit Stop so the timer goroutine is cleaned up immediately
		// when the context is cancelled, rather than leaking until pollInterval expires.
		t := time.NewTimer(pollInterval)
		select {
		case <-ctx.Done():
			t.Stop()
			slog.Info("scan worker stopping", "worker", id)
			return
		case <-t.C:
			processOneJob(ctx, id)
		}
	}
}

func processOneJob(ctx context.Context, workerID int) {
	// Claim a job atomically — other workers are racing for the same queue.
	job, err := db.ClaimNextJob(ctx)
	if err != nil || job == nil {
		return // no jobs available
	}

	log := slog.With("job", job.ID, "repo", job.RepoFullName, "worker", workerID)
	log.Info("processing scan job", "sha", job.HeadSHA)

	jobCtx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()

	prsOpened, err := runJob(jobCtx, log, job)
	if err != nil {
		log.Error("scan job failed", "error", err)
		_ = db.FailJob(context.Background(), job.ID, err.Error())
		return
	}
	_ = db.CompleteJob(context.Background(), job.ID, prsOpened)
	log.Info("scan job complete", "prs_opened", prsOpened)
}

func runJob(ctx context.Context, log *slog.Logger, job *db.ScanJob) (int, error) {
	// ── 1. Get GitHub App credentials ────────────────────────────────
	appCfg, err := gh.App()
	if err != nil {
		return 0, fmt.Errorf("GitHub App not configured: %w", err)
	}
	token, err := gh.GetInstallationToken(ctx, appCfg, job.InstallationID)
	if err != nil {
		return 0, fmt.Errorf("installation token: %w", err)
	}

	// ── 2. Parse owner/repo ──────────────────────────────────────────
	parts := strings.SplitN(job.RepoFullName, "/", 2)
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid repo_full_name: %q", job.RepoFullName)
	}
	owner, repo := parts[0], parts[1]

	// ── 3. Fetch repo files via GitHub API ──────────────────────────
	log.Info("fetching repo files", "sha", job.HeadSHA)
	files, err := gh.FetchRepoFiles(ctx, token, owner, repo, job.HeadSHA)
	if err != nil {
		return 0, fmt.Errorf("fetch repo files: %w", err)
	}
	if len(files) == 0 {
		log.Info("no scannable files found")
		return 0, nil
	}
	log.Info("files fetched", "count", len(files))

	// ── 4. Build file content map for evidence re-anchoring ──────────
	fileContents := make(map[string]string, len(files))
	for _, f := range files {
		fileContents[f.Path] = f.Content
	}

	// ── 5. Run discovery pass across all chunks ──────────────────────
	llmClient := llm.NewClient()
	chunks := gh.PartitionFiles(files)

	var candidateFindings []*types.Finding
	discoveryUsage := &llm.Usage{}
	var usageMu sync.Mutex

	for i, chunk := range chunks {
		payload := gh.FormatChunkPayload(chunk)
		findings, err := llm.RunDiscovery(ctx, llmClient, i+1, payload, discoveryUsage, &usageMu)
		if err != nil {
			log.Warn("chunk discovery error", "chunk", i+1, "error", err)
			continue
		}
		candidateFindings = append(candidateFindings, findings...)
		log.Info("chunk scanned", "chunk", i+1, "candidates", len(findings))
	}

	if len(candidateFindings) == 0 {
		log.Info("no candidate findings")
		return 0, nil
	}

	// ── 6. Evidence re-anchoring — drop hallucinations ───────────────
	// Build the filesContent map in the format verifyFindings expects
	// (map[string][]string: filepath → slice of lines).
	filesLines := make(map[string][]string, len(fileContents))
	for path, content := range fileContents {
		filesLines[path] = strings.Split(content, "\n")
	}
	verified, dropped := verifyFindings(candidateFindings, filesLines)
	log.Info("verification", "verified", len(verified), "dropped", dropped)

	if len(verified) == 0 {
		return 0, nil
	}

	// ── 7. Adversarial audit pass ─────────────────────────────────────
	auditUsage := &llm.Usage{}
	final, rejected, _ := llm.RunAudit(ctx, llmClient, verified, filesLines, auditUsage, &usageMu)
	log.Info("audit", "final", len(final), "rejected", rejected)

	if len(final) == 0 {
		return 0, nil
	}

	// ── 8. Generate fixes and open PRs ──────────────────────────────
	// Only Critical and High findings get automated PRs, and we cap at maxPRsPerScan.
	eligibleSeverities := map[string]bool{"Critical": true, "High": true}
	baseSHA, err := gh.GetDefaultBranchSHA(ctx, token, owner, repo, job.DefaultBranch)
	if err != nil {
		return 0, fmt.Errorf("get default branch SHA: %w", err)
	}

	prsOpened := 0
	for _, finding := range final {
		if prsOpened >= maxPRsPerScan {
			log.Info("PR cap reached", "cap", maxPRsPerScan)
			break
		}
		if !eligibleSeverities[finding.Severity] {
			continue
		}
		fileContent, ok := fileContents[finding.File]
		if !ok {
			continue
		}

		prURL, err := createFixPR(ctx, log, llmClient, token, owner, repo,
			job.DefaultBranch, baseSHA, finding, fileContent)
		if err != nil {
			log.Warn("fix PR failed", "finding", finding.CWE, "file", finding.File, "error", err)
			continue
		}
		log.Info("PR opened", "url", prURL, "cwe", finding.CWE)
		prsOpened++
	}

	return prsOpened, nil
}

// createFixPR generates a fix with the LLM and opens a GitHub PR for one finding.
// llmClient is passed in from the caller to avoid allocating a new HTTP client per PR.
func createFixPR(
	ctx context.Context,
	log *slog.Logger,
	llmClient *llm.Client,
	token, owner, repo, defaultBranch, baseSHA string,
	finding *types.Finding,
	fileContent string,
) (string, error) {
	// Generate fix.
	fix, err := llm.RunFix(ctx, llmClient, finding, fileContent)
	if err != nil {
		return "", fmt.Errorf("fix generation: %w", err)
	}

	// Sanity check: don't commit a fix that is identical to the original.
	if strings.TrimSpace(fix.FixedContent) == strings.TrimSpace(fileContent) {
		return "", fmt.Errorf("LLM produced no change for %s", finding.File)
	}

	// Create a uniquely-named branch.
	branchName := fmt.Sprintf("ciotx/fix-%s-%s",
		gh.SanitizeBranchName(finding.CWE),
		randomHex(4),
	)
	if err := gh.CreateBranch(ctx, token, owner, repo, branchName, baseSHA); err != nil {
		return "", fmt.Errorf("create branch %s: %w", branchName, err)
	}
	log.Info("branch created", "branch", branchName)

	// Get the current blob SHA for the file (required by GitHub's update file API).
	fileSHA, err := gh.GetFileSHA(ctx, token, owner, repo, finding.File, defaultBranch)
	if err != nil {
		return "", fmt.Errorf("get file SHA for %s: %w", finding.File, err)
	}

	// Commit the fixed file.
	commitMsg := fmt.Sprintf("fix: %s — %s (%s:%d)",
		finding.CWE, finding.Title, finding.File, finding.LineStart)
	if err := gh.CommitFile(ctx, token, owner, repo,
		finding.File, branchName, commitMsg, fix.FixedContent, fileSHA); err != nil {
		return "", fmt.Errorf("commit fix: %w", err)
	}

	// Open the PR.
	prURL, err := gh.OpenPR(ctx, token, owner, repo,
		fix.PRTitle, fix.PRBody, branchName, defaultBranch)
	if err != nil {
		return "", fmt.Errorf("open PR: %w", err)
	}
	return prURL, nil
}

// ── Evidence verification (duplicated from handlers/scan.go to avoid coupling) ─

// verifyFindings re-anchors LLM-reported line numbers to the actual source.
// This is a faithful copy of the logic in handlers/scan.go#verifyFindings.
func verifyFindings(findings []*types.Finding, filesContent map[string][]string) ([]*types.Finding, int) {
	dropped := 0
	seen := map[string]bool{}
	var verified []*types.Finding

	for _, f := range findings {
		lines, ok := filesContent[f.File]
		if !ok {
			dropped++
			continue
		}
		evidenceText := strings.TrimSpace(f.Evidence)
		if evidenceText == "" {
			dropped++
			continue
		}
		evLines := strings.Split(evidenceText, "\n")
		firstEv := strings.TrimSpace(evLines[0])
		if firstEv == "" {
			dropped++
			continue
		}

		matchedStart := -1
		matchedEnd := -1

		if candIdx := f.LineStart - 1; candIdx >= 0 && candIdx < len(lines) {
			if strings.Contains(lines[candIdx], firstEv) {
				matchedStart = f.LineStart
				matchedEnd = f.LineStart + len(evLines) - 1
			}
		}
		if matchedStart == -1 {
			start := max(0, f.LineStart-16)
			end := min(len(lines), f.LineStart+15)
			for idx := start; idx < end; idx++ {
				if strings.Contains(lines[idx], firstEv) {
					matchedStart = idx + 1
					matchedEnd = idx + len(evLines)
					break
				}
			}
		}
		if matchedStart == -1 && len(firstEv) >= 5 {
			for idx, line := range lines {
				if strings.Contains(line, firstEv) {
					matchedStart = idx + 1
					matchedEnd = idx + len(evLines)
					break
				}
			}
		}
		if matchedStart == -1 {
			dropped++
			continue
		}

		f.LineStart = matchedStart
		f.LineEnd = matchedEnd
		if f.LineEnd < f.LineStart {
			f.LineEnd = f.LineStart
		}
		key := fmt.Sprintf("%s|%s|%d", f.File, f.CWE, f.LineStart)
		if seen[key] {
			continue
		}
		seen[key] = true
		verified = append(verified, f)
	}
	return verified, dropped
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "0000"
	}
	return hex.EncodeToString(b)
}
