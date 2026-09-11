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

	// ── 8. Open informational PRs grouped by file (one PR per file) ────
	// PRs contain zero source-code changes — they are purely informational,
	// describing the finding and recommending remediation to the developer.
	// If the branch already exists and has an open PR, the body is updated.
	eligibleSeverities := map[string]bool{"Critical": true, "High": true}
	baseSHA, err := gh.GetDefaultBranchSHA(ctx, token, owner, repo, job.DefaultBranch)
	if err != nil {
		return 0, fmt.Errorf("get default branch SHA: %w", err)
	}

	groups := groupFindingsByFile(final, eligibleSeverities)

	prsOpened := 0
	for _, group := range groups {
		if prsOpened >= maxPRsPerScan {
			log.Info("PR cap reached", "cap", maxPRsPerScan)
			break
		}
		fileContent, ok := fileContents[group.filePath]
		if !ok {
			continue
		}

		prURL, err := createOrUpdateFilePR(ctx, log, llmClient, token, owner, repo,
			job.DefaultBranch, baseSHA, group.findings, fileContent)
		if err != nil {
			log.Warn("file PR failed", "file", group.filePath, "error", err)
			continue
		}
		log.Info("PR opened/updated", "url", prURL, "file", group.filePath, "findings", len(group.findings))
		prsOpened++
	}

	return prsOpened, nil
}

// fileFindingGroup holds all eligible findings for a single file.
type fileFindingGroup struct {
	filePath string
	findings []*types.Finding
}

// groupFindingsByFile collects findings that pass the severity filter into one group
// per unique file path, preserving the order findings are encountered.
func groupFindingsByFile(findings []*types.Finding, eligible map[string]bool) []fileFindingGroup {
	seen := map[string]int{} // filePath → index in result
	var groups []fileFindingGroup
	for _, f := range findings {
		if !eligible[f.Severity] {
			continue
		}
		if idx, ok := seen[f.File]; ok {
			groups[idx].findings = append(groups[idx].findings, f)
		} else {
			seen[f.File] = len(groups)
			groups = append(groups, fileFindingGroup{filePath: f.File, findings: []*types.Finding{f}})
		}
	}
	return groups
}

// createOrUpdateFilePR opens (or updates) a single informational PR for all findings
// in one file. Branch naming is deterministic so we can identify an existing PR:
//
//	ciotx/findings-<sanitized-file-path>
//
// Decision matrix:
//   - Branch does not exist → create branch, empty commit, open new PR
//   - Branch exists + open PR → update PR body with fresh findings
//   - Branch exists, no open PR (was closed/merged) → delete branch, re-create, open new PR
func createOrUpdateFilePR(
	ctx context.Context,
	log *slog.Logger,
	llmClient *llm.Client,
	token, owner, repo, defaultBranch, baseSHA string,
	findings []*types.Finding,
	fileContent string,
) (string, error) {
	filePath := findings[0].File
	filename := filePath
	if i := strings.LastIndexByte(filename, '/'); i >= 0 {
		filename = filename[i+1:]
	}

	// Deterministic branch name for this file.
	branchName := "ciotx/findings-" + gh.SanitizeFilePath(filePath)

	// PR title.
	n := len(findings)
	noun := "finding"
	if n != 1 {
		noun = "findings"
	}
	prTitle := fmt.Sprintf("[ciotx] %d security %s in %s", n, noun, filename)
	if len(prTitle) > 72 {
		prTitle = prTitle[:72]
	}

	// Generate PR body (LLM, falls back to plain text on failure).
	prBody, err := llm.RunPRBody(ctx, llmClient, findings, fileContent)
	if err != nil {
		log.Warn("PR body generation failed — using fallback", "error", err)
	}

	exists, err := gh.BranchExists(ctx, token, owner, repo, branchName)
	if err != nil {
		return "", fmt.Errorf("check branch exists: %w", err)
	}

	if exists {
		// Check for an open PR on this branch.
		prNum, err := gh.FindOpenPR(ctx, token, owner, repo, branchName)
		if err != nil {
			return "", fmt.Errorf("find open PR: %w", err)
		}
		if prNum > 0 {
			// Open PR found — update its body with the latest findings.
			if err := gh.UpdatePRBody(ctx, token, owner, repo, prNum, prBody); err != nil {
				return "", fmt.Errorf("update PR body: %w", err)
			}
			log.Info("updated existing PR", "branch", branchName, "pr", prNum)
			return fmt.Sprintf("https://github.com/%s/%s/pull/%d", owner, repo, prNum), nil
		}
		// PR was closed/merged — delete the stale branch and start fresh.
		if err := gh.DeleteBranch(ctx, token, owner, repo, branchName); err != nil {
			log.Warn("could not delete stale branch", "branch", branchName, "error", err)
			// Non-fatal — attempt creation anyway (it may fail with 422 if branch still exists)
		}
	}

	// Create branch + empty commit + new PR.
	if err := gh.CreateBranch(ctx, token, owner, repo, branchName, baseSHA); err != nil {
		return "", fmt.Errorf("create branch %s: %w", branchName, err)
	}
	log.Info("branch created", "branch", branchName)

	emptyMsg := fmt.Sprintf("chore: ciotx security scan — %d %s in %s (no code changes)", n, noun, filename)
	if err := gh.CreateEmptyCommit(ctx, token, owner, repo, branchName, baseSHA, emptyMsg); err != nil {
		return "", fmt.Errorf("empty commit: %w", err)
	}

	prURL, err := gh.OpenPR(ctx, token, owner, repo, prTitle, prBody, branchName, defaultBranch)
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
