package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/iam-orsu/ciotx/server/internal/db"
	"github.com/iam-orsu/ciotx/server/internal/llm"
	"github.com/iam-orsu/ciotx/server/internal/types"
)

// =====================================================================
// REQUEST / RESPONSE MODELS
// =====================================================================

type ChunkPayload struct {
	ChunkID int    `json:"chunk_id"`
	Payload string `json:"payload"`
}

type ScanRequest struct {
	Chunks     []ChunkPayload `json:"chunks"`
	TotalFiles int            `json:"total_files"`
	TotalLines int            `json:"total_lines"`
}

type ScanStats struct {
	HallucinationsDropped  int     `json:"hallucinations_dropped"`
	FalsePositivesFiltered int     `json:"false_positives_filtered"`
	DurationSeconds        float64 `json:"duration_seconds"`
	EstimatedCostUSD       float64 `json:"estimated_cost_usd"`
}

type ScanResponse struct {
	Findings []*types.Finding `json:"findings"`
	Stats    ScanStats        `json:"stats"`
}

// =====================================================================
// SCAN HANDLER
// =====================================================================

// ScanHandler processes incoming scan requests from the CLI.
// It runs the full discovery + verification + audit pipeline server-side.
// Zero LLM branding is returned in the response.
func ScanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// ── Quota check (DB-backed licenses only; master key bypasses) ────
	license := licenseFromContext(r.Context())
	if license != nil && license.IsQuotaExceeded() {
		writeError(w, http.StatusPaymentRequired,
			fmt.Sprintf("monthly scan limit reached (%d/%d) — upgrade your plan",
				license.ScansThisMonth, license.MaxScansPerMonth))
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 32<<20)) // 32MB max
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	var req ScanRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request format")
		return
	}

	if len(req.Chunks) == 0 {
		writeJSON(w, http.StatusOK, ScanResponse{Findings: []*types.Finding{}, Stats: ScanStats{}})
		return
	}

	// Context with timeout — propagated to all LLM calls so a hung scan
	// cannot block the server goroutine pool indefinitely.
	scanCtx, cancel := context.WithTimeout(r.Context(), 30*time.Minute)
	defer cancel()

	startTime := time.Now()
	client := llm.NewClient()

	// Track usage per model for accurate per-model cost calculation.
	discoveryUsage := &llm.Usage{}
	auditUsage := &llm.Usage{}
	var usageMu sync.Mutex

	// ── Phase 1: Discovery pass — sequential (required by rate limits)
	var candidateFindings []*types.Finding
	for _, chunk := range req.Chunks {
		findings, err := llm.RunDiscovery(scanCtx, client, chunk.ChunkID, chunk.Payload, discoveryUsage, &usageMu)
		if err != nil {
			// Log server-side only — never expose internal errors to users
			fmt.Printf("[server] chunk #%d error: %v\n", chunk.ChunkID, err)
			continue
		}
		candidateFindings = append(candidateFindings, findings...)
		fmt.Printf("[server] chunk #%d: %d candidates\n", chunk.ChunkID, len(findings))
	}

	// ── Phase 2: Evidence re-anchoring — drop hallucinations
	filesContent := extractFilesContent(req.Chunks)
	verified, dropped := verifyFindings(candidateFindings, filesContent)
	fmt.Printf("[server] verified: %d (%d hallucinations dropped)\n", len(verified), dropped)

	// ── Phase 3: Adversarial audit — filter false positives
	final, rejected, _ := llm.RunAudit(scanCtx, client, verified, filesContent, auditUsage, &usageMu)
	fmt.Printf("[server] final: %d (%d false positives filtered)\n", len(final), rejected)

	if final == nil {
		final = []*types.Finding{}
	}

	totalCost := llm.CostUSD(*discoveryUsage, llm.DiscoveryModel()) +
		llm.CostUSD(*auditUsage, llm.AuditModel())

	resp := ScanResponse{
		Findings: final,
		Stats: ScanStats{
			HallucinationsDropped:  dropped,
			FalsePositivesFiltered: rejected,
			DurationSeconds:        time.Since(startTime).Seconds(),
			EstimatedCostUSD:       totalCost,
		},
	}

	writeJSON(w, http.StatusOK, resp)

	// ── Post-scan accounting (non-fatal — scan is already done) ──────
	// Run in a background goroutine so the HTTP response is not delayed.
	if license != nil {
		clientVersion := strings.TrimPrefix(r.Header.Get("User-Agent"), "ciotx/")
		criticalCount := 0
		highCount := 0
		for _, f := range final {
			switch f.Severity {
			case "Critical":
				criticalCount++
			case "High":
				highCount++
			}
		}
		durationMS := time.Since(startTime).Milliseconds()
		go func() {
			bgCtx, bgCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer bgCancel()
			if err := db.IncrementScanCount(bgCtx, license.ID); err != nil {
				fmt.Printf("[server] warn: increment scan count: %v\n", err)
			}
			if err := db.RecordScan(bgCtx, license.ID, clientVersion,
				len(final), criticalCount, highCount, durationMS); err != nil {
				fmt.Printf("[server] warn: record scan history: %v\n", err)
			}
		}()
	}
}

// =====================================================================
// EVIDENCE VERIFICATION (server-side re-anchoring)
// =====================================================================

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

		// Check candidate line first
		if candIdx := f.LineStart - 1; candIdx >= 0 && candIdx < len(lines) {
			if strings.Contains(lines[candIdx], firstEv) {
				matchedStart = f.LineStart
				matchedEnd = f.LineStart + len(evLines) - 1
			}
		}

		// Search ±15 lines
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

		// Full file search for non-trivial evidence
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

// extractFilesContent parses file content from chunk payloads for evidence verification.
// Chunks are formatted as "===== FILE: path (N lines) =====\n0001 | line\n..."
func extractFilesContent(chunks []ChunkPayload) map[string][]string {
	result := map[string][]string{}

	fileHeaderRe := regexp.MustCompile(`===== FILE: (.+?) \(\d+ lines\) =====`)
	lineRe := regexp.MustCompile(`^\d{4} \| (.*)$`)

	for _, chunk := range chunks {
		currentFile := ""
		for _, line := range strings.Split(chunk.Payload, "\n") {
			if m := fileHeaderRe.FindStringSubmatch(line); len(m) > 1 {
				currentFile = strings.TrimSpace(m[1])
				if _, exists := result[currentFile]; !exists {
					result[currentFile] = []string{}
				}
				continue
			}
			if currentFile != "" {
				if m := lineRe.FindStringSubmatch(line); len(m) > 1 {
					result[currentFile] = append(result[currentFile], m[1])
				}
			}
		}
	}

	return result
}

// =====================================================================
// HELPERS
// =====================================================================

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

