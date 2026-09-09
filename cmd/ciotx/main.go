// ciotx — Autonomous Deep-Reasoning Source Code Security Auditor
//
// Usage:
//   ciotx scan /path/to/repo
//   ciotx scan . --model deepseek-chat --workers 4
//   ciotx scan . --no-audit --output my-report.html
//   ciotx scan . --dry-run
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/iam-orsu/ciotx/pkg/llm"
	"github.com/iam-orsu/ciotx/pkg/report"
	"github.com/iam-orsu/ciotx/pkg/scanner"
)

// =====================================================================
// PRICING (USD per 1M tokens - DeepSeek rates)
// =====================================================================

const (
	priceInputCacheMiss = 0.14
	priceInputCacheHit  = 0.0028
	priceOutput         = 0.28

	// Paste your keys here or set environment variables.
	// CIOTX_DEEPSEEK_API_KEY
	defaultAPIKey = ""
)

// =====================================================================
// CLI FLAGS
// =====================================================================

type config struct {
	target       string
	apiKey       string
	model        string
	auditModel   string
	workers      int
	maxCost      float64
	output       string
	jsonOutput   string
	dryRun       bool
	noAudit      bool
	version      bool
}

func parseFlags() config {
	cfg := config{}

	flag.StringVar(&cfg.apiKey, "api-key", "", "DeepSeek API key (or set CIOTX_DEEPSEEK_API_KEY env var)")
	flag.StringVar(&cfg.model, "model", llm.ReasonerModel, "Discovery model: deepseek-reasoner (default) or deepseek-chat")
	flag.StringVar(&cfg.auditModel, "audit-model", llm.ChatModel, "Audit model for false-positive filtering")
	flag.IntVar(&cfg.workers, "workers", 2, "Concurrent chunk workers (auto-capped to 1 for deepseek-reasoner)")
	flag.Float64Var(&cfg.maxCost, "max-cost", 5.0, "Maximum budget in USD (aborts if projected cost exceeds this)")
	flag.StringVar(&cfg.output, "output", "ciotx-report.html", "HTML report output path")
	flag.StringVar(&cfg.jsonOutput, "json-output", "ciotx-findings.json", "JSON findings output path")
	flag.BoolVar(&cfg.dryRun, "dry-run", false, "Ingest and estimate cost without making API calls")
	flag.BoolVar(&cfg.noAudit, "no-audit", false, "Skip the adversarial false-positive audit pass")
	flag.BoolVar(&cfg.version, "version", false, "Print version and exit")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `ciotx — Autonomous Deep-Reasoning Security Auditor

Usage:
  ciotx [flags] <target-directory>

Examples:
  ciotx .
  ciotx /path/to/repo --model deepseek-chat --workers 4
  ciotx . --dry-run
  ciotx . --no-audit --output report.html

Flags:
`)
		flag.PrintDefaults()
	}

	flag.Parse()

	// Positional argument: target directory
	if flag.NArg() > 0 {
		cfg.target = flag.Arg(0)
	} else {
		cfg.target = "."
	}

	return cfg
}

// =====================================================================
// MAIN
// =====================================================================

func main() {
	cfg := parseFlags()

	if cfg.version {
		fmt.Println("ciotx v0.1.0 (Phase 1 - Core Engine)")
		os.Exit(0)
	}

	os.Exit(run(cfg))
}

func run(cfg config) int {
	startTime := time.Now()

	// ── Resolve API key ──────────────────────────────────────────────
	apiKey := cfg.apiKey
	if apiKey == "" {
		apiKey = os.Getenv("CIOTX_DEEPSEEK_API_KEY")
	}
	if apiKey == "" {
		apiKey = defaultAPIKey
	}

	// ── Header ───────────────────────────────────────────────────────
	printBanner()
	targetDir, _ := filepath.Abs(cfg.target)
	fmt.Printf("[*] Target Directory : %s\n", targetDir)
	fmt.Printf("[*] Discovery Model  : %s\n", cfg.model)
	if cfg.noAudit {
		fmt.Printf("[*] Verification Pass: Disabled (--no-audit)\n")
	} else {
		fmt.Printf("[*] Verification Pass: %s\n", cfg.auditModel)
	}
	fmt.Printf("[*] Output HTML      : %s\n", cfg.output)
	fmt.Printf("[*] Output JSON      : %s\n", cfg.jsonOutput)
	fmt.Println()

	// ── Phase 1: Ingest ───────────────────────────────────────────────
	fmt.Println("[1/5] Ingesting codebase and indexing source lines...")
	files, err := scanner.IngestCodebase(targetDir)
	if err != nil {
		fmt.Printf("[-] Error reading target directory: %v\n", err)
		return 1
	}
	if len(files) == 0 {
		fmt.Println("[-] No valid source files found to audit.")
		return 0
	}

	sort.Slice(files, func(i, j int) bool { return files[i].RelPath < files[j].RelPath })

	totalLines := 0
	totalTokens := 0
	for _, f := range files {
		totalLines += len(f.Lines)
		totalTokens += f.EstTokens
	}
	fmt.Printf("      Indexed %d files, %d total lines (~%s tokens).\n",
		len(files), totalLines, formatN(totalTokens))

	filesMap := map[string]*scanner.SourceFile{}
	for _, f := range files {
		filesMap[f.RelPath] = f
	}

	// ── Phase 2: Chunk & Budget ───────────────────────────────────────
	chunks := scanner.PartitionChunks(files, 15000)
	estCost := (float64(totalTokens) / 1_000_000) * priceInputCacheMiss
	fmt.Printf("\n[2/5] Partitioned into %d contextual chunk(s).\n", len(chunks))
	fmt.Printf("      Estimated scan cost: ~$%.4f USD (Budget cap: $%.2f)\n", estCost, cfg.maxCost)

	if estCost > cfg.maxCost {
		fmt.Printf("[-] Projected cost ($%.2f) exceeds --max-cost ($%.2f). Aborting.\n", estCost, cfg.maxCost)
		return 1
	}

	if cfg.dryRun {
		fmt.Println("[+] Dry-run complete. No API calls made.")
		return 0
	}

	if apiKey == "" {
		fmt.Println("\n[-] Error: No API key found.")
		fmt.Println("    Set CIOTX_DEEPSEEK_API_KEY environment variable or pass --api-key flag.")
		return 1
	}

	// Auto-cap workers for the slow reasoner model
	workers := cfg.workers
	if cfg.model == llm.ReasonerModel && workers > 1 {
		fmt.Printf("[*] Note: deepseek-reasoner detected — capping workers to 1 to respect rate limits.\n")
		workers = 1
	}

	client := llm.NewClient(apiKey)
	usage := &llm.Usage{}
	var usageMu sync.Mutex

	// ── Phase 3: Discovery Pass ───────────────────────────────────────
	fmt.Printf("\n[3/5] Launching deep semantic discovery pass across %d chunk(s)...\n", len(chunks))

	var candidateFindings []*llm.Finding
	var findingsMu sync.Mutex

	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	interrupted := false

	for _, chunk := range chunks {
		wg.Add(1)
		sem <- struct{}{}
		go func(c *scanner.CodeChunk) {
			defer wg.Done()
			defer func() { <-sem }()

			findings, err := llm.RunDiscoveryPass(client, c, cfg.model, usage, &usageMu)
			if err != nil {
				fmt.Printf("      [!] Chunk #%d failed: %v\n", c.ChunkID, err)
				return
			}
			findingsMu.Lock()
			candidateFindings = append(candidateFindings, findings...)
			findingsMu.Unlock()
			fmt.Printf("      [+] Chunk #%d completed (%d candidate findings)\n", c.ChunkID, len(findings))
		}(chunk)
	}

	waitDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitDone)
	}()

	select {
	case <-waitDone:
		// all chunks done
	}

	if interrupted {
		fmt.Println("\n[!] Scan interrupted.")
		return 130
	}

	fmt.Printf("      Discovered %d raw candidate findings.\n", len(candidateFindings))

	// ── Phase 4: Evidence Re-Anchoring & Verification ─────────────────
	fmt.Println("\n[4/5] Verifying evidence snippets & re-anchoring exact line numbers...")
	verified, dropped := llm.VerifyAndReanchor(candidateFindings, filesMap)
	fmt.Printf("      %d findings passed evidence gate (%d dropped as hallucinations).\n",
		len(verified), dropped)

	// ── Phase 5: Adversarial Audit Pass ──────────────────────────────
	finalFindings := verified
	auditRejected := 0
	if !cfg.noAudit && len(verified) > 0 {
		fmt.Println("\n[5/5] Executing skeptical audit pass to filter false positives...")
		var auditErr error
		finalFindings, auditRejected, auditErr = llm.RunAdversarialAudit(client, verified, filesMap, cfg.auditModel, usage, &usageMu)
		if auditErr != nil {
			fmt.Printf("      [!] Audit pass error: %v\n", auditErr)
		}
		fmt.Printf("      Audit complete: %d confirmed (%d filtered out).\n",
			len(finalFindings), auditRejected)
	} else {
		fmt.Println("\n[5/5] Skipping audit pass.")
	}

	// ── Compute Final Cost ────────────────────────────────────────────
	duration := time.Since(startTime).Seconds()
	costUSD := (float64(usage.CacheMissTokens)/1_000_000)*priceInputCacheMiss +
		(float64(usage.CacheHitTokens)/1_000_000)*priceInputCacheHit +
		(float64(usage.CompletionTokens)/1_000_000)*priceOutput

	stats := &report.ScanStats{
		TotalFiles:            len(files),
		TotalLines:            totalLines,
		TotalTokensEst:        totalTokens,
		PromptTokens:          usage.PromptTokens,
		CompletionTokens:      usage.CompletionTokens,
		CacheHitTokens:        usage.CacheHitTokens,
		CacheMissTokens:       usage.CacheMissTokens,
		HallucinationsDropped: dropped,
		AuditRejected:         auditRejected,
		DurationSeconds:       duration,
		EstimatedCostUSD:      costUSD,
	}

	// ── Write Reports ─────────────────────────────────────────────────
	if err := report.WriteHTML(finalFindings, stats, targetDir, cfg.output); err != nil {
		fmt.Printf("[!] Failed to write HTML report: %v\n", err)
	}
	if err := report.WriteJSON(finalFindings, cfg.jsonOutput); err != nil {
		fmt.Printf("[!] Failed to write JSON findings: %v\n", err)
	}

	// ── Summary ───────────────────────────────────────────────────────
	fmt.Println("\n" + line())
	fmt.Printf("[+] SCAN COMPLETE in %.1fs\n", duration)
	fmt.Printf("    - Findings Identified : %d\n", len(finalFindings))
	fmt.Printf("    - HTML Report Written : %s\n", absPath(cfg.output))
	fmt.Printf("    - JSON Findings Saved : %s\n", absPath(cfg.jsonOutput))
	fmt.Printf("    - Est. Scan Cost      : $%.4f\n", costUSD)
	fmt.Println(line())

	return 0
}

// =====================================================================
// HELPERS
// =====================================================================

func printBanner() {
	fmt.Println(line())
	fmt.Println("  ciotx — Autonomous Deep-Reasoning Security Auditor")
	fmt.Println("  github.com/iam-orsu/ciotx")
	fmt.Println(line())
}

func line() string {
	return "======================================================================"
}

func absPath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return abs
}

func formatN(n int) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	result := make([]byte, 0, len(s)+(len(s)-1)/3)
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, byte(c))
	}
	return string(result)
}
