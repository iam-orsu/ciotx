// ciotx — Source Code Security Auditor
//
// Usage:
//   ciotx auth login              Authenticate with your ciotx license key
//   ciotx scan .                  Scan current directory
//   ciotx scan /path/to/repo      Scan a specific directory
package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/iam-orsu/ciotx/cli/pkg/api"
	"github.com/iam-orsu/ciotx/cli/pkg/config"
	"github.com/iam-orsu/ciotx/cli/pkg/report"
	"github.com/iam-orsu/ciotx/cli/pkg/scanner"
)

// Build metadata — ALL injected via ldflags at build time by deploy.sh / Makefile.
// The operator sets DOMAIN_NAME in .env; deploy.sh compiles these in.
// Zero hardcoded domains ship in the binary.
var (
	APIEndpoint = "http://localhost:8080" // always overridden: -X main.APIEndpoint=https://DOMAIN_NAME
	WebsiteURL  = "http://localhost:8080" // always overridden: -X main.WebsiteURL=https://DOMAIN_NAME
	Version     = "dev"
	Commit      = "unknown"
	BuildDate   = "unknown"
)

func main() {
	args := os.Args[1:]

	if len(args) == 0 {
		printHelp()
		os.Exit(0)
	}

	switch args[0] {
	case "auth":
		if len(args) < 2 || args[1] != "login" {
			printHelp()
			os.Exit(1)
		}
		os.Exit(cmdAuthLogin())

	case "scan":
		target := "."
		if len(args) >= 2 {
			target = args[1]
		}
		os.Exit(cmdScan(target))

	case "status":
		os.Exit(cmdStatus())

	case "history":
		limit := 10
		if len(args) >= 3 && args[1] == "--limit" {
			if n, err := strconv.Atoi(args[2]); err == nil && n >= 1 && n <= 50 {
				limit = n
			}
		}
		os.Exit(cmdHistory(limit))

	case "version", "--version", "-v":
		fmt.Printf("ciotx %s (commit %s, built %s)\n", Version, Commit, BuildDate)
		os.Exit(0)

	case "help", "--help", "-h":
		printHelp()
		os.Exit(0)

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", args[0])
		printHelp()
		os.Exit(1)
	}
}

// =====================================================================
// ciotx auth login
// =====================================================================

func cmdAuthLogin() int {
	fmt.Println()
	fmt.Println("  ciotx — Authentication")
	fmt.Println(strings.Repeat("─", 50))
	fmt.Println()
	fmt.Print("  Enter your license key: ")

	reader := bufio.NewReader(os.Stdin)
	key, err := reader.ReadString('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n[!] Failed to read input: %v\n", err)
		return 1
	}
	key = strings.TrimSpace(key)

	if key == "" {
		fmt.Println("\n[!] License key cannot be empty.")
		fmt.Printf("    Get your key at %s\n", WebsiteURL)
		return 1
	}

	fmt.Println("\n  Verifying license key...")

	cfg := &config.Config{LicenseKey: key}
	client := api.NewClient(APIEndpoint, key, Version)
	if err := client.VerifyLicense(key); err != nil {
		fmt.Fprintf(os.Stderr, "\n[!] %v\n", err)
		return 1
	}

	if err := config.Save(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "\n[!] Failed to save credentials: %v\n", err)
		return 1
	}

	fmt.Println("\n  [+] Authenticated successfully!")
	fmt.Println("      You can now run: ciotx scan .")
	fmt.Println()
	return 0
}

// =====================================================================
// ciotx scan <path>
// =====================================================================

func cmdScan(target string) int {
	startTime := time.Now()

	// ── Load credentials ──────────────────────────────────────────────
	cfg, err := config.Load()
	if err != nil || !cfg.IsAuthenticated() {
		fmt.Println()
		fmt.Println("[!] Not authenticated. Run 'ciotx auth login' first.")
		return 1
	}

	// ── Print header ──────────────────────────────────────────────────
	targetDir, _ := filepath.Abs(target)
	fmt.Println()
	fmt.Println(strings.Repeat("─", 56))
	fmt.Println("  ciotx  Security Auditor")
	fmt.Println(strings.Repeat("─", 56))
	fmt.Printf("  Target : %s\n", targetDir)
	fmt.Println()

	// ── Step 1: Ingest codebase ───────────────────────────────────────
	fmt.Print("  [1/3] Reading source files...")
	files, err := scanner.IngestCodebase(targetDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n[!] Error reading directory: %v\n", err)
		return 1
	}
	if len(files) == 0 {
		fmt.Println("\n[!] No source files found in this directory.")
		return 0
	}
	sort.Slice(files, func(i, j int) bool { return files[i].RelPath < files[j].RelPath })

	totalLines := 0
	for _, f := range files {
		totalLines += len(f.Lines)
	}
	fmt.Printf(" %d files, %s lines\n", len(files), formatN(totalLines))

	// ── Step 2: Chunk and send to backend ─────────────────────────────
	chunks := scanner.PartitionChunks(files, 15000)
	fmt.Printf("  [2/3] Analyzing code (this may take a few minutes)...\n")

	var apiChunks []api.ChunkPayload
	for _, c := range chunks {
		apiChunks = append(apiChunks, api.ChunkPayload{
			ChunkID: c.ChunkID,
			Payload: c.PayloadText,
		})
	}

	client := api.NewClient(APIEndpoint, cfg.LicenseKey, Version)
	scanResp, err := client.Scan(&api.ScanRequest{
		Chunks:     apiChunks,
		TotalFiles: len(files),
		TotalLines: totalLines,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n[!] Scan failed: %v\n", err)
		return 1
	}

	// ── Step 3: Generate report ───────────────────────────────────────
	duration := time.Since(startTime).Seconds()
	findings := scanResp.Findings
	stats := &report.ScanStats{
		TotalFiles:             len(files),
		TotalLines:             totalLines,
		HallucinationsDropped:  scanResp.Stats.HallucinationsDropped,
		FalsePositivesFiltered: scanResp.Stats.FalsePositivesFiltered,
		DurationSeconds:        duration,
	}

	pdfPath := "ciotx-report.pdf"
	jsonPath := "ciotx-findings.json"

	if err := report.WritePDF(findings, stats, targetDir, pdfPath); err != nil {
		fmt.Fprintf(os.Stderr, "  [!] Failed to write PDF report: %v\n", err)
	}
	if err := report.WriteJSON(findings, jsonPath); err != nil {
		fmt.Fprintf(os.Stderr, "  [!] Failed to write JSON findings: %v\n", err)
	}

	// ── Summary ───────────────────────────────────────────────────────
	fmt.Printf("  [3/3] Done.\n\n")
	fmt.Println(strings.Repeat("─", 56))

	if len(findings) == 0 {
		fmt.Println("  [+] No vulnerabilities found.")
	} else {
		counts := map[string]int{}
		for _, f := range findings {
			counts[f.Severity]++
		}
		fmt.Printf("  [!] %d vulnerabilities found:\n", len(findings))
		if counts["Critical"] > 0 {
			fmt.Printf("      %d Critical\n", counts["Critical"])
		}
		if counts["High"] > 0 {
			fmt.Printf("      %d High\n", counts["High"])
		}
		if counts["Medium"] > 0 {
			fmt.Printf("      %d Medium\n", counts["Medium"])
		}
		if counts["Low"] > 0 {
			fmt.Printf("      %d Low\n", counts["Low"])
		}
	}

	fmt.Printf("\n  Report    : %s\n", absPath(pdfPath))
	fmt.Printf("  Scan time : %.1fs\n", duration)
	if scanResp.Stats.EstimatedCostUSD > 0 {
		fmt.Printf("  Cost      : $%.4f\n", scanResp.Stats.EstimatedCostUSD)
	}
	fmt.Println(strings.Repeat("─", 56))
	fmt.Println()

	return 0
}

// =====================================================================
// ciotx status
// =====================================================================

func cmdStatus() int {
	cfg, err := config.Load()
	if err != nil || !cfg.IsAuthenticated() {
		fmt.Println("\n[!] Not authenticated. Run 'ciotx auth login' first.")
		return 1
	}

	client := api.NewClient(APIEndpoint, cfg.LicenseKey, Version)
	status, err := client.Status()
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n[!] %v\n", err)
		return 1
	}

	fmt.Println()
	fmt.Println(strings.Repeat("─", 50))
	fmt.Println("  ciotx  Account Status")
	fmt.Println(strings.Repeat("─", 50))
	fmt.Printf("  Plan         : %s\n", status.Plan)
	fmt.Printf("  Organization : %s\n", status.Organization)
	if status.MaxScansPerMonth < 0 {
		fmt.Printf("  Scans used   : unlimited (operator)\n")
	} else {
		fmt.Printf("  Scans used   : %d / %d  this month\n",
			status.ScansThisMonth, status.MaxScansPerMonth)
	}
	activeStr := "active"
	if !status.IsActive {
		activeStr = "revoked"
	}
	fmt.Printf("  Status       : %s\n", activeStr)
	if status.ExpiresAt != nil {
		fmt.Printf("  Expires      : %s\n", *status.ExpiresAt)
	} else {
		fmt.Printf("  Expires      : never\n")
	}
	fmt.Println(strings.Repeat("─", 50))
	fmt.Println()
	return 0
}

// =====================================================================
// ciotx history
// =====================================================================

func cmdHistory(limit int) int {
	cfg, err := config.Load()
	if err != nil || !cfg.IsAuthenticated() {
		fmt.Println("\n[!] Not authenticated. Run 'ciotx auth login' first.")
		return 1
	}

	client := api.NewClient(APIEndpoint, cfg.LicenseKey, Version)
	hist, err := client.History(limit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n[!] %v\n", err)
		return 1
	}

	fmt.Println()
	fmt.Println(strings.Repeat("─", 66))
	fmt.Println("  ciotx  Scan History")
	fmt.Println(strings.Repeat("─", 66))

	if len(hist.Records) == 0 {
		fmt.Println("  No scans recorded yet.")
		fmt.Println(strings.Repeat("─", 66))
		fmt.Println()
		return 0
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "  #\tDATE\tFINDINGS\tCRITICAL\tHIGH\tDURATION")
	for i, rec := range hist.Records {
		dur := formatDurationMS(rec.DurationMS)
		fmt.Fprintf(w, "  %d\t%s\t%d\t%d\t%d\t%s\n",
			i+1, rec.CreatedAt,
			rec.FindingsCount, rec.CriticalCount, rec.HighCount,
			dur,
		)
	}
	w.Flush()

	fmt.Println(strings.Repeat("─", 66))
	if len(hist.Records) == limit {
		fmt.Printf("  Showing last %d scans. Use --limit N to show more (max 50).\n", limit)
	} else {
		fmt.Printf("  Showing all %d scan(s).\n", len(hist.Records))
	}
	fmt.Println()
	return 0
}

func formatDurationMS(ms int64) string {
	d := time.Duration(ms) * time.Millisecond
	if d < time.Minute {
		return fmt.Sprintf("%.0fs", d.Seconds())
	}
	return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
}

func printHelp() {
	fmt.Printf(`
  ciotx — Security Auditor

  Usage:
    ciotx auth login             Authenticate with your license key
    ciotx scan .                 Scan the current directory
    ciotx scan /path/to/repo     Scan a specific directory
    ciotx status                 Show plan, quota, and account status
    ciotx history                Show recent scan history
    ciotx history --limit 20     Show up to 20 recent scans (max 50)
    ciotx version                Print version and build info

  Get your license key at %s
`, WebsiteURL)
}

func absPath(p string) string {
	abs, _ := filepath.Abs(p)
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
