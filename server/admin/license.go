// Package admin provides the operator CLI for managing ciotx licenses.
// Invoked when the server binary is called with the "license" subcommand:
//
//	ciotx-server license create --org "Acme" --email admin@acme.com --plan pro --scans 500
//	ciotx-server license revoke <key>
//	ciotx-server license list
package admin

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/iam-orsu/ciotx/server/internal/db"
)

func formatDuration(ms int64) string {
	d := time.Duration(ms) * time.Millisecond
	if d < time.Minute {
		return fmt.Sprintf("%.0fs", d.Seconds())
	}
	return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
}

var validPlans = map[string]bool{
	"starter":    true,
	"pro":        true,
	"enterprise": true,
}

// RunLicenseCLI dispatches `ciotx-server license <subcommand>`.
func RunLicenseCLI(args []string) {
	if len(args) == 0 {
		printLicenseHelp()
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := db.Init(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "[admin] database error: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	switch args[0] {
	case "create":
		runCreate(ctx, args[1:])
	case "revoke":
		runRevoke(ctx, args[1:])
	case "list":
		runList(ctx)
	case "stats":
		runStats(ctx, args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n", args[0])
		printLicenseHelp()
		os.Exit(1)
	}
}

// ── create ──────────────────────────────────────────────────────────────────

func runCreate(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("license create", flag.ExitOnError)
	org := fs.String("org", "", "Organization name (required)")
	email := fs.String("email", "", "Contact email (required)")
	plan := fs.String("plan", "starter", "Plan: starter | pro | enterprise")
	scans := fs.Int("scans", 50, "Max scans per month")
	expireDays := fs.Int("expires", 0, "Days until expiry (0 = never)")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if *org == "" || *email == "" {
		fmt.Fprintln(os.Stderr, "[!] --org and --email are required")
		fs.Usage()
		os.Exit(1)
	}
	if !strings.Contains(*email, "@") {
		fmt.Fprintf(os.Stderr, "[!] invalid email address: %s\n", *email)
		os.Exit(1)
	}
	if !validPlans[*plan] {
		fmt.Fprintf(os.Stderr, "[!] invalid plan %q — must be one of: starter, pro, enterprise\n", *plan)
		os.Exit(1)
	}
	if *scans < 1 {
		fmt.Fprintln(os.Stderr, "[!] --scans must be at least 1")
		os.Exit(1)
	}

	var expiresAt *time.Time
	if *expireDays > 0 {
		t := time.Now().UTC().AddDate(0, 0, *expireDays)
		expiresAt = &t
	}

	key, err := db.CreateLicense(ctx, *org, *email, *plan, *scans, expiresAt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Failed to create license: %v\n", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println("  License created successfully!")
	fmt.Printf("  Key          : %s\n", key)
	fmt.Printf("  Organization : %s\n", *org)
	fmt.Printf("  Email        : %s\n", *email)
	fmt.Printf("  Plan         : %s\n", *plan)
	fmt.Printf("  Scans/month  : %d\n", *scans)
	if expiresAt != nil {
		fmt.Printf("  Expires      : %s\n", expiresAt.Format("2006-01-02"))
	} else {
		fmt.Printf("  Expires      : never\n")
	}
	fmt.Println()
	fmt.Println("  Share this key with the user — they run:")
	fmt.Printf("    ciotx auth login\n")
	fmt.Println()
}

// ── revoke ──────────────────────────────────────────────────────────────────

func runRevoke(ctx context.Context, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "[!] Usage: ciotx-server license revoke <license-key>")
		os.Exit(1)
	}

	key := args[0]
	if err := db.RevokeLicense(ctx, key); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Failed to revoke license: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("  [+] License revoked: %s\n", key)
}

// ── list ────────────────────────────────────────────────────────────────────

func runList(ctx context.Context) {
	licenses, err := db.ListLicenses(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Failed to list licenses: %v\n", err)
		os.Exit(1)
	}

	if len(licenses) == 0 {
		fmt.Println("  No licenses found.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "\n  KEY\tORG\tEMAIL\tPLAN\tSCANS\tACTIVE\tCREATED")
	fmt.Fprintln(w, "  ---\t---\t-----\t----\t-----\t------\t-------")

	for _, l := range licenses {
		active := "yes"
		if !l.IsActive {
			active = "REVOKED"
		}
		if l.IsExpired() {
			active = "EXPIRED"
		}
		currentMonth := time.Now().UTC().Format("2006-01")
		scansThisMonth := 0
		if l.ScanMonth == currentMonth {
			scansThisMonth = l.ScansThisMonth
		}
		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%d/%d\t%s\t%s\n",
			l.LicenseKey,
			l.Organization,
			l.Email,
			l.Plan,
			scansThisMonth, l.MaxScansPerMonth,
			active,
			l.CreatedAt.Format("2006-01-02"),
		)
	}
	w.Flush()
	fmt.Println()
}

// ── stats ────────────────────────────────────────────────────────────────────

func runStats(ctx context.Context, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "[!] Usage: ciotx-server license stats <license-key>")
		os.Exit(1)
	}

	key := args[0]
	license, err := db.GetLicenseByKey(ctx, key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] License not found: %v\n", err)
		os.Exit(1)
	}

	totalScans, lastScanAt, err := db.GetLicenseScanStats(ctx, license.ID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Failed to fetch stats: %v\n", err)
		os.Exit(1)
	}

	currentMonth := time.Now().UTC().Format("2006-01")
	scansThisMonth := 0
	if license.ScanMonth == currentMonth {
		scansThisMonth = license.ScansThisMonth
	}

	status := "active"
	if !license.IsActive {
		status = "REVOKED"
	} else if license.IsExpired() {
		status = "EXPIRED"
	}

	expiry := "never"
	if license.ExpiresAt != nil {
		expiry = license.ExpiresAt.Format("2006-01-02")
	}

	lastScan := "never"
	if lastScanAt != nil {
		lastScan = lastScanAt.Format("2006-01-02 15:04 UTC")
	}

	fmt.Println()
	fmt.Printf("  License     : %s\n", license.LicenseKey)
	fmt.Printf("  Organization: %s\n", license.Organization)
	fmt.Printf("  Email       : %s\n", license.Email)
	fmt.Printf("  Plan        : %s\n", license.Plan)
	fmt.Printf("  Status      : %s\n", status)
	fmt.Printf("  Quota       : %d / %d  this month\n", scansThisMonth, license.MaxScansPerMonth)
	fmt.Printf("  Total scans : %d  (all time)\n", totalScans)
	fmt.Printf("  Last scan   : %s\n", lastScan)
	fmt.Printf("  Expires     : %s\n", expiry)
	fmt.Printf("  Created     : %s\n", license.CreatedAt.Format("2006-01-02"))

	records, err := db.GetScanHistory(ctx, license.ID, 20)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [!] Warning: could not fetch scan history: %v\n", err)
		fmt.Println()
		return
	}
	if len(records) == 0 {
		fmt.Println()
		return
	}

	fmt.Println()
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "  DATE\tFINDINGS\tCRITICAL\tHIGH\tDURATION\tVERSION")
	fmt.Fprintln(w, "  ────\t────────\t────────\t────\t────────\t───────")
	for _, rec := range records {
		fmt.Fprintf(w, "  %s\t%d\t%d\t%d\t%s\t%s\n",
			rec.CreatedAt.UTC().Format("2006-01-02 15:04"),
			rec.FindingsCount, rec.CriticalCount, rec.HighCount,
			formatDuration(rec.DurationMS),
			rec.ClientVersion,
		)
	}
	w.Flush()
	fmt.Println()
}

// ── help ────────────────────────────────────────────────────────────────────

func printLicenseHelp() {
	fmt.Print(`
  ciotx-server license — License Management

  Usage:
    ciotx-server license create --org <name> --email <email> [--plan <plan>] [--scans <n>] [--expires <days>]
    ciotx-server license revoke <license-key>
    ciotx-server license list
    ciotx-server license stats <license-key>

  Plans: starter (50 scans/mo) | pro (500 scans/mo) | enterprise (unlimited)

  Examples:
    ciotx-server license create --org "Acme Corp" --email sec@acme.com --plan pro --scans 500
    ciotx-server license create --org "Trial User" --email user@example.com --expires 14
    ciotx-server license revoke ciotx_abc123...
    ciotx-server license list
    ciotx-server license stats ciotx_abc123...

`)
}
