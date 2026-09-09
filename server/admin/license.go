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

// ── help ────────────────────────────────────────────────────────────────────

func printLicenseHelp() {
	fmt.Print(`
  ciotx-server license — License Management

  Usage:
    ciotx-server license create --org <name> --email <email> [--plan <plan>] [--scans <n>] [--expires <days>]
    ciotx-server license revoke <license-key>
    ciotx-server license list

  Plans: starter (50 scans/mo) | pro (500 scans/mo) | enterprise (unlimited)

  Examples:
    ciotx-server license create --org "Acme Corp" --email sec@acme.com --plan pro --scans 500
    ciotx-server license create --org "Trial User" --email user@example.com --expires 14
    ciotx-server license revoke ciotx_abc123...
    ciotx-server license list

`)
}
