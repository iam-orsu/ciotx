package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iam-orsu/ciotx/cli/pkg/types"
)

var sampleFindings = []*types.Finding{
	{
		RuleID:      "SQLI-001",
		Title:       "SQL Injection",
		Severity:    "Critical",
		CWE:         "CWE-89",
		File:        "main.go",
		LineStart:   10,
		LineEnd:     10,
		Evidence:    `db.Exec(query)`,
		DataFlow:    "user input -> query -> db.Exec",
		Description: "Unsanitized input reaches SQL sink",
		Remediation: "Use parameterized queries",
	},
	{
		RuleID:    "XSS-001",
		Title:     "Reflected XSS",
		Severity:  "High",
		CWE:       "CWE-79",
		File:      "handler.go",
		LineStart: 42,
		LineEnd:   42,
		Evidence:  `w.Write([]byte(r.FormValue("q")))`,
	},
}

// ──────────────────────────────────────────────────────────────────────────────
// WriteJSON
// ──────────────────────────────────────────────────────────────────────────────

func TestWriteJSON_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "findings.json")

	if err := WriteJSON(sampleFindings, path); err != nil {
		t.Fatalf("WriteJSON error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}

	var got []*types.Finding
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	if len(got) != len(sampleFindings) {
		t.Errorf("expected %d findings, got %d", len(sampleFindings), len(got))
	}
	if got[0].RuleID != sampleFindings[0].RuleID {
		t.Errorf("RuleID = %q, want %q", got[0].RuleID, sampleFindings[0].RuleID)
	}
}

func TestWriteJSON_EmptyFindings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "findings.json")

	if err := WriteJSON([]*types.Finding{}, path); err != nil {
		t.Fatalf("WriteJSON error: %v", err)
	}

	data, _ := os.ReadFile(path)
	if strings.TrimSpace(string(data)) == "" {
		t.Error("expected non-empty JSON output for empty findings")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// WritePDF
// ──────────────────────────────────────────────────────────────────────────────

func TestWritePDF_ProducesValidPDF(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.pdf")
	stats := &ScanStats{TotalFiles: 5, TotalLines: 300, DurationSeconds: 12.5}

	if err := WritePDF(sampleFindings, stats, "/project", path); err != nil {
		t.Fatalf("WritePDF error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}
	if len(data) < 100 {
		t.Fatalf("PDF too small (%d bytes) — likely empty or invalid", len(data))
	}
	// Every valid PDF starts with %PDF
	if !strings.HasPrefix(string(data[:5]), "%PDF-") {
		t.Errorf("output does not start with PDF magic bytes, got: %q", string(data[:8]))
	}
}

func TestWritePDF_EmptyFindings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.pdf")
	stats := &ScanStats{}

	if err := WritePDF([]*types.Finding{}, stats, "/project", path); err != nil {
		t.Fatalf("WritePDF error: %v", err)
	}

	data, _ := os.ReadFile(path)
	if len(data) < 100 {
		t.Error("PDF for empty findings is unexpectedly small")
	}
	if !strings.HasPrefix(string(data[:5]), "%PDF-") {
		t.Error("output does not look like a PDF")
	}
}

func TestWritePDF_AllSeverities(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.pdf")
	stats := &ScanStats{TotalFiles: 10, TotalLines: 5000}

	mixed := []*types.Finding{
		{Title: "Critical Issue", Severity: "Critical", File: "a.go", LineStart: 1, CWE: "CWE-89", Description: "SQL injection", Evidence: `db.Query(input)`},
		{Title: "High Issue", Severity: "High", File: "b.go", LineStart: 10, CWE: "CWE-79"},
		{Title: "Medium Issue", Severity: "Medium", File: "c.go", LineStart: 20},
		{Title: "Low Issue", Severity: "Low", File: "d.go", LineStart: 30, Remediation: "Sanitize output"},
	}

	if err := WritePDF(mixed, stats, "/repo", path); err != nil {
		t.Fatalf("WritePDF error: %v", err)
	}

	data, _ := os.ReadFile(path)
	if len(data) < 100 {
		t.Error("PDF unexpectedly small for 4 findings")
	}
}

func TestWritePDF_LongEvidence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.pdf")
	stats := &ScanStats{}

	longEvidence := strings.Repeat("x := very_long_identifier_name_to_test_wrapping(input)\n", 20)
	findings := []*types.Finding{
		{Title: "Long Evidence Test", Severity: "High", File: "big.go", LineStart: 1, Evidence: longEvidence},
	}

	if err := WritePDF(findings, stats, "/project", path); err != nil {
		t.Fatalf("WritePDF with long evidence: %v", err)
	}
}
