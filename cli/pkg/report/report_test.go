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
// WriteHTML
// ──────────────────────────────────────────────────────────────────────────────

func TestWriteHTML_ProducesValidHTML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.html")
	stats := &ScanStats{TotalFiles: 5, TotalLines: 300, DurationSeconds: 12.5}

	if err := WriteHTML(sampleFindings, stats, "/project", path); err != nil {
		t.Fatalf("WriteHTML error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}
	html := string(data)

	for _, must := range []string{"<!DOCTYPE html>", "<html", "SQL Injection", "Reflected XSS", "CWE-89", "ciotx"} {
		if !strings.Contains(html, must) {
			t.Errorf("HTML missing expected string %q", must)
		}
	}
}

func TestWriteHTML_EscapesUserContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.html")
	xssFindings := []*types.Finding{
		{
			Title:    `<script>alert(1)</script>`,
			Severity: "Critical",
			File:     "evil.go",
			Evidence: `<img src=x onerror=alert(1)>`,
		},
	}
	stats := &ScanStats{}
	if err := WriteHTML(xssFindings, stats, "/project", path); err != nil {
		t.Fatalf("WriteHTML error: %v", err)
	}

	data, _ := os.ReadFile(path)
	html := string(data)
	if strings.Contains(html, "<script>alert(1)</script>") {
		t.Error("HTML report contains unescaped <script> tag — XSS in report")
	}
}

func TestWriteHTML_EmptyFindings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.html")
	stats := &ScanStats{}

	if err := WriteHTML([]*types.Finding{}, stats, "/project", path); err != nil {
		t.Fatalf("WriteHTML error: %v", err)
	}

	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "No Vulnerabilities Found") {
		t.Error("expected empty-state message in HTML report")
	}
}

func TestWriteHTML_SeveritySorting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.html")
	// Low severity finding listed first — should appear after Critical in report
	unordered := []*types.Finding{
		{Title: "Low Issue", Severity: "Low", File: "a.go"},
		{Title: "Critical Issue", Severity: "Critical", File: "b.go"},
	}
	stats := &ScanStats{}
	if err := WriteHTML(unordered, stats, "/project", path); err != nil {
		t.Fatalf("WriteHTML error: %v", err)
	}

	data, _ := os.ReadFile(path)
	html := string(data)
	critIdx := strings.Index(html, "Critical Issue")
	lowIdx := strings.Index(html, "Low Issue")
	if critIdx == -1 || lowIdx == -1 {
		t.Fatal("could not find both findings in HTML")
	}
	if critIdx > lowIdx {
		t.Error("Critical finding should appear before Low finding in sorted output")
	}
}
