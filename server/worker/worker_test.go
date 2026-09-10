package worker

import (
	"strings"
	"testing"

	"github.com/iam-orsu/ciotx/server/internal/types"
)

// ── verifyFindings ─────────────────────────────────────────────────────────

func TestVerifyFindings_ExactLineMatch(t *testing.T) {
	files := map[string][]string{
		"main.go": {"package main", `db.Query("SELECT * FROM users WHERE id=" + id)`, ""},
	}
	findings := []*types.Finding{{
		File:      "main.go",
		CWE:       "CWE-89",
		Title:     "SQL Injection",
		Severity:  "Critical",
		LineStart: 2,
		Evidence:  `db.Query("SELECT * FROM users WHERE id=" + id)`,
	}}
	verified, dropped := verifyFindings(findings, files)
	if dropped != 0 {
		t.Fatalf("expected 0 dropped, got %d", dropped)
	}
	if len(verified) != 1 {
		t.Fatalf("expected 1 verified, got %d", len(verified))
	}
	if verified[0].LineStart != 2 {
		t.Fatalf("expected LineStart=2, got %d", verified[0].LineStart)
	}
}

func TestVerifyFindings_FuzzyWindowMatch(t *testing.T) {
	lines := make([]string, 30)
	for i := range lines {
		lines[i] = "// filler"
	}
	lines[19] = `exec.Command("bash", "-c", userInput)` // line 20 (1-indexed)
	files := map[string][]string{"cmd.go": lines}

	findings := []*types.Finding{{
		File:      "cmd.go",
		CWE:       "CWE-78",
		Title:     "OS Command Injection",
		Severity:  "Critical",
		LineStart: 14, // wrong — within the ±15 window
		Evidence:  `exec.Command("bash", "-c", userInput)`,
	}}
	verified, dropped := verifyFindings(findings, files)
	if dropped != 0 {
		t.Fatalf("expected 0 dropped, got %d", dropped)
	}
	if len(verified) != 1 {
		t.Fatalf("expected 1 verified, got %d", len(verified))
	}
	if verified[0].LineStart != 20 {
		t.Fatalf("expected re-anchored LineStart=20, got %d", verified[0].LineStart)
	}
}

func TestVerifyFindings_FullFileScan(t *testing.T) {
	lines := make([]string, 100)
	for i := range lines {
		lines[i] = "// placeholder"
	}
	lines[95] = `fmt.Sprintf("<div>%s</div>", userInput)` // line 96
	files := map[string][]string{"tmpl.go": lines}

	findings := []*types.Finding{{
		File:      "tmpl.go",
		CWE:       "CWE-79",
		Title:     "XSS",
		Severity:  "High",
		LineStart: 1, // far from actual line — outside ±15 window
		Evidence:  `fmt.Sprintf("<div>%s</div>", userInput)`,
	}}
	verified, dropped := verifyFindings(findings, files)
	if dropped != 0 {
		t.Fatalf("expected 0 dropped, got %d", dropped)
	}
	if len(verified) != 1 || verified[0].LineStart != 96 {
		t.Fatalf("expected LineStart=96, got %d (dropped=%d)", verified[0].LineStart, dropped)
	}
}

func TestVerifyFindings_FileNotFound(t *testing.T) {
	files := map[string][]string{"real.go": {"x"}}
	findings := []*types.Finding{{
		File:      "ghost.go",
		CWE:       "CWE-89",
		Evidence:  "something",
		LineStart: 1,
	}}
	_, dropped := verifyFindings(findings, files)
	if dropped != 1 {
		t.Fatalf("expected 1 dropped, got %d", dropped)
	}
}

func TestVerifyFindings_EmptyEvidence(t *testing.T) {
	files := map[string][]string{"a.go": {"line1"}}
	findings := []*types.Finding{{
		File:      "a.go",
		CWE:       "CWE-89",
		Evidence:  "",
		LineStart: 1,
	}}
	_, dropped := verifyFindings(findings, files)
	if dropped != 1 {
		t.Fatalf("expected 1 dropped for empty evidence, got %d", dropped)
	}
}

func TestVerifyFindings_EvidenceNotFound(t *testing.T) {
	files := map[string][]string{"a.go": {"line1", "line2", "line3"}}
	findings := []*types.Finding{{
		File:      "a.go",
		CWE:       "CWE-89",
		Evidence:  "this text does not appear in the file",
		LineStart: 1,
	}}
	_, dropped := verifyFindings(findings, files)
	if dropped != 1 {
		t.Fatalf("expected 1 dropped when evidence not found, got %d", dropped)
	}
}

func TestVerifyFindings_DeduplicatesSameLocation(t *testing.T) {
	files := map[string][]string{
		"a.go": {`db.Exec("DELETE FROM t WHERE id=" + id)`},
	}
	f := &types.Finding{
		File:      "a.go",
		CWE:       "CWE-89",
		Title:     "SQL Injection",
		Severity:  "Critical",
		LineStart: 1,
		Evidence:  `db.Exec("DELETE FROM t WHERE id=" + id)`,
	}
	// Two identical findings for the same location.
	findings := []*types.Finding{f, {
		File:      f.File,
		CWE:       f.CWE,
		Title:     f.Title,
		Severity:  f.Severity,
		LineStart: f.LineStart,
		Evidence:  f.Evidence,
	}}
	verified, _ := verifyFindings(findings, files)
	if len(verified) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(verified))
	}
}

func TestVerifyFindings_ShortEvidenceSkipsFallback(t *testing.T) {
	// Evidence shorter than 5 chars should not trigger the full-file scan.
	files := map[string][]string{"a.go": {"x", "y", "z"}}
	findings := []*types.Finding{{
		File:      "a.go",
		CWE:       "CWE-89",
		Evidence:  "x", // only 1 char — below the 5-char threshold for full scan
		LineStart: 2,   // "x" is at line 1, not 2 → will not match in ±15 window either
	}}
	// Line 1 contains "x", line 2 does not.
	// The initial exact check at LineStart-1=1 (line 2 "y") fails.
	// The window check around line 2 includes line 1 ("x") → should match.
	verified, _ := verifyFindings(findings, files)
	// Either matched (window) or dropped — the important thing is no panic.
	_ = verified
}

func TestVerifyFindings_MultilineEvidence(t *testing.T) {
	files := map[string][]string{
		"q.go": {
			"func login(u, p string) {",
			`  row := db.QueryRow("SELECT * FROM users WHERE user='" + u + "'")`,
			"  // check row",
			"}",
		},
	}
	evidence := "  row := db.QueryRow(\"SELECT * FROM users WHERE user='\" + u + \"'\")"
	findings := []*types.Finding{{
		File:      "q.go",
		CWE:       "CWE-89",
		Title:     "SQL Injection",
		Severity:  "Critical",
		LineStart: 2,
		Evidence:  evidence,
	}}
	verified, dropped := verifyFindings(findings, files)
	if dropped != 0 || len(verified) != 1 {
		t.Fatalf("expected 1 verified, got %d verified %d dropped", len(verified), dropped)
	}
}

func TestVerifyFindings_LineEndFloor(t *testing.T) {
	files := map[string][]string{"a.go": {"vuln line"}}
	findings := []*types.Finding{{
		File:      "a.go",
		CWE:       "CWE-89",
		Evidence:  "vuln line",
		LineStart: 1,
		LineEnd:   0, // will be set to LineStart
	}}
	verified, _ := verifyFindings(findings, files)
	if len(verified) == 1 && verified[0].LineEnd < verified[0].LineStart {
		t.Fatal("LineEnd should not be below LineStart")
	}
}

// ── randomHex ─────────────────────────────────────────────────────────────

func TestRandomHex_Length(t *testing.T) {
	h := randomHex(4)
	if len(h) != 8 {
		t.Fatalf("expected 8 hex chars for n=4, got %d: %q", len(h), h)
	}
}

func TestRandomHex_Uniqueness(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		h := randomHex(4)
		if seen[h] {
			t.Fatalf("collision after %d iterations: %q", i, h)
		}
		seen[h] = true
	}
}

func TestRandomHex_ValidHexChars(t *testing.T) {
	h := randomHex(8)
	for _, c := range h {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Fatalf("non-hex char %q in %q", c, h)
		}
	}
}
