package handlers

import (
	"testing"

	"github.com/iam-orsu/ciotx/server/internal/types"
)

// ──────────────────────────────────────────────────────────────────────────────
// verifyFindings
// ──────────────────────────────────────────────────────────────────────────────

func TestVerifyFindings_GoodFinding(t *testing.T) {
	findings := []*types.Finding{
		{File: "main.go", CWE: "CWE-89", LineStart: 2, LineEnd: 2, Evidence: "db.Exec(query)"},
	}
	filesContent := map[string][]string{
		"main.go": {"package main", `db.Exec(query)`, ""},
	}
	verified, dropped := verifyFindings(findings, filesContent)
	if dropped != 0 {
		t.Errorf("expected 0 dropped, got %d", dropped)
	}
	if len(verified) != 1 {
		t.Fatalf("expected 1 verified, got %d", len(verified))
	}
	if verified[0].LineStart != 2 {
		t.Errorf("LineStart = %d, want 2", verified[0].LineStart)
	}
}

func TestVerifyFindings_HallucinatedFile(t *testing.T) {
	findings := []*types.Finding{
		{File: "ghost.go", CWE: "CWE-89", LineStart: 1, LineEnd: 1, Evidence: "something"},
	}
	filesContent := map[string][]string{}
	_, dropped := verifyFindings(findings, filesContent)
	if dropped != 1 {
		t.Errorf("expected 1 dropped (file not in payload), got %d", dropped)
	}
}

func TestVerifyFindings_EmptyEvidence(t *testing.T) {
	findings := []*types.Finding{
		{File: "main.go", CWE: "CWE-89", LineStart: 1, LineEnd: 1, Evidence: ""},
	}
	filesContent := map[string][]string{
		"main.go": {"package main"},
	}
	_, dropped := verifyFindings(findings, filesContent)
	if dropped != 1 {
		t.Errorf("expected 1 dropped (empty evidence), got %d", dropped)
	}
}

func TestVerifyFindings_LineCorrection(t *testing.T) {
	// LLM reports wrong line; evidence exists elsewhere in the file.
	findings := []*types.Finding{
		{File: "app.go", CWE: "CWE-78", LineStart: 1, LineEnd: 1, Evidence: "os.Exec(cmd)"},
	}
	filesContent := map[string][]string{
		"app.go": {"package main", "func f() {", "    os.Exec(cmd)", "}"},
	}
	verified, dropped := verifyFindings(findings, filesContent)
	if dropped != 0 {
		t.Errorf("expected 0 dropped, got %d", dropped)
	}
	if len(verified) != 1 {
		t.Fatalf("expected 1 verified, got %d", len(verified))
	}
	// Should have corrected line to 3 (1-indexed)
	if verified[0].LineStart != 3 {
		t.Errorf("corrected LineStart = %d, want 3", verified[0].LineStart)
	}
}

func TestVerifyFindings_Deduplication(t *testing.T) {
	// Two identical findings (same file, CWE, line) — only one should survive.
	findings := []*types.Finding{
		{File: "main.go", CWE: "CWE-89", LineStart: 2, LineEnd: 2, Evidence: "db.Exec(query)"},
		{File: "main.go", CWE: "CWE-89", LineStart: 2, LineEnd: 2, Evidence: "db.Exec(query)"},
	}
	filesContent := map[string][]string{
		"main.go": {"package main", `db.Exec(query)`, ""},
	}
	verified, _ := verifyFindings(findings, filesContent)
	if len(verified) != 1 {
		t.Errorf("expected 1 after dedup, got %d", len(verified))
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// extractFilesContent
// ──────────────────────────────────────────────────────────────────────────────

func TestExtractFilesContent_Basic(t *testing.T) {
	payload := "===== FILE: main.go (3 lines) =====\n" +
		"0001 | package main\n" +
		"0002 | func main() {}\n" +
		"0003 | \n"

	chunks := []ChunkPayload{{ChunkID: 1, Payload: payload}}
	result := extractFilesContent(chunks)

	lines, ok := result["main.go"]
	if !ok {
		t.Fatal("expected main.go in result")
	}
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
	if lines[0] != "package main" {
		t.Errorf("lines[0] = %q, want %q", lines[0], "package main")
	}
	if lines[1] != "func main() {}" {
		t.Errorf("lines[1] = %q, want %q", lines[1], "func main() {}")
	}
}

func TestExtractFilesContent_MultipleFiles(t *testing.T) {
	payload := "===== FILE: a.go (1 lines) =====\n0001 | package a\n" +
		"===== FILE: b.go (1 lines) =====\n0001 | package b\n"
	chunks := []ChunkPayload{{ChunkID: 1, Payload: payload}}
	result := extractFilesContent(chunks)

	if _, ok := result["a.go"]; !ok {
		t.Error("expected a.go in result")
	}
	if _, ok := result["b.go"]; !ok {
		t.Error("expected b.go in result")
	}
}

func TestExtractFilesContent_MultipleChunks(t *testing.T) {
	chunks := []ChunkPayload{
		{ChunkID: 1, Payload: "===== FILE: a.go (1 lines) =====\n0001 | package a\n"},
		{ChunkID: 2, Payload: "===== FILE: b.go (1 lines) =====\n0001 | package b\n"},
	}
	result := extractFilesContent(chunks)
	if len(result) != 2 {
		t.Errorf("expected 2 files, got %d", len(result))
	}
}
