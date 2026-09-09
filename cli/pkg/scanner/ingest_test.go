package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ──────────────────────────────────────────────────────────────────────────────
// FormatNumberedFile
// ──────────────────────────────────────────────────────────────────────────────

func TestFormatNumberedFile_LineNumbers(t *testing.T) {
	sf := &SourceFile{
		RelPath: "main.go",
		Lines:   []string{"package main", "func main() {}"},
	}
	out := FormatNumberedFile(sf)

	if !strings.Contains(out, "===== FILE: main.go (2 lines) =====") {
		t.Errorf("missing file header in output:\n%s", out)
	}
	if !strings.Contains(out, "0001 | package main") {
		t.Errorf("missing line 1 in output:\n%s", out)
	}
	if !strings.Contains(out, "0002 | func main() {}") {
		t.Errorf("missing line 2 in output:\n%s", out)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// PartitionChunks
// ──────────────────────────────────────────────────────────────────────────────

func TestPartitionChunks_SingleChunk(t *testing.T) {
	files := []*SourceFile{
		{RelPath: "a.go", Lines: []string{"a"}, EstTokens: 100},
		{RelPath: "b.go", Lines: []string{"b"}, EstTokens: 100},
	}
	chunks := PartitionChunks(files, 10_000)
	if len(chunks) != 1 {
		t.Errorf("expected 1 chunk, got %d", len(chunks))
	}
	if chunks[0].ChunkID != 1 {
		t.Errorf("ChunkID = %d, want 1", chunks[0].ChunkID)
	}
}

func TestPartitionChunks_MultiChunk(t *testing.T) {
	files := []*SourceFile{
		{RelPath: "a.go", Lines: []string{"a"}, EstTokens: 8000},
		{RelPath: "b.go", Lines: []string{"b"}, EstTokens: 8000},
		{RelPath: "c.go", Lines: []string{"c"}, EstTokens: 8000},
	}
	chunks := PartitionChunks(files, 10_000)
	if len(chunks) < 2 {
		t.Errorf("expected at least 2 chunks for oversized input, got %d", len(chunks))
	}
	// Verify chunk IDs are sequential starting from 1
	for i, c := range chunks {
		if c.ChunkID != i+1 {
			t.Errorf("chunks[%d].ChunkID = %d, want %d", i, c.ChunkID, i+1)
		}
	}
}

func TestPartitionChunks_Empty(t *testing.T) {
	chunks := PartitionChunks(nil, 10_000)
	if len(chunks) != 0 {
		t.Errorf("expected 0 chunks for empty input, got %d", len(chunks))
	}
}

func TestPartitionChunks_PayloadContainsFileHeader(t *testing.T) {
	files := []*SourceFile{
		{RelPath: "main.go", Lines: []string{"package main"}, EstTokens: 10},
	}
	chunks := PartitionChunks(files, 10_000)
	if len(chunks) == 0 {
		t.Fatal("expected at least 1 chunk")
	}
	if !strings.Contains(chunks[0].PayloadText, "===== FILE: main.go") {
		t.Errorf("payload missing file header:\n%s", chunks[0].PayloadText)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// IngestCodebase
// ──────────────────────────────────────────────────────────────────────────────

func TestIngestCodebase_Basic(t *testing.T) {
	dir := t.TempDir()

	// Write a Go source file
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Write a file that should be ignored (lock file)
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	files, err := IngestCodebase(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 1 {
		t.Errorf("expected 1 file (lock file excluded), got %d", len(files))
	}
	if files[0].RelPath != "main.go" {
		t.Errorf("RelPath = %q, want main.go", files[0].RelPath)
	}
}

func TestIngestCodebase_IgnoresDir(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules")
	if err := os.Mkdir(nmDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nmDir, "index.js"), []byte("module.exports={}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte("console.log('hi')"), 0o644); err != nil {
		t.Fatal(err)
	}

	files, err := IngestCodebase(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range files {
		if strings.HasPrefix(f.RelPath, "node_modules") {
			t.Errorf("node_modules file should be excluded: %s", f.RelPath)
		}
	}
	if len(files) != 1 {
		t.Errorf("expected 1 file, got %d", len(files))
	}
}

func TestIngestCodebase_SkipsLargeFile(t *testing.T) {
	dir := t.TempDir()
	// Write a file larger than 512KB
	large := make([]byte, 513*1024)
	for i := range large {
		large[i] = 'a'
	}
	if err := os.WriteFile(filepath.Join(dir, "big.go"), large, 0o644); err != nil {
		t.Fatal(err)
	}

	files, err := IngestCodebase(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("expected 0 files (large file skipped), got %d", len(files))
	}
}

func TestIngestCodebase_SkipsBinaryFile(t *testing.T) {
	dir := t.TempDir()
	// Write a file with NUL bytes (binary)
	binary := []byte("package main\x00\x00\x00")
	if err := os.WriteFile(filepath.Join(dir, "binary.go"), binary, 0o644); err != nil {
		t.Fatal(err)
	}

	files, err := IngestCodebase(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("expected 0 files (binary skipped), got %d", len(files))
	}
}
