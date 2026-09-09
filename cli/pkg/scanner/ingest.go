// Package scanner handles local file ingestion, filtering, and chunking.
// This runs entirely on the user's machine — no files are sent without chunking.
package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SupportedExtensions lists all source file types ciotx will analyze.
var SupportedExtensions = map[string]bool{
	".py": true, ".js": true, ".ts": true, ".tsx": true, ".jsx": true,
	".go": true, ".rs": true, ".java": true, ".php": true, ".rb": true,
	".c": true, ".cpp": true, ".cs": true, ".sh": true, ".sql": true,
	".yaml": true, ".yml": true, ".json": true, ".html": true,
	".vue": true, ".svelte": true, ".sol": true,
}

// IgnoreDirs are directories that should never be scanned.
var IgnoreDirs = map[string]bool{
	".git": true, ".hg": true, ".svn": true, ".venv": true, "venv": true,
	"node_modules": true, "__pycache__": true, "dist": true, "build": true,
	"target": true, "bin": true, "obj": true, ".idea": true, ".vscode": true,
	".pytest_cache": true, "coverage": true, "htmlcov": true, ".tox": true,
	"vendor": true, "third_party": true, "site-packages": true, "lib": true,
	"libs": true, "bower_components": true, "packages": true, "logs": true,
	"log": true, "tmp": true, "temp": true,
}

// IgnoreFiles are specific filenames to skip.
var IgnoreFiles = map[string]bool{
	"package-lock.json": true, "yarn.lock": true, "pnpm-lock.yaml": true,
	"poetry.lock": true, "Pipfile.lock": true, "Cargo.lock": true,
}

// SourceFile holds the content and metadata for a single scanned file.
type SourceFile struct {
	RelPath   string
	AbsPath   string
	Content   string
	Lines     []string
	EstTokens int
}

// CodeChunk is a group of source files packaged for a single LLM inference call.
type CodeChunk struct {
	ChunkID     int
	Files       []*SourceFile
	TotalTokens int
	PayloadText string
}

// IngestCodebase walks the target directory and returns all scannable source files.
func IngestCodebase(rootDir string) ([]*SourceFile, error) {
	var files []*SourceFile

	err := filepath.WalkDir(rootDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable paths
		}

		if d.IsDir() {
			if IgnoreDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		if IgnoreFiles[d.Name()] {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(d.Name()))
		if !SupportedExtensions[ext] {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil // skip unreadable files
		}

		// Skip binary files (>512KB or NUL bytes in first 8KB)
		if len(content) > 512*1024 {
			return nil
		}
		sample := content
		if len(sample) > 8192 {
			sample = sample[:8192]
		}
		for _, b := range sample {
			if b == 0 {
				return nil
			}
		}

		text := string(content)
		lines := strings.Split(text, "\n")
		estTokens := max(1, len(text)/4)

		relPath, _ := filepath.Rel(rootDir, path)
		relPath = filepath.ToSlash(relPath)

		files = append(files, &SourceFile{
			RelPath:   relPath,
			AbsPath:   path,
			Content:   text,
			Lines:     lines,
			EstTokens: estTokens,
		})
		return nil
	})

	return files, err
}

// FormatNumberedFile returns a file's content with 1-indexed line numbers for LLM context.
func FormatNumberedFile(sf *SourceFile) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("===== FILE: %s (%d lines) =====\n", sf.RelPath, len(sf.Lines)))
	for i, line := range sf.Lines {
		sb.WriteString(fmt.Sprintf("%04d | %s\n", i+1, line))
	}
	return sb.String()
}

// PartitionChunks splits source files into LLM-sized chunks.
func PartitionChunks(files []*SourceFile, targetTokens int) []*CodeChunk {
	var chunks []*CodeChunk
	var current []*SourceFile
	currentTokens := 0
	chunkID := 1

	flush := func() {
		if len(current) == 0 {
			return
		}
		var header strings.Builder
		header.WriteString("FILES IN THIS CHUNK:\n")
		for _, f := range current {
			header.WriteString(fmt.Sprintf("- %s (%d lines)\n", f.RelPath, len(f.Lines)))
		}
		header.WriteString("\n")

		var payload strings.Builder
		payload.WriteString(header.String())
		for _, f := range current {
			payload.WriteString(FormatNumberedFile(f))
			payload.WriteString("\n\n")
		}

		chunks = append(chunks, &CodeChunk{
			ChunkID:     chunkID,
			Files:       current,
			TotalTokens: currentTokens,
			PayloadText: payload.String(),
		})
		chunkID++
		current = nil
		currentTokens = 0
	}

	for _, sf := range files {
		if currentTokens+sf.EstTokens > targetTokens && len(current) > 0 {
			flush()
		}
		current = append(current, sf)
		currentTokens += sf.EstTokens
	}
	flush()

	return chunks
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
