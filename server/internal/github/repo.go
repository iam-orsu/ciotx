package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
)

const (
	// maxFileBytes is the per-file size ceiling. Files larger than this are
	// almost always minified bundles or generated files — skip them.
	maxFileBytes = 2 * 1024 * 1024 // 2 MB per file

	// maxCodebaseBytes is the total scannable-source ceiling per scan.
	// When hit, scanning stops and FetchRepoFiles signals sizeLimited=true
	// so the caller can surface a "partial scan" status to the user.
	maxCodebaseBytes = 200 * 1024 * 1024 // 200 MB total
)

// supportedExtensions mirrors cli/pkg/scanner/ingest.go SupportedExtensions.
var supportedExtensions = map[string]bool{
	".py": true, ".js": true, ".ts": true, ".tsx": true, ".jsx": true,
	".go": true, ".rs": true, ".java": true, ".php": true, ".rb": true,
	".c": true, ".cpp": true, ".cs": true, ".sh": true, ".sql": true,
	".yaml": true, ".yml": true, ".json": true, ".html": true,
	".vue": true, ".svelte": true, ".sol": true,
}

// ignoreDirs mirrors cli/pkg/scanner/ingest.go IgnoreDirs.
var ignoreDirs = map[string]bool{
	".git": true, ".hg": true, "node_modules": true, "__pycache__": true,
	"dist": true, "build": true, "target": true, "bin": true, "obj": true,
	"vendor": true, "third_party": true, "site-packages": true,
}

// ignoreFiles mirrors cli/pkg/scanner/ingest.go IgnoreFiles.
var ignoreFiles = map[string]bool{
	"package-lock.json": true, "yarn.lock": true, "pnpm-lock.yaml": true,
	"poetry.lock": true, "Pipfile.lock": true, "Cargo.lock": true,
}

// RepoFile is a single source file fetched from GitHub.
type RepoFile struct {
	Path    string
	Content string // decoded text content
	SHA     string // blob SHA (needed for file update API)
}

// treeEntry is one item in a GitHub recursive tree response.
type treeEntry struct {
	Path string `json:"path"`
	Type string `json:"type"` // "blob" or "tree"
	SHA  string `json:"sha"`
	Size int    `json:"size"`
	URL  string `json:"url"`
}

type treeResponse struct {
	Tree     []treeEntry `json:"tree"`
	Truncated bool       `json:"truncated"`
}

// FetchRepoFiles returns all scannable source files from a repo at a given commit SHA.
// sizeLimited is true when scanning stopped early because the repo hit maxCodebaseBytes
// OR because GitHub's own recursive tree API truncated the entry list (>100k files).
// In both cases the returned files are the portion that was scanned.
func FetchRepoFiles(ctx context.Context, token, owner, repo, sha string) (files []*RepoFile, sizeLimited bool, err error) {
	// Step 1: get the full recursive tree.
	treeURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/git/trees/%s?recursive=1", owner, repo, sha)
	treeBody, err := ghGet(ctx, token, treeURL)
	if err != nil {
		return nil, false, fmt.Errorf("fetch repo tree: %w", err)
	}

	var tree treeResponse
	if err := json.Unmarshal(treeBody, &tree); err != nil {
		return nil, false, fmt.Errorf("parse repo tree: %w", err)
	}

	// GitHub truncates recursive tree responses at 100,000 entries.
	if tree.Truncated {
		sizeLimited = true
	}

	// Step 2: filter to scannable blobs.
	var scannable []treeEntry
	totalBytes := 0
	for _, e := range tree.Tree {
		if e.Type != "blob" {
			continue
		}
		if e.Size > maxFileBytes {
			continue
		}
		if inIgnoredPath(e.Path) {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Path))
		if !supportedExtensions[ext] {
			continue
		}
		base := filepath.Base(e.Path)
		if ignoreFiles[base] {
			continue
		}
		if totalBytes+e.Size > maxCodebaseBytes {
			// Soft stop: record that we hit the ceiling and stop adding files.
			sizeLimited = true
			break
		}
		totalBytes += e.Size
		scannable = append(scannable, e)
	}

	// Step 3: fetch file contents in sequence.
	for _, e := range scannable {
		content, blobSHA, fetchErr := fetchFileContent(ctx, token, owner, repo, e.Path, sha)
		if fetchErr != nil {
			continue // skip unreadable files — don't abort the whole scan
		}
		// Skip binary content (null bytes in first 8 KB).
		sample := content
		if len(sample) > 8192 {
			sample = sample[:8192]
		}
		isBinary := false
		for _, b := range []byte(sample) {
			if b == 0 {
				isBinary = true
				break
			}
		}
		if isBinary {
			continue
		}
		files = append(files, &RepoFile{
			Path:    e.Path,
			Content: content,
			SHA:     blobSHA,
		})
	}
	return files, sizeLimited, nil
}

// fetchFileContent fetches the decoded text content of one file at a given ref.
func fetchFileContent(ctx context.Context, token, owner, repo, path, ref string) (string, string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s?ref=%s",
		owner, repo, path, ref)
	body, err := ghGet(ctx, token, url)
	if err != nil {
		return "", "", err
	}
	var resp struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
		SHA      string `json:"sha"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", "", err
	}
	if resp.Encoding != "base64" {
		return "", "", fmt.Errorf("unexpected encoding: %s", resp.Encoding)
	}
	// GitHub wraps base64 with newlines; strip them before decoding.
	cleaned := strings.ReplaceAll(resp.Content, "\n", "")
	decoded, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		return "", "", fmt.Errorf("base64 decode: %w", err)
	}
	return string(decoded), resp.SHA, nil
}

// FormatChunkPayload formats a slice of repo files into the ciotx chunk format
// that the LLM pipeline's RunDiscovery / verifyFindings / RunAudit functions expect.
// The format is identical to what cli/pkg/scanner.FormatNumberedFile produces.
func FormatChunkPayload(files []*RepoFile) string {
	var sb strings.Builder
	sb.WriteString("FILES IN THIS CHUNK:\n")
	for _, f := range files {
		lines := strings.Split(f.Content, "\n")
		sb.WriteString(fmt.Sprintf("- %s (%d lines)\n", f.Path, len(lines)))
	}
	sb.WriteString("\n")

	for _, f := range files {
		lines := strings.Split(f.Content, "\n")
		sb.WriteString(fmt.Sprintf("===== FILE: %s (%d lines) =====\n", f.Path, len(lines)))
		for i, line := range lines {
			sb.WriteString(fmt.Sprintf("%04d | %s\n", i+1, line))
		}
		sb.WriteString("\n\n")
	}
	return sb.String()
}

// PartitionFiles splits RepoFiles into chunks capped at ~30k tokens each
// (targeting the same sizes the CLI uses).
func PartitionFiles(files []*RepoFile) [][]*RepoFile {
	const targetTokens = 30_000

	var chunks [][]*RepoFile
	var current []*RepoFile
	currentTokens := 0

	for _, f := range files {
		est := max(1, len(f.Content)/4)
		if currentTokens+est > targetTokens && len(current) > 0 {
			chunks = append(chunks, current)
			current = nil
			currentTokens = 0
		}
		current = append(current, f)
		currentTokens += est
	}
	if len(current) > 0 {
		chunks = append(chunks, current)
	}
	return chunks
}

// inIgnoredPath returns true if any path component matches an ignored dir.
func inIgnoredPath(path string) bool {
	for _, part := range strings.Split(path, "/") {
		if ignoreDirs[part] {
			return true
		}
	}
	return false
}

// ghGet performs an authenticated GET against the GitHub API and returns the body.
func ghGet(ctx context.Context, token, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "ciotx-server/1.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GitHub API GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 20<<20))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("GitHub API GET %s: HTTP %d: %s", url, resp.StatusCode, body)
	}
	return body, nil
}
