package github

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// GetDefaultBranchSHA returns the HEAD commit SHA of the repo's default branch.
func GetDefaultBranchSHA(ctx context.Context, token, owner, repo, branch string) (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/branches/%s", owner, repo, branch)
	body, err := ghGet(ctx, token, url)
	if err != nil {
		return "", err
	}
	var resp struct {
		Commit struct {
			SHA string `json:"sha"`
		} `json:"commit"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", err
	}
	if resp.Commit.SHA == "" {
		return "", fmt.Errorf("empty SHA for branch %s", branch)
	}
	return resp.Commit.SHA, nil
}

// CreateBranch creates a new git ref (branch) pointing to baseSHA.
// Returns an error if the branch already exists.
func CreateBranch(ctx context.Context, token, owner, repo, branchName, baseSHA string) error {
	payload := map[string]string{
		"ref": "refs/heads/" + branchName,
		"sha": baseSHA,
	}
	return ghPost(ctx, token,
		fmt.Sprintf("https://api.github.com/repos/%s/%s/git/refs", owner, repo),
		payload, http.StatusCreated, nil)
}

// GetFileSHA returns the current blob SHA of a file on the given branch.
// This SHA is required by the GitHub file update API.
func GetFileSHA(ctx context.Context, token, owner, repo, path, branchName string) (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s?ref=%s",
		owner, repo, path, branchName)
	body, err := ghGet(ctx, token, url)
	if err != nil {
		return "", err
	}
	var resp struct {
		SHA string `json:"sha"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", err
	}
	return resp.SHA, nil
}

// CommitFile creates or updates a single file on the specified branch.
// fileSHA is the current blob SHA (required for updates; empty for new files).
func CommitFile(ctx context.Context, token, owner, repo, path, branchName, commitMsg, content, fileSHA string) error {
	payload := map[string]interface{}{
		"message": commitMsg,
		"content": base64.StdEncoding.EncodeToString([]byte(content)),
		"branch":  branchName,
	}
	if fileSHA != "" {
		payload["sha"] = fileSHA
	}
	return ghPut(ctx, token,
		fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s", owner, repo, path),
		payload)
}

// OpenPR creates a pull request and returns its HTML URL.
func OpenPR(ctx context.Context, token, owner, repo, title, body, headBranch, baseBranch string) (string, error) {
	payload := map[string]interface{}{
		"title": title,
		"body":  body,
		"head":  headBranch,
		"base":  baseBranch,
	}
	var result struct {
		HTMLURL string `json:"html_url"`
	}
	if err := ghPost(ctx, token,
		fmt.Sprintf("https://api.github.com/repos/%s/%s/pulls", owner, repo),
		payload, http.StatusCreated, &result); err != nil {
		return "", err
	}
	return result.HTMLURL, nil
}

// SanitizeBranchName converts a CWE string like "CWE-89" into a valid branch segment.
func SanitizeBranchName(s string) string {
	s = strings.ToLower(s)
	var out strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			out.WriteRune(r)
		}
	}
	return out.String()
}

// ── internal HTTP helpers ──────────────────────────────────────────────────

func ghPost(ctx context.Context, token, url string, payload interface{}, expectStatus int, result interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "ciotx-server/1.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("GitHub POST %s: %w", url, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))

	if resp.StatusCode != expectStatus {
		return fmt.Errorf("GitHub POST %s: HTTP %d: %s", url, resp.StatusCode, respBody)
	}
	if result != nil {
		return json.Unmarshal(respBody, result)
	}
	return nil
}

func ghPut(ctx context.Context, token, url string, payload interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "ciotx-server/1.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("GitHub PUT %s: %w", url, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))

	// 200 (update) or 201 (create) are both success.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("GitHub PUT %s: HTTP %d: %s", url, resp.StatusCode, respBody)
	}
	return nil
}
