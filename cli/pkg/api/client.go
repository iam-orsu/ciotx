// Package api handles all communication between the ciotx CLI and the ciotx backend.
// The user's machine NEVER calls any third-party LLM service directly.
// All requests go to the ciotx API endpoint (your backend) over HTTPS.
package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/iam-orsu/ciotx/cli/pkg/types"
)

// ScanRequest is what the CLI sends to the backend.
type ScanRequest struct {
	Chunks     []ChunkPayload `json:"chunks"`
	TotalFiles int            `json:"total_files"`
	TotalLines int            `json:"total_lines"`
}

// ChunkPayload is a single code chunk sent for analysis.
type ChunkPayload struct {
	ChunkID int    `json:"chunk_id"`
	Payload string `json:"payload"`
}

// ScanResponse is what the backend returns after analysis.
type ScanResponse struct {
	Findings []*types.Finding `json:"findings"`
	Stats    ScanStats        `json:"stats"`
	Error    string           `json:"error,omitempty"`
}

// ScanStats contains scan metrics returned from the backend.
type ScanStats struct {
	HallucinationsDropped int     `json:"hallucinations_dropped"`
	FalsePositivesFiltered int   `json:"false_positives_filtered"`
	DurationSeconds       float64 `json:"duration_seconds"`
	EstimatedCostUSD      float64 `json:"estimated_cost_usd"`
}

// Client is the ciotx backend API client.
type Client struct {
	endpoint   string
	licenseKey string
	version    string
	http       *http.Client
}

// NewClient creates a new backend API client.
func NewClient(endpoint, licenseKey, version string) *Client {
	return &Client{
		endpoint:   endpoint,
		licenseKey: licenseKey,
		version:    version,
		http: &http.Client{
			Timeout: 35 * time.Minute, // Matches server WriteTimeout exactly
		},
	}
}

// Scan sends code chunks to the ciotx backend and returns confirmed findings.
func (c *Client) Scan(req *ScanRequest) (*ScanResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("prepare request: %w", err)
	}

	url := c.endpoint + "/v1/scan"
	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	// Only identifier exposed to network: the user's license key.
	// No LLM provider names, no model names, no third-party references.
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.licenseKey)
	// User-Agent is the only signal exposed — version comes from ldflags at build time
	httpReq.Header.Set("User-Agent", "ciotx/"+c.version)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("connect to ciotx backend: %w\nTip: Check your network connection or run 'ciotx auth login' to re-authenticate.", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20)) // 5 MB cap
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("authentication failed — run 'ciotx auth login' to re-authenticate")
	}
	if resp.StatusCode == http.StatusPaymentRequired {
		return nil, fmt.Errorf("scan limit reached — upgrade your plan")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("backend error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var scanResp ScanResponse
	if err := json.Unmarshal(respBody, &scanResp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	if scanResp.Error != "" {
		return nil, fmt.Errorf("scan error: %s", scanResp.Error)
	}

	return &scanResp, nil
}

// VerifyLicense checks if the provided license key is valid against the ciotx backend.
func (c *Client) VerifyLicense(key string) error {
	type verifyReq struct {
		LicenseKey string `json:"license_key"`
	}
	body, err := json.Marshal(verifyReq{LicenseKey: key})
	if err != nil {
		return fmt.Errorf("cannot prepare verification request: %w", err)
	}

	url := c.endpoint + "/v1/auth/verify"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("cannot create verification request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach ciotx servers: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return nil
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("invalid license key")
	}
	return fmt.Errorf("verification failed (HTTP %d)", resp.StatusCode)
}
