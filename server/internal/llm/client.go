// Package llm is INTERNAL to the ciotx server.
// It is completely hidden from users — zero third-party branding leaks through the API.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// internal constants — never logged, never returned to users
const (
	providerEndpoint = "https://api.deepseek.com/chat/completions"
	modelDiscovery   = "deepseek-flash" // fast discovery pass
	modelAudit       = "deepseek-flash" // fast skeptical second pass
)

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type thinkingConfig struct {
	Type string `json:"type"` // "enabled"
}

type chatRequest struct {
	Model           string          `json:"model"`
	Messages        []message       `json:"messages"`
	MaxTokens       int             `json:"max_tokens"`
	Temperature     float64         `json:"temperature"`
	ResponseFormat  interface{}     `json:"response_format,omitempty"`
	Thinking        *thinkingConfig `json:"thinking,omitempty"`
	ReasoningEffort string          `json:"reasoning_effort,omitempty"`
}

type responseFormat struct {
	Type string `json:"type"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content          string `json:"content"`
			ReasoningContent string `json:"reasoning_content"`
		} `json:"message"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		PromptTokensDetails struct {
			CachedTokens int `json:"cached_tokens"`
		} `json:"prompt_tokens_details"`
	} `json:"usage"`
}

// Usage tracks internal token consumption (for billing, not exposed to users).
type Usage struct {
	PromptTokens     int
	CompletionTokens int
	CacheHitTokens   int
	CacheMissTokens  int
}

// Pricing (USD per million tokens, off-peak baseline).
// Peak hours (Mon-Fri 01:00-04:00 and 06:00-10:00 UTC) are 2× these rates.
// Source: https://api-docs.deepseek.com/quick_start/pricing
const (
	priceDiscoveryCacheMiss = 0.66  // deepseek-v4-pro input, cache miss (off-peak)
	priceDiscoveryCacheHit  = 0.022 // deepseek-v4-pro input, cache hit  (off-peak)
	priceDiscoveryOutput    = 1.98  // deepseek-v4-pro output             (off-peak)
	priceAuditCacheMiss     = 0.15  // deepseek-flash input, cache miss   (off-peak)
	priceAuditCacheHit      = 0.003 // deepseek-flash input, cache hit    (off-peak)
	priceAuditOutput        = 0.60  // deepseek-flash output              (off-peak)
)

// CostUSD returns the estimated USD cost for a Usage at the given model's rates.
// model must be one of the model* constants exported by this package.
func CostUSD(u Usage, model string) float64 {
	const m = 1_000_000.0
	// Both discovery and audit currently use deepseek-flash; always use audit rates.
	_ = model
	return (float64(u.CacheMissTokens)*priceAuditCacheMiss+
		float64(u.CacheHitTokens)*priceAuditCacheHit)/m +
		float64(u.CompletionTokens)*priceAuditOutput/m
}

// Client is the internal LLM provider client.
// Its existence and configuration are invisible to ciotx end users.
type Client struct {
	apiKey      string
	httpClient  *http.Client
	retryDelay  time.Duration // base retry delay; 0 = default 5s (overridable in tests)
}

// NewClient creates a new internal LLM client using the server's API key from env.
func NewClient() *Client {
	return &Client{
		apiKey: os.Getenv("LLM_API_KEY"),
		httpClient: &http.Client{
			Timeout: 360 * time.Second,
		},
	}
}

// DiscoveryModel returns the internal model name used for discovery.
func DiscoveryModel() string { return modelDiscovery }

// AuditModel returns the internal model name used for audit.
func AuditModel() string { return modelAudit }

// Chat sends a request to the internal LLM provider with retry and exponential backoff.
// All provider-specific metadata is stripped from the returned content string.
// The context is propagated so the HTTP request is cancelled on timeout or client disconnect.
func (c *Client) Chat(ctx context.Context, model string, messages []message, jsonMode bool, maxTokens int) (string, Usage, error) {
	req := chatRequest{
		Model:       model,
		Messages:    messages,
		MaxTokens:   maxTokens,
		Temperature: 0.1,
	}
	if jsonMode {
		req.ResponseFormat = &responseFormat{Type: "json_object"}
	}

	body, err := json.Marshal(req)
	if err != nil {
		return "", Usage{}, err
	}

	maxRetries := 5
	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		content, usage, err := c.doRequest(ctx, body)
		if err == nil {
			return content, usage, nil
		}
		lastErr = err

		// If context was cancelled (timeout/disconnect), stop retrying immediately
		if ctx.Err() != nil {
			return "", Usage{}, ctx.Err()
		}

		// Exponential backoff: base, 2×base, 4×base, 8×base (default base = 5s)
		if attempt < maxRetries-1 {
			base := c.retryDelay
			if base == 0 {
				base = 5 * time.Second
			}
			wait := time.Duration(1<<attempt) * base
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return "", Usage{}, ctx.Err()
			}
		}
	}
	return "", Usage{}, fmt.Errorf("analysis service temporarily unavailable: %w", lastErr)
}

func (c *Client) doRequest(ctx context.Context, body []byte) (string, Usage, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, providerEndpoint, bytes.NewReader(body))
	if err != nil {
		return "", Usage{}, err
	}
	// Use generic headers to avoid fingerprinting
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	httpReq.Header.Set("User-Agent", "ciotx-server/1.0")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return "", Usage{}, fmt.Errorf("analysis backend unreachable: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10 MB cap
	if err != nil {
		return "", Usage{}, err
	}

	if resp.StatusCode != http.StatusOK {
		return "", Usage{}, fmt.Errorf("analysis error (status %d)", resp.StatusCode)
	}

	var chatResp chatResponse
	if err := json.Unmarshal(respBody, &chatResp); err != nil {
		return "", Usage{}, fmt.Errorf("analysis response parse error")
	}

	if len(chatResp.Choices) == 0 {
		return "", Usage{}, fmt.Errorf("empty analysis response")
	}

	// Reasoner puts final answer in content; reasoning is scratchpad only
	content := chatResp.Choices[0].Message.Content
	if content == "" {
		content = chatResp.Choices[0].Message.ReasoningContent
	}
	if content == "" {
		content = "{}"
	}

	u := Usage{
		PromptTokens:     chatResp.Usage.PromptTokens,
		CompletionTokens: chatResp.Usage.CompletionTokens,
		CacheHitTokens:   chatResp.Usage.PromptTokensDetails.CachedTokens,
	}
	u.CacheMissTokens = max(0, u.PromptTokens-u.CacheHitTokens)

	return content, u, nil
}

// NewMessages creates a chat message slice.
func NewMessages(system, user string) []message {
	return []message{
		{Role: "system", Content: system},
		{Role: "user", Content: user},
	}
}

