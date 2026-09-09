// Package llm is INTERNAL to the ciotx server.
// It is completely hidden from users — zero third-party branding leaks through the API.
package llm

import (
	"bytes"
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
	modelDiscovery   = "deepseek-reasoner" // highest reasoning, lowest hallucinations
	modelAudit       = "deepseek-chat"     // fast skeptical second pass
)

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model          string      `json:"model"`
	Messages       []message   `json:"messages"`
	MaxTokens      int         `json:"max_tokens"`
	Temperature    float64     `json:"temperature"`
	ResponseFormat interface{} `json:"response_format,omitempty"`
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

// Client is the internal LLM provider client.
// Its existence and configuration are invisible to ciotx end users.
type Client struct {
	apiKey     string
	httpClient *http.Client
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

// Chat sends a request to the internal LLM provider with retry and backoff.
// All provider-specific metadata is stripped from the returned content string.
func (c *Client) Chat(model string, messages []message, jsonMode bool, maxTokens int) (string, Usage, error) {
	req := chatRequest{
		Model:       model,
		Messages:    messages,
		MaxTokens:   maxTokens,
		Temperature: 0.1,
	}
	// Reasoner does not support json_object mode
	if jsonMode && model != modelDiscovery {
		req.ResponseFormat = &responseFormat{Type: "json_object"}
	}

	body, err := json.Marshal(req)
	if err != nil {
		return "", Usage{}, err
	}

	maxRetries := 5
	for attempt := 0; attempt < maxRetries; attempt++ {
		content, usage, err := c.doRequest(body)
		if err == nil {
			return content, usage, nil
		}

		if attempt < maxRetries-1 {
			wait := time.Duration(attempt+1) * 10 * time.Second
			time.Sleep(wait)
			continue
		}
		return "", Usage{}, fmt.Errorf("analysis service temporarily unavailable after %d attempts", maxRetries)
	}
	return "", Usage{}, fmt.Errorf("analysis service unavailable")
}

func (c *Client) doRequest(body []byte) (string, Usage, error) {
	httpReq, err := http.NewRequest(http.MethodPost, providerEndpoint, bytes.NewReader(body))
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

	respBody, err := io.ReadAll(resp.Body)
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

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
