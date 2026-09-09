package llm

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	deepSeekAPIBase = "https://api.deepseek.com"
	// JSON mode is not supported by the reasoner model.
	ReasonerModel = "deepseek-reasoner"
	ChatModel     = "deepseek-chat"
)

// Message represents a single chat message.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatRequest is the DeepSeek API request payload.
type ChatRequest struct {
	Model          string      `json:"model"`
	Messages       []Message   `json:"messages"`
	MaxTokens      int         `json:"max_tokens"`
	Temperature    float64     `json:"temperature"`
	ResponseFormat interface{} `json:"response_format,omitempty"`
}

// ResponseFormat enables JSON output mode.
type ResponseFormat struct {
	Type string `json:"type"`
}

// ChatResponse is the DeepSeek API response.
type ChatResponse struct {
	ID      string `json:"id"`
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

// Usage tracks API cost and token consumption across the scan.
type Usage struct {
	PromptTokens     int
	CompletionTokens int
	CacheHitTokens   int
	CacheMissTokens  int
}

// Client is a resilient HTTP client for the DeepSeek LLM API.
type Client struct {
	APIKey     string
	HTTPClient *http.Client
}

// NewClient creates a new DeepSeek API client with sensible timeouts.
func NewClient(apiKey string) *Client {
	return &Client{
		APIKey: apiKey,
		HTTPClient: &http.Client{
			Timeout: 360 * time.Second, // Long timeout for deepseek-reasoner
		},
	}
}

// Chat calls the DeepSeek chat completions endpoint with retry and backoff.
// Returns the response body content string and token usage.
func (c *Client) Chat(model string, messages []Message, jsonMode bool, maxTokens int) (string, Usage, error) {
	url := deepSeekAPIBase + "/chat/completions"

	req := ChatRequest{
		Model:       model,
		Messages:    messages,
		MaxTokens:   maxTokens,
		Temperature: 0.1,
	}
	// deepseek-reasoner does NOT support json_object response format
	if jsonMode && model != ReasonerModel {
		req.ResponseFormat = &ResponseFormat{Type: "json_object"}
	}

	body, err := json.Marshal(req)
	if err != nil {
		return "", Usage{}, fmt.Errorf("marshal request: %w", err)
	}

	maxRetries := 5
	for attempt := 0; attempt < maxRetries; attempt++ {
		content, usage, err := c.doRequest(url, body)
		if err == nil {
			return content, usage, nil
		}

		// Determine if error is retryable
		var apiErr *APIError
		if errors.As(err, &apiErr) && !isRetryableStatus(apiErr.StatusCode) {
			return "", Usage{}, err
		}

		wait := time.Duration(attempt+1)*10*time.Second
		fmt.Printf("      [~] Attempt %d/%d failed: %v — retrying in %s\n", attempt+1, maxRetries, err, wait)
		time.Sleep(wait)
	}

	return "", Usage{}, fmt.Errorf("max retries (%d) exceeded calling DeepSeek API", maxRetries)
}

// doRequest performs a single HTTP call and parses the LLM response.
func (c *Client) doRequest(url string, body []byte) (string, Usage, error) {
	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", Usage{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.APIKey)

	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		// Network-level error (connection reset, timeout, etc.) — always retryable
		return "", Usage{}, fmt.Errorf("network error: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", Usage{}, fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", Usage{}, &APIError{
			StatusCode: resp.StatusCode,
			Body:       string(respBody),
		}
	}

	var chatResp ChatResponse
	if err := json.Unmarshal(respBody, &chatResp); err != nil {
		return "", Usage{}, fmt.Errorf("parse response JSON: %w", err)
	}

	if len(chatResp.Choices) == 0 {
		return "", Usage{}, fmt.Errorf("empty choices in API response")
	}

	// deepseek-reasoner puts final answer in content; reasoning_content is the scratchpad
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

// APIError represents an HTTP-level error from the DeepSeek API.
type APIError struct {
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("DeepSeek API HTTP %d: %s", e.StatusCode, e.Body)
}

func isRetryableStatus(code int) bool {
	switch code {
	case 429, 500, 502, 503, 504:
		return true
	}
	return false
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
