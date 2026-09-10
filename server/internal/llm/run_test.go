package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iam-orsu/ciotx/server/internal/types"
)

// mockLLMResponse builds the JSON the LLM provider sends back.
func mockLLMResponse(content string) []byte {
	resp := chatResponse{}
	resp.Choices = []struct {
		Message struct {
			Content          string `json:"content"`
			ReasoningContent string `json:"reasoning_content"`
		} `json:"message"`
	}{
		{Message: struct {
			Content          string `json:"content"`
			ReasoningContent string `json:"reasoning_content"`
		}{Content: content}},
	}
	resp.Usage.PromptTokens = 100
	resp.Usage.CompletionTokens = 40
	resp.Usage.PromptTokensDetails.CachedTokens = 20
	b, _ := json.Marshal(resp)
	return b
}

// newTestClient returns a Client pointed at ts with instant retry delay.
func newTestClient(ts *httptest.Server) *Client {
	return &Client{
		apiKey:     "test-key",
		httpClient: ts.Client(),
		retryDelay: time.Millisecond, // fast retries in tests
	}
}

// ── RunDiscovery ──────────────────────────────────────────────────────────────

func TestRunDiscovery_Success(t *testing.T) {
	payload := `{"findings":[{"rule_id":"SQLI-001","title":"SQL Injection","severity":"critical","cwe":"CWE-89","file":"main.go","line_start":10,"line_end":12,"evidence":"db.Exec(q)","data_flow":"user->q->db","description":"sqli","remediation":"parameterize"}]}`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(mockLLMResponse(payload))
	}))
	defer ts.Close()

	// Redirect the client to our test server by swapping the transport target.
	// We can't change providerEndpoint, so we override the transport to always
	// dial the test server regardless of the URL.
	c := newTestClient(ts)
	c.httpClient.Transport = rewriteTransport(ts.URL)

	usage := &Usage{}
	var mu nopMu
	findings, err := RunDiscovery(context.Background(), c, 1, "some code", usage, &mu)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != "Critical" {
		t.Errorf("Severity = %q, want Critical (normalized)", findings[0].Severity)
	}
	if usage.PromptTokens != 100 {
		t.Errorf("PromptTokens = %d, want 100", usage.PromptTokens)
	}
}

func TestRunDiscovery_EmptyFindings(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(mockLLMResponse(`{"findings":[]}`))
	}))
	defer ts.Close()

	c := newTestClient(ts)
	c.httpClient.Transport = rewriteTransport(ts.URL)

	var mu nopMu
	findings, err := RunDiscovery(context.Background(), c, 1, "code", &Usage{}, &mu)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestRunDiscovery_BackendError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	c := newTestClient(ts)
	c.httpClient.Transport = rewriteTransport(ts.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	var mu nopMu
	_, err := RunDiscovery(ctx, c, 1, "code", &Usage{}, &mu)
	if err == nil {
		t.Fatal("expected error on backend 500, got nil")
	}
}

// ── RunAudit ──────────────────────────────────────────────────────────────────

func TestRunAudit_EmptyInput(t *testing.T) {
	// Should return immediately without hitting the network.
	surviving, rejected, err := RunAudit(context.Background(), nil, nil, nil, &Usage{}, &nopMu{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rejected != 0 {
		t.Errorf("expected 0 rejected, got %d", rejected)
	}
	if len(surviving) != 0 {
		t.Errorf("expected 0 surviving, got %d", len(surviving))
	}
}

func TestRunAudit_ConfirmedAndRejected(t *testing.T) {
	verdicts := `{"verdicts":[{"index":0,"status":"CONFIRMED","justification":"real"},{"index":1,"status":"REJECTED","justification":"fp"}]}`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(mockLLMResponse(verdicts))
	}))
	defer ts.Close()

	c := newTestClient(ts)
	c.httpClient.Transport = rewriteTransport(ts.URL)

	findings := []*types.Finding{
		{Title: "Finding A", Severity: "High"},
		{Title: "Finding B", Severity: "Medium"},
	}
	filesContent := map[string][]string{}

	var mu nopMu
	surviving, rejected, err := RunAudit(context.Background(), c, findings, filesContent, &Usage{}, &mu)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rejected != 1 {
		t.Errorf("expected 1 rejected, got %d", rejected)
	}
	if len(surviving) != 1 {
		t.Errorf("expected 1 surviving, got %d", len(surviving))
	}
	if surviving[0].Title != "Finding A" {
		t.Errorf("wrong surviving finding: %q", surviving[0].Title)
	}
}

func TestRunAudit_RefinedSeverity(t *testing.T) {
	verdicts := `{"verdicts":[{"index":0,"status":"REFINED","refined_severity":"low","justification":"lower risk"}]}`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(mockLLMResponse(verdicts))
	}))
	defer ts.Close()

	c := newTestClient(ts)
	c.httpClient.Transport = rewriteTransport(ts.URL)

	findings := []*types.Finding{{Title: "Finding", Severity: "High"}}
	var mu nopMu
	surviving, _, err := RunAudit(context.Background(), c, findings, map[string][]string{}, &Usage{}, &mu)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(surviving) != 1 {
		t.Fatalf("expected 1 surviving, got %d", len(surviving))
	}
	if surviving[0].Severity != "Low" {
		t.Errorf("Severity = %q after refinement, want Low", surviving[0].Severity)
	}
}

func TestRunAudit_ChatError_PassThrough(t *testing.T) {
	// If the audit LLM call fails, all verified findings should pass through unchanged.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	c := newTestClient(ts)
	c.httpClient.Transport = rewriteTransport(ts.URL)

	findings := []*types.Finding{
		{Title: "Finding A", Severity: "Critical"},
		{Title: "Finding B", Severity: "High"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	var mu nopMu
	surviving, rejected, err := RunAudit(ctx, c, findings, map[string][]string{}, &Usage{}, &mu)
	if err != nil {
		t.Fatalf("unexpected error: audit failure must be non-fatal, got %v", err)
	}
	if rejected != 0 {
		t.Errorf("expected 0 rejected on audit error, got %d", rejected)
	}
	if len(surviving) != len(findings) {
		t.Errorf("expected all %d findings to pass through, got %d", len(findings), len(surviving))
	}
}

// ── Chat retry ────────────────────────────────────────────────────────────────

func TestChat_SuccessFirstAttempt(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(mockLLMResponse(`{"findings":[]}`))
	}))
	defer ts.Close()

	c := newTestClient(ts)
	c.httpClient.Transport = rewriteTransport(ts.URL)

	content, _, err := c.Chat(context.Background(), modelAudit, NewMessages("sys", "user"), false, 256)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if content == "" {
		t.Error("expected non-empty content")
	}
}

func TestChat_RetriesOnFailureThenSucceeds(t *testing.T) {
	var calls atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write(mockLLMResponse("ok"))
	}))
	defer ts.Close()

	c := newTestClient(ts)
	c.httpClient.Transport = rewriteTransport(ts.URL)

	_, _, err := c.Chat(context.Background(), modelAudit, NewMessages("s", "u"), false, 64)
	if err != nil {
		t.Fatalf("expected success after retries, got: %v", err)
	}
	if calls.Load() != 3 {
		t.Errorf("expected 3 calls (2 failures + 1 success), got %d", calls.Load())
	}
}

func TestChat_ContextCancellationStopsRetries(t *testing.T) {
	var calls atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	c := newTestClient(ts)
	c.httpClient.Transport = rewriteTransport(ts.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()

	_, _, err := c.Chat(ctx, modelAudit, NewMessages("s", "u"), false, 64)
	if err == nil {
		t.Fatal("expected error when context cancelled, got nil")
	}
	// Context must stop retries before all 5 attempts complete.
	if calls.Load() >= 5 {
		t.Errorf("context cancellation had no effect: all %d attempts ran", calls.Load())
	}
}

func TestChat_ExhaustsAllRetries(t *testing.T) {
	var calls atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	c := newTestClient(ts)
	c.httpClient.Transport = rewriteTransport(ts.URL)

	// Short context so backoff waits don't stall the test.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, _, err := c.Chat(ctx, modelAudit, NewMessages("s", "u"), false, 64)
	if err == nil {
		t.Fatal("expected error after all retries exhausted")
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

// nopMu is a no-op mutex for tests.
type nopMu struct{}

func (*nopMu) Lock()   {}
func (*nopMu) Unlock() {}

// rewriteTransport returns an http.RoundTripper that rewrites every request
// to the given base URL, so Client can reach httptest.Server even though the
// production code builds requests against providerEndpoint.
type rewriteTransport string

func (base rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req2 := req.Clone(req.Context())
	req2.URL.Host = req.URL.Host
	// Parse base URL and reuse its scheme+host.
	target, _ := http.NewRequest("GET", string(base), nil)
	req2.URL.Scheme = target.URL.Scheme
	req2.URL.Host = target.URL.Host
	return http.DefaultTransport.RoundTrip(req2)
}
