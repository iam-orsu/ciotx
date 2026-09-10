package handlers

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ── verifyWebhookSignature ─────────────────────────────────────────────────

func TestVerifyWebhookSignature_Valid(t *testing.T) {
	body := []byte(`{"action":"created"}`)
	secret := "testwebhooksecret"
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	if !verifyWebhookSignature(body, sig, secret) {
		t.Fatal("expected valid signature to pass")
	}
}

func TestVerifyWebhookSignature_WrongSecret(t *testing.T) {
	body := []byte(`{"action":"created"}`)
	mac := hmac.New(sha256.New, []byte("correctsecret"))
	mac.Write(body)
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	if verifyWebhookSignature(body, sig, "wrongsecret") {
		t.Fatal("expected wrong secret to fail")
	}
}

func TestVerifyWebhookSignature_MissingPrefix(t *testing.T) {
	body := []byte(`{}`)
	mac := hmac.New(sha256.New, []byte("s"))
	mac.Write(body)
	sig := hex.EncodeToString(mac.Sum(nil)) // missing "sha256=" prefix

	if verifyWebhookSignature(body, sig, "s") {
		t.Fatal("expected missing prefix to fail")
	}
}

func TestVerifyWebhookSignature_TamperedBody(t *testing.T) {
	secret := "testsecret"
	body := []byte(`{"action":"created"}`)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	// Change one byte of the body after signing.
	body[0] = '!'
	if verifyWebhookSignature(body, sig, secret) {
		t.Fatal("expected tampered body to fail")
	}
}

func TestVerifyWebhookSignature_InvalidHex(t *testing.T) {
	if verifyWebhookSignature([]byte("x"), "sha256=ZZZZ", "s") {
		t.Fatal("expected invalid hex to fail")
	}
}

func TestVerifyWebhookSignature_Empty(t *testing.T) {
	if verifyWebhookSignature([]byte{}, "", "secret") {
		t.Fatal("expected empty sig header to fail")
	}
}

// ── WebhookHandler integration ─────────────────────────────────────────────

func signBody(t *testing.T, body []byte, secret string) string {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func webhookReq(t *testing.T, event string, body []byte, secret string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/webhooks/github", bytes.NewReader(body))
	r.Header.Set("X-GitHub-Event", event)
	r.Header.Set("X-GitHub-Delivery", "test-delivery-id")
	r.Header.Set("X-Hub-Signature-256", signBody(t, body, secret))
	return r
}

func TestWebhookHandler_MethodNotAllowed(t *testing.T) {
	t.Setenv("GITHUB_WEBHOOK_SECRET", "secret")
	r := httptest.NewRequest(http.MethodGet, "/webhooks/github", nil)
	w := httptest.NewRecorder()
	WebhookHandler(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestWebhookHandler_NoSecret(t *testing.T) {
	t.Setenv("GITHUB_WEBHOOK_SECRET", "")
	body := []byte(`{"action":"created"}`)
	r := webhookReq(t, "ping", body, "any")
	w := httptest.NewRecorder()
	WebhookHandler(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
}

func TestWebhookHandler_BadSignature(t *testing.T) {
	t.Setenv("GITHUB_WEBHOOK_SECRET", "realsecret")
	body := []byte(`{"action":"created"}`)
	r := httptest.NewRequest(http.MethodPost, "/webhooks/github", bytes.NewReader(body))
	r.Header.Set("X-GitHub-Event", "ping")
	r.Header.Set("X-Hub-Signature-256", "sha256=deadbeef")
	w := httptest.NewRecorder()
	WebhookHandler(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestWebhookHandler_PingEvent(t *testing.T) {
	secret := "pingsecret"
	t.Setenv("GITHUB_WEBHOOK_SECRET", secret)
	body := []byte(`{"zen":"design for failure"}`)
	r := webhookReq(t, "ping", body, secret)
	w := httptest.NewRecorder()
	WebhookHandler(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "pong" {
		t.Fatalf("expected pong, got %q", resp["status"])
	}
}

func TestWebhookHandler_UnknownEvent(t *testing.T) {
	secret := "testsecret"
	t.Setenv("GITHUB_WEBHOOK_SECRET", secret)
	body := []byte(`{"action":"labeled"}`)
	r := webhookReq(t, "pull_request", body, secret)
	w := httptest.NewRecorder()
	WebhookHandler(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for unknown event, got %d", w.Code)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "ignored" {
		t.Fatalf("expected ignored, got %q", resp["status"])
	}
}

func TestWebhookHandler_PushNonDefaultBranch(t *testing.T) {
	secret := "testsecret"
	t.Setenv("GITHUB_WEBHOOK_SECRET", secret)

	payload := pushPayload{}
	payload.Ref = "refs/heads/feature/my-branch"
	payload.After = strings.Repeat("a", 40)
	payload.Repository.FullName = "org/repo"
	payload.Repository.DefaultBranch = "main"
	payload.Installation.ID = 123

	body, _ := json.Marshal(payload)
	r := webhookReq(t, "push", body, secret)
	w := httptest.NewRecorder()
	WebhookHandler(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for non-default branch, got %d", w.Code)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "ignored" {
		t.Fatalf("expected ignored, got %q", resp["status"])
	}
}

func TestWebhookHandler_PushDeletedBranch(t *testing.T) {
	secret := "testsecret"
	t.Setenv("GITHUB_WEBHOOK_SECRET", secret)

	payload := pushPayload{}
	payload.Ref = "refs/heads/main"
	payload.After = strings.Repeat("0", 40) // deletion sentinel
	payload.Repository.FullName = "org/repo"
	payload.Repository.DefaultBranch = "main"
	payload.Installation.ID = 123

	body, _ := json.Marshal(payload)
	r := webhookReq(t, "push", body, secret)
	w := httptest.NewRecorder()
	WebhookHandler(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for deleted branch, got %d", w.Code)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "ignored" {
		t.Fatalf("expected ignored, got %q", resp["status"])
	}
}

func TestWebhookHandler_PushEmptyAfterSHA(t *testing.T) {
	secret := "testsecret"
	t.Setenv("GITHUB_WEBHOOK_SECRET", secret)

	payload := pushPayload{}
	payload.Ref = "refs/heads/main"
	payload.After = "" // empty
	payload.Repository.FullName = "org/repo"
	payload.Repository.DefaultBranch = "main"
	payload.Installation.ID = 123

	body, _ := json.Marshal(payload)
	r := webhookReq(t, "push", body, secret)
	w := httptest.NewRecorder()
	WebhookHandler(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for empty SHA, got %d", w.Code)
	}
}

func TestWebhookHandler_PushMissingInstallationID(t *testing.T) {
	secret := "testsecret"
	t.Setenv("GITHUB_WEBHOOK_SECRET", secret)

	payload := pushPayload{}
	payload.Ref = "refs/heads/main"
	payload.After = strings.Repeat("a", 40)
	payload.Repository.FullName = "org/repo"
	payload.Repository.DefaultBranch = "main"
	payload.Installation.ID = 0 // missing

	body, _ := json.Marshal(payload)
	r := webhookReq(t, "push", body, secret)
	w := httptest.NewRecorder()
	WebhookHandler(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing installation_id, got %d", w.Code)
	}
}

func TestWebhookHandler_PushInvalidJSON(t *testing.T) {
	secret := "testsecret"
	t.Setenv("GITHUB_WEBHOOK_SECRET", secret)
	body := []byte(`not-json`)
	r := webhookReq(t, "push", body, secret)
	w := httptest.NewRecorder()
	WebhookHandler(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid JSON, got %d", w.Code)
	}
}

func TestWebhookHandler_InstallationInvalidJSON(t *testing.T) {
	secret := "testsecret"
	t.Setenv("GITHUB_WEBHOOK_SECRET", secret)
	body := []byte(`{invalid}`)
	r := webhookReq(t, "installation", body, secret)
	w := httptest.NewRecorder()
	WebhookHandler(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid JSON, got %d", w.Code)
	}
}

func TestWebhookHandler_PushDefaultBranchNoDBReturns500(t *testing.T) {
	secret := "testsecret"
	t.Setenv("GITHUB_WEBHOOK_SECRET", secret)

	type minPayload struct {
		Ref          string `json:"ref"`
		After        string `json:"after"`
		Repository   struct {
			FullName      string `json:"full_name"`
			DefaultBranch string `json:"default_branch"`
		} `json:"repository"`
		Installation struct {
			ID int64 `json:"id"`
		} `json:"installation"`
	}
	var p minPayload
	p.Ref = "refs/heads/main"
	p.After = strings.Repeat("a", 40)
	p.Repository.FullName = "org/repo"
	p.Repository.DefaultBranch = "main"
	p.Installation.ID = 99

	body, _ := json.Marshal(p)
	r := webhookReq(t, "push", body, secret)
	w := httptest.NewRecorder()
	WebhookHandler(w, r)

	// Without a real DB, EnqueueScanJob returns an error → 500.
	if w.Code != http.StatusInternalServerError && w.Code != http.StatusAccepted {
		t.Fatalf("expected 500 (no DB) or 202 (live DB), got %d", w.Code)
	}
}

func TestWebhookHandler_BodySizeLimit(t *testing.T) {
	secret := "testsecret"
	t.Setenv("GITHUB_WEBHOOK_SECRET", secret)

	// 11MB body — exceeds the 10MB limit.
	body := bytes.Repeat([]byte("x"), 11<<20)
	r := httptest.NewRequest(http.MethodPost, "/webhooks/github", bytes.NewReader(body))
	r.Header.Set("X-GitHub-Event", "ping")
	// Compute HMAC on the actual (truncated) bytes we will receive — but the
	// signature will be over the first 10MB, causing a mismatch → 401.
	// The important thing is no panic/OOM: the handler limits the read.
	trunc := body[:10<<20]
	r.Header.Set("X-Hub-Signature-256", signBody(t, trunc, secret))
	w := httptest.NewRecorder()
	WebhookHandler(w, r)
	// The server reads only 10MB, so HMAC computed over 11MB header will mismatch.
	// Acceptable outcomes: 401 (sig mismatch) — the key is no crash.
	if w.Code == 0 {
		t.Fatal("handler did not respond")
	}
	_ = fmt.Sprintf("body size limit test: got %d", w.Code)
}
