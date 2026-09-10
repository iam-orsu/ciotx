package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/iam-orsu/ciotx/server/internal/db"
)

// WebhookHandler handles POST /webhooks/github.
// Validates the HMAC-SHA256 signature, then routes by X-GitHub-Event.
func WebhookHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Read body before anything else — the HMAC signature covers the raw bytes.
	body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	// ── HMAC-SHA256 signature verification ───────────────────────────
	secret := os.Getenv("GITHUB_WEBHOOK_SECRET")
	if secret == "" {
		slog.Error("GITHUB_WEBHOOK_SECRET not set — webhook rejected")
		writeError(w, http.StatusServiceUnavailable, "webhook not configured")
		return
	}
	if !verifyWebhookSignature(body, r.Header.Get("X-Hub-Signature-256"), secret) {
		slog.Warn("webhook signature mismatch")
		writeError(w, http.StatusUnauthorized, "invalid webhook signature")
		return
	}

	event := r.Header.Get("X-GitHub-Event")
	slog.Info("github webhook", "event", event, "delivery", r.Header.Get("X-GitHub-Delivery"))

	switch event {
	case "installation":
		handleInstallationEvent(w, r, body)
	case "push":
		handlePushEvent(w, r, body)
	case "ping":
		writeJSON(w, http.StatusOK, map[string]string{"status": "pong"})
	default:
		// Acknowledge all other events so GitHub does not retry delivery.
		writeJSON(w, http.StatusOK, map[string]string{"status": "ignored"})
	}
}

// ── Installation event ─────────────────────────────────────────────────────

type installationPayload struct {
	Action string `json:"action"`
	Installation struct {
		ID      int64 `json:"id"`
		Account struct {
			Login string `json:"login"`
			Type  string `json:"type"` // "User" or "Organization"
		} `json:"account"`
	} `json:"installation"`
}

func handleInstallationEvent(w http.ResponseWriter, r *http.Request, body []byte) {
	var p installationPayload
	if err := json.Unmarshal(body, &p); err != nil {
		writeError(w, http.StatusBadRequest, "invalid installation payload")
		return
	}

	now := time.Now().UTC()
	inst := &db.GitHubInstallation{
		InstallationID: p.Installation.ID,
		AccountLogin:   p.Installation.Account.Login,
		AccountType:    p.Installation.Account.Type,
	}
	switch p.Action {
	case "deleted":
		inst.UninstalledAt = &now
	case "suspend":
		inst.SuspendedAt = &now
	case "unsuspend":
		// Clear the suspended timestamp by leaving it nil — ON CONFLICT will overwrite.
	}

	if err := db.UpsertInstallation(r.Context(), inst); err != nil {
		slog.Error("upsert installation", "id", inst.InstallationID, "error", err)
		writeError(w, http.StatusInternalServerError, "failed to record installation")
		return
	}

	slog.Info("installation", "action", p.Action,
		"id", inst.InstallationID, "account", inst.AccountLogin)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ── Push event ─────────────────────────────────────────────────────────────

type pushPayload struct {
	Ref        string `json:"ref"`   // "refs/heads/main"
	After      string `json:"after"` // HEAD SHA after push
	Repository struct {
		FullName      string `json:"full_name"`
		DefaultBranch string `json:"default_branch"`
	} `json:"repository"`
	Installation struct {
		ID int64 `json:"id"`
	} `json:"installation"`
}

func handlePushEvent(w http.ResponseWriter, r *http.Request, body []byte) {
	var p pushPayload
	if err := json.Unmarshal(body, &p); err != nil {
		writeError(w, http.StatusBadRequest, "invalid push payload")
		return
	}

	// Only scan pushes to the default branch.
	if p.Ref != "refs/heads/"+p.Repository.DefaultBranch {
		slog.Info("push skipped — non-default branch", "ref", p.Ref)
		writeJSON(w, http.StatusOK, map[string]string{"status": "ignored"})
		return
	}
	// Deleted branch push: After is 40 zeros.
	if p.After == "" || p.After == strings.Repeat("0", 40) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ignored"})
		return
	}
	if p.Installation.ID == 0 {
		writeError(w, http.StatusBadRequest, "missing installation_id in push payload")
		return
	}

	if err := db.EnqueueScanJob(r.Context(),
		p.Installation.ID,
		p.Repository.FullName,
		p.Repository.DefaultBranch,
		p.After,
	); err != nil {
		slog.Error("enqueue scan job",
			"repo", p.Repository.FullName, "sha", p.After, "error", err)
		writeError(w, http.StatusInternalServerError, "failed to enqueue scan")
		return
	}

	slog.Info("scan job enqueued",
		"repo", p.Repository.FullName, "sha", p.After)
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "queued"})
}

// ── Signature verification ─────────────────────────────────────────────────

// verifyWebhookSignature does a constant-time HMAC-SHA256 comparison.
// GitHub sends the header as "sha256=<hex-digest>".
func verifyWebhookSignature(body []byte, sigHeader, secret string) bool {
	if !strings.HasPrefix(sigHeader, "sha256=") {
		return false
	}
	gotBytes, err := hex.DecodeString(strings.TrimPrefix(sigHeader, "sha256="))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hmac.Equal(gotBytes, mac.Sum(nil))
}
