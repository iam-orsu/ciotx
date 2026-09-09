package handlers

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
)

type verifyRequest struct {
	LicenseKey string `json:"license_key"`
}

// AuthVerifyHandler validates a user's license key.
// Phase 1: uses MASTER_LICENSE_KEY env var for simple validation.
// Phase 2: will validate against PostgreSQL database with plan enforcement.
func AuthVerifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1024))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	var req verifyRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request format")
		return
	}

	if !isValidKey(req.LicenseKey) {
		writeError(w, http.StatusUnauthorized, "invalid license key")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// isValidKey validates the license key using constant-time comparison to prevent timing attacks.
// Phase 1: exact match against MASTER_LICENSE_KEY environment variable only.
// Phase 2: will validate against PostgreSQL license keys table with plan enforcement.
func isValidKey(key string) bool {
	if key == "" {
		return false
	}
	master := os.Getenv("MASTER_LICENSE_KEY")
	if master == "" {
		// No master key configured — deny all (fail-secure, not fail-open)
		return false
	}
	// Constant-time comparison prevents timing side-channel attacks
	return subtle.ConstantTimeCompare([]byte(key), []byte(master)) == 1
	// TODO Phase 2: validate against database with plan enforcement
}

// AuthMiddleware validates the Bearer token on protected routes.
func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}

		key := strings.TrimPrefix(authHeader, "Bearer ")
		if !isValidKey(key) {
			writeError(w, http.StatusUnauthorized, "invalid license key")
			return
		}

		next(w, r)
	}
}
