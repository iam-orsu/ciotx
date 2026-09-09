package handlers

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/iam-orsu/ciotx/server/internal/db"
)

type verifyRequest struct {
	LicenseKey string `json:"license_key"`
}

// AuthVerifyHandler validates a license key and returns a plan summary.
// Used by `ciotx auth login` to confirm a key works before saving it locally.
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

	license, authErr := resolveKey(r.Context(), req.LicenseKey)
	if authErr != nil {
		writeError(w, http.StatusUnauthorized, "invalid license key")
		return
	}

	resp := map[string]string{"status": "ok"}
	if license != nil {
		resp["plan"] = license.Plan
		resp["organization"] = license.Organization
	}
	writeJSON(w, http.StatusOK, resp)
}

// AuthMiddleware validates the Bearer token on every protected route.
// On success it attaches the License (if DB-backed) to the request context
// so downstream handlers can check quotas without a second DB round-trip.
func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}

		key := strings.TrimPrefix(authHeader, "Bearer ")
		license, err := resolveKey(r.Context(), key)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid license key")
			return
		}

		// Attach license to context (nil for master-key auth — that's fine).
		ctx := withLicense(r.Context(), license)
		next(w, r.WithContext(ctx))
	}
}

// resolveKey authenticates a key.
// Order:
//  1. DB lookup — checks active, not expired, returns *License
//  2. Master key fallback — constant-time compare, returns nil license (admin bypass)
//
// Returns a non-nil error if neither check passes.
func resolveKey(ctx context.Context, key string) (*db.License, error) {
	if key == "" {
		return nil, fmt.Errorf("empty key")
	}
	if len(key) > 128 {
		return nil, fmt.Errorf("key too long")
	}

	// ── 1. Database lookup ────────────────────────────────────────────
	license, dbErr := db.GetLicenseByKey(ctx, key)
	if dbErr == nil {
		// Key exists in DB — enforce business rules.
		if !license.IsActive {
			return nil, fmt.Errorf("license revoked")
		}
		if license.IsExpired() {
			return nil, fmt.Errorf("license expired")
		}
		return license, nil
	}
	if !errors.Is(dbErr, pgx.ErrNoRows) {
		// Genuine DB error (connection down, etc.) — log server-side, fail secure.
		fmt.Printf("[auth] db error during key lookup: %v\n", dbErr)
	}

	// ── 2. Master key fallback ────────────────────────────────────────
	// The master key bypasses DB — used for operator testing and emergency access.
	master := os.Getenv("MASTER_LICENSE_KEY")
	if master != "" && subtle.ConstantTimeCompare([]byte(key), []byte(master)) == 1 {
		return nil, nil // authenticated, but no DB record → nil license
	}

	return nil, fmt.Errorf("key not found")
}
