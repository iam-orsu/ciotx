package handlers

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/iam-orsu/ciotx/server/internal/db"
)

// ── HMAC cookie constants ──────────────────────────────────────────────────

const (
	adminCookieName = "cadmin"
	cookieTTL       = 8 * time.Hour
	cookieMaxAge    = int(8 * 60 * 60) // seconds
)

// cookieSecret is generated fresh on every process start.
// Restarting the server invalidates all existing admin sessions — intentional.
var cookieSecret = func() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("[admin] crypto/rand failed: %v", err))
	}
	return b
}()

// ── Login rate limiter ─────────────────────────────────────────────────────
// Per-IP: max 5 attempts per 15-minute window, then 15-minute lockout.

type loginAttempt struct {
	count    int
	windowAt time.Time
	lockedAt *time.Time
}

var (
	loginMu      sync.Mutex
	loginAttempts = make(map[string]*loginAttempt)
)

// loginAllowed returns true if this IP may attempt a login.
func loginAllowed(ip string) bool {
	loginMu.Lock()
	defer loginMu.Unlock()

	now := time.Now()
	a, ok := loginAttempts[ip]
	if !ok {
		loginAttempts[ip] = &loginAttempt{windowAt: now}
		return true
	}
	// Locked out?
	if a.lockedAt != nil {
		if now.Sub(*a.lockedAt) < 15*time.Minute {
			return false
		}
		// Lockout expired — reset.
		delete(loginAttempts, ip)
		loginAttempts[ip] = &loginAttempt{windowAt: now}
		return true
	}
	// New window?
	if now.Sub(a.windowAt) >= 15*time.Minute {
		loginAttempts[ip] = &loginAttempt{windowAt: now}
		return true
	}
	return true
}

// loginFailed records a failed login attempt and may lock the IP.
func loginFailed(ip string) {
	loginMu.Lock()
	defer loginMu.Unlock()

	a, ok := loginAttempts[ip]
	if !ok {
		return
	}
	a.count++
	if a.count >= 5 {
		now := time.Now()
		a.lockedAt = &now
		slog.Warn("admin login locked", "ip", ip)
	}
}

// loginSucceeded clears the attempt counter for an IP.
func loginSucceeded(ip string) {
	loginMu.Lock()
	defer loginMu.Unlock()
	delete(loginAttempts, ip)
}

// ── Cookie helpers ─────────────────────────────────────────────────────────

// signedToken builds a token: <expiry_unix_hex>.<hmac_hex>
func signedToken(expiry time.Time) string {
	payload := fmt.Sprintf("%x", expiry.Unix())
	mac := hmac.New(sha256.New, cookieSecret)
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))
	return payload + "." + sig
}

// verifyToken returns true if the token is valid and not expired.
func verifyToken(token string) bool {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return false
	}
	payload, sig := parts[0], parts[1]

	// Constant-time HMAC verification.
	mac := hmac.New(sha256.New, cookieSecret)
	mac.Write([]byte(payload))
	expected := hex.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(sig), []byte(expected)) != 1 {
		return false
	}

	// Check expiry.
	var expiryUnix int64
	if _, err := fmt.Sscanf(payload, "%x", &expiryUnix); err != nil {
		return false
	}
	return time.Now().Unix() < expiryUnix
}

func setAdminCookie(w http.ResponseWriter) {
	expiry := time.Now().Add(cookieTTL)
	token := signedToken(expiry)
	http.SetCookie(w, &http.Cookie{
		Name:     adminCookieName,
		Value:    token,
		Path:     "/admin",
		MaxAge:   cookieMaxAge,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		// Secure is set at the Nginx/TLS layer; omitting it here keeps
		// local development over HTTP functional.
	})
}

func clearAdminCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     adminCookieName,
		Value:    "",
		Path:     "/admin",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func isAdminAuthenticated(r *http.Request) bool {
	cookie, err := r.Cookie(adminCookieName)
	if err != nil {
		return false
	}
	return verifyToken(cookie.Value)
}

// remoteIP extracts the client IP, respecting X-Forwarded-For only for
// loopback/private upstreams (i.e. our own Nginx reverse proxy).
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip != nil && (ip.IsLoopback() || ip.IsPrivate()) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if candidate := strings.TrimSpace(parts[0]); candidate != "" {
				return candidate
			}
		}
	}
	return host
}

// ── Admin auth middleware ──────────────────────────────────────────────────

// AdminAuthMiddleware rejects unauthenticated requests to /admin/* (except login/logout).
func AdminAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isAdminAuthenticated(r) {
			writeError(w, http.StatusUnauthorized, "admin authentication required")
			return
		}
		next(w, r)
	}
}

// ── Handlers ──────────────────────────────────────────────────────────────

// AdminDashboardHandler serves the embedded admin SPA for GET /admin.
// Returns 302 → /admin/login for unauthenticated requests so browsers can redirect.
func AdminDashboardHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isAdminAuthenticated(r) {
		// Browsers: redirect to login page (which is the SPA itself with the login form visible).
		// API clients hitting this with no cookie get the redirect too — acceptable.
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	// Serve dashboard (same file — JS decides what to show based on session).
	AdminUIHandler(w, r)
}

// AdminUIHandler serves the raw HTML without auth check (login form is embedded).
// Only called from AdminDashboardHandler or directly for the root /admin path.
func AdminUIHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(adminHTML); err != nil {
		slog.Error("admin html write failed", "error", err)
	}
}

// AdminLoginHandler handles POST /admin/login.
func AdminLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	ip := remoteIP(r)

	if !loginAllowed(ip) {
		writeError(w, http.StatusTooManyRequests, "too many login attempts — try again later")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1024))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request format")
		return
	}

	adminPW := os.Getenv("ADMIN_PASSWORD")
	if adminPW == "" {
		slog.Error("ADMIN_PASSWORD not set — admin panel disabled")
		writeError(w, http.StatusServiceUnavailable, "admin panel not configured")
		return
	}

	if subtle.ConstantTimeCompare([]byte(req.Password), []byte(adminPW)) != 1 {
		loginFailed(ip)
		// Constant delay to prevent timing attacks giving information about password length.
		time.Sleep(200 * time.Millisecond)
		writeError(w, http.StatusUnauthorized, "invalid password")
		return
	}

	loginSucceeded(ip)
	setAdminCookie(w)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// AdminLogoutHandler handles POST /admin/logout.
func AdminLogoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	clearAdminCookie(w)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// AdminStatsHandler handles GET /admin/api/stats.
func AdminStatsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	stats, err := db.GetAdminStats(r.Context())
	if err != nil {
		slog.Error("admin stats query failed", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to retrieve stats")
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

// AdminListLicensesHandler handles GET /admin/api/licenses.
func AdminListLicensesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	licenses, err := db.ListLicenses(r.Context())
	if err != nil {
		slog.Error("admin list licenses failed", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to retrieve licenses")
		return
	}
	if licenses == nil {
		licenses = []*db.License{}
	}
	writeJSON(w, http.StatusOK, licenses)
}

type createLicenseRequest struct {
	Organization      string `json:"organization"`
	Email             string `json:"email"`
	Plan              string `json:"plan"`
	MaxScansPerMonth  int    `json:"max_scans_per_month"`
	ExpiresAt         string `json:"expires_at"` // "YYYY-MM-DD" or empty
}

// AdminCreateLicenseHandler handles POST /admin/api/licenses.
func AdminCreateLicenseHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	var req createLicenseRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request format")
		return
	}

	// Input validation.
	req.Organization = strings.TrimSpace(req.Organization)
	req.Email        = strings.TrimSpace(req.Email)
	req.Plan         = strings.TrimSpace(req.Plan)

	if req.Organization == "" || len(req.Organization) > 120 {
		writeError(w, http.StatusBadRequest, "organization must be 1–120 characters")
		return
	}
	if req.Email == "" || len(req.Email) > 254 || !strings.Contains(req.Email, "@") {
		writeError(w, http.StatusBadRequest, "valid email is required")
		return
	}
	validPlans := map[string]bool{"starter": true, "pro": true, "enterprise": true}
	if !validPlans[req.Plan] {
		writeError(w, http.StatusBadRequest, "plan must be starter, pro, or enterprise")
		return
	}
	if req.MaxScansPerMonth < 1 || req.MaxScansPerMonth > 100000 {
		writeError(w, http.StatusBadRequest, "max_scans_per_month must be between 1 and 100,000")
		return
	}

	var expiresAt *time.Time
	if req.ExpiresAt != "" {
		t, err := time.Parse("2006-01-02", req.ExpiresAt)
		if err != nil {
			writeError(w, http.StatusBadRequest, "expires_at must be YYYY-MM-DD")
			return
		}
		// Set expiry to end of day UTC.
		t = time.Date(t.Year(), t.Month(), t.Day(), 23, 59, 59, 0, time.UTC)
		if !t.After(time.Now().UTC()) {
			writeError(w, http.StatusBadRequest, "expires_at must be in the future")
			return
		}
		expiresAt = &t
	}

	key, err := db.CreateLicense(r.Context(), req.Organization, req.Email, req.Plan, req.MaxScansPerMonth, expiresAt)
	if err != nil {
		slog.Error("admin create license failed", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to create license")
		return
	}

	slog.Info("admin issued license", "org", req.Organization, "email", req.Email, "plan", req.Plan)
	writeJSON(w, http.StatusCreated, map[string]string{"license_key": key})
}

// AdminRevokeLicenseHandler handles DELETE /admin/api/licenses/{key}.
func AdminRevokeLicenseHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Extract key from URL suffix: /admin/api/licenses/<key>
	key := strings.TrimPrefix(r.URL.Path, "/admin/api/licenses/")
	key = strings.TrimSpace(key)
	if key == "" || len(key) > 128 {
		writeError(w, http.StatusBadRequest, "invalid license key")
		return
	}

	if err := db.RevokeLicense(r.Context(), key); err != nil {
		slog.Error("admin revoke license failed", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to revoke license")
		return
	}

	slog.Info("admin revoked license", "key", key[:min(len(key), 16)]+"…")
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// AdminScansHandler handles GET /admin/api/scans.
func AdminScansHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	scans, err := db.GetRecentScansAll(r.Context(), 50)
	if err != nil {
		slog.Error("admin scans query failed", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to retrieve scans")
		return
	}
	if scans == nil {
		scans = []*db.AdminScanRecord{}
	}
	writeJSON(w, http.StatusOK, scans)
}

