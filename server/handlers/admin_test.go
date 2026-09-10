package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ── helpers ────────────────────────────────────────────────────────────────

// loginAndGetCookie performs a successful admin login and returns the session cookie.
// It sets ADMIN_PASSWORD in the process.
func loginAndGetCookie(t *testing.T) *http.Cookie {
	t.Helper()
	t.Setenv("ADMIN_PASSWORD", "correct-horse-battery-staple")

	body, _ := json.Marshal(map[string]string{"password": "correct-horse-battery-staple"})
	req := httptest.NewRequest(http.MethodPost, "/admin/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	AdminLoginHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("loginAndGetCookie: want 200, got %d body=%s", res.StatusCode, w.Body.String())
	}
	for _, c := range res.Cookies() {
		if c.Name == adminCookieName {
			return c
		}
	}
	t.Fatal("loginAndGetCookie: no session cookie in response")
	return nil
}

func authReq(method, path string, body []byte, cookie *http.Cookie) *http.Request {
	var bodyReader *bytes.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	} else {
		bodyReader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, bodyReader)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:9999"
	if cookie != nil {
		req.AddCookie(cookie)
	}
	return req
}

// ── Login ──────────────────────────────────────────────────────────────────

func TestAdminLogin_Success(t *testing.T) {
	t.Setenv("ADMIN_PASSWORD", "supersecret")
	body, _ := json.Marshal(map[string]string{"password": "supersecret"})
	req := httptest.NewRequest(http.MethodPost, "/admin/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "10.0.0.1:5000"
	w := httptest.NewRecorder()
	AdminLoginHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	// Cookie must be set.
	found := false
	for _, c := range w.Result().Cookies() {
		if c.Name == adminCookieName && c.HttpOnly && c.SameSite == http.SameSiteStrictMode {
			found = true
		}
	}
	if !found {
		t.Fatal("expected HttpOnly SameSite=Strict session cookie in response")
	}
}

func TestAdminLogin_WrongPassword(t *testing.T) {
	t.Setenv("ADMIN_PASSWORD", "correct")
	body, _ := json.Marshal(map[string]string{"password": "wrong"})
	req := httptest.NewRequest(http.MethodPost, "/admin/login", bytes.NewReader(body))
	req.RemoteAddr = "10.0.0.2:5000"
	w := httptest.NewRecorder()
	AdminLoginHandler(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
}

func TestAdminLogin_NoAdminPasswordEnv(t *testing.T) {
	t.Setenv("ADMIN_PASSWORD", "") // unset
	body, _ := json.Marshal(map[string]string{"password": "anything"})
	req := httptest.NewRequest(http.MethodPost, "/admin/login", bytes.NewReader(body))
	req.RemoteAddr = "10.0.0.3:5000"
	w := httptest.NewRecorder()
	AdminLoginHandler(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d", w.Code)
	}
}

func TestAdminLogin_WrongMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/login", nil)
	req.RemoteAddr = "10.0.0.4:5000"
	w := httptest.NewRecorder()
	AdminLoginHandler(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", w.Code)
	}
}

func TestAdminLogin_EmptyBody(t *testing.T) {
	t.Setenv("ADMIN_PASSWORD", "x")
	req := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader("{bad json"))
	req.RemoteAddr = "10.0.0.5:5000"
	w := httptest.NewRecorder()
	AdminLoginHandler(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

// ── Rate limiting ──────────────────────────────────────────────────────────

func TestAdminLogin_RateLimit(t *testing.T) {
	t.Setenv("ADMIN_PASSWORD", "correct")
	// Use a unique IP to avoid interference from other tests.
	ip := "192.168.99.99:5000"

	// Reset attempts for this IP.
	loginMu.Lock()
	delete(loginAttempts, "192.168.99.99")
	loginMu.Unlock()

	badBody, _ := json.Marshal(map[string]string{"password": "wrong"})

	// 5 failed attempts.
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodPost, "/admin/login", bytes.NewReader(badBody))
		req.RemoteAddr = ip
		w := httptest.NewRecorder()
		AdminLoginHandler(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: want 401, got %d", i+1, w.Code)
		}
	}

	// 6th attempt must be locked out.
	req := httptest.NewRequest(http.MethodPost, "/admin/login", bytes.NewReader(badBody))
	req.RemoteAddr = ip
	w := httptest.NewRecorder()
	AdminLoginHandler(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("after lockout want 429, got %d", w.Code)
	}
}

// ── Logout ─────────────────────────────────────────────────────────────────

func TestAdminLogout_ClearsCookie(t *testing.T) {
	cookie := loginAndGetCookie(t)
	req := authReq(http.MethodPost, "/admin/logout", nil, cookie)
	w := httptest.NewRecorder()
	AdminLogoutHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == adminCookieName && c.MaxAge < 0 {
			return // found cleared cookie
		}
	}
	t.Fatal("expected MaxAge=-1 cookie to clear session")
}

func TestAdminLogout_WrongMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/logout", nil)
	w := httptest.NewRecorder()
	AdminLogoutHandler(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", w.Code)
	}
}

// ── Auth middleware ────────────────────────────────────────────────────────

func TestAdminAuthMiddleware_RejectsNoCookie(t *testing.T) {
	handler := AdminAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/api/stats", nil)
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
}

func TestAdminAuthMiddleware_RejectsTamperedCookie(t *testing.T) {
	handler := AdminAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/api/stats", nil)
	req.AddCookie(&http.Cookie{Name: adminCookieName, Value: "tampered.value"})
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
}

func TestAdminAuthMiddleware_RejectsExpiredCookie(t *testing.T) {
	// Generate a token with an expiry in the past.
	pastToken := signedToken(time.Now().Add(-1 * time.Hour))
	handler := AdminAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/api/stats", nil)
	req.AddCookie(&http.Cookie{Name: adminCookieName, Value: pastToken})
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
}

func TestAdminAuthMiddleware_AcceptsValidCookie(t *testing.T) {
	cookie := loginAndGetCookie(t)
	handler := AdminAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot) // sentinel
	})
	req := authReq(http.MethodGet, "/admin/api/stats", nil, cookie)
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusTeapot {
		t.Fatalf("want 418 (passed through), got %d", w.Code)
	}
}

func TestAdminAuthMiddleware_RejectsMalformedCookieValue(t *testing.T) {
	handler := AdminAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	for _, bad := range []string{"", "nodot", "a.b.c", "x."} {
		req := httptest.NewRequest(http.MethodGet, "/admin/api/stats", nil)
		req.AddCookie(&http.Cookie{Name: adminCookieName, Value: bad})
		w := httptest.NewRecorder()
		handler(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("want 401 for token %q, got %d", bad, w.Code)
		}
	}
}

// ── Create license validation ──────────────────────────────────────────────

func adminCreateRequest(t *testing.T, payload map[string]interface{}) (int, string) {
	t.Helper()
	cookie := loginAndGetCookie(t)
	body, _ := json.Marshal(payload)
	req := authReq(http.MethodPost, "/admin/api/licenses", body, cookie)
	w := httptest.NewRecorder()
	AdminAuthMiddleware(AdminCreateLicenseHandler)(w, req)
	return w.Code, w.Body.String()
}

func TestAdminCreateLicense_MissingOrg(t *testing.T) {
	code, _ := adminCreateRequest(t, map[string]interface{}{
		"organization": "", "email": "a@b.com", "plan": "pro", "max_scans_per_month": 100,
	})
	if code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", code)
	}
}

func TestAdminCreateLicense_OrgTooLong(t *testing.T) {
	code, _ := adminCreateRequest(t, map[string]interface{}{
		"organization": strings.Repeat("x", 121), "email": "a@b.com", "plan": "pro", "max_scans_per_month": 100,
	})
	if code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", code)
	}
}

func TestAdminCreateLicense_InvalidEmail(t *testing.T) {
	for _, email := range []string{"", "notanemail", strings.Repeat("x", 255) + "@x.com"} {
		code, _ := adminCreateRequest(t, map[string]interface{}{
			"organization": "Acme", "email": email, "plan": "pro", "max_scans_per_month": 100,
		})
		if code != http.StatusBadRequest {
			t.Fatalf("want 400 for email %q, got %d", email, code)
		}
	}
}

func TestAdminCreateLicense_InvalidPlan(t *testing.T) {
	code, _ := adminCreateRequest(t, map[string]interface{}{
		"organization": "Acme", "email": "a@b.com", "plan": "hacker", "max_scans_per_month": 100,
	})
	if code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", code)
	}
}

func TestAdminCreateLicense_ScansZero(t *testing.T) {
	code, _ := adminCreateRequest(t, map[string]interface{}{
		"organization": "Acme", "email": "a@b.com", "plan": "pro", "max_scans_per_month": 0,
	})
	if code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", code)
	}
}

func TestAdminCreateLicense_ScansOver100k(t *testing.T) {
	code, _ := adminCreateRequest(t, map[string]interface{}{
		"organization": "Acme", "email": "a@b.com", "plan": "pro", "max_scans_per_month": 100001,
	})
	if code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", code)
	}
}

func TestAdminCreateLicense_BadExpiryFormat(t *testing.T) {
	code, _ := adminCreateRequest(t, map[string]interface{}{
		"organization": "Acme", "email": "a@b.com", "plan": "pro",
		"max_scans_per_month": 100, "expires_at": "01/15/2030",
	})
	if code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", code)
	}
}

func TestAdminCreateLicense_PastExpiry(t *testing.T) {
	code, _ := adminCreateRequest(t, map[string]interface{}{
		"organization": "Acme", "email": "a@b.com", "plan": "pro",
		"max_scans_per_month": 100, "expires_at": "2020-01-01",
	})
	if code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", code)
	}
}

func TestAdminCreateLicense_BadJSON(t *testing.T) {
	cookie := loginAndGetCookie(t)
	req := authReq(http.MethodPost, "/admin/api/licenses", []byte("{broken"), cookie)
	w := httptest.NewRecorder()
	AdminAuthMiddleware(AdminCreateLicenseHandler)(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestAdminCreateLicense_WrongMethod(t *testing.T) {
	cookie := loginAndGetCookie(t)
	req := authReq(http.MethodPatch, "/admin/api/licenses", nil, cookie)
	w := httptest.NewRecorder()
	AdminAuthMiddleware(AdminCreateLicenseHandler)(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", w.Code)
	}
}

// ── Revoke license validation ──────────────────────────────────────────────

func TestAdminRevokeLicense_EmptyKey(t *testing.T) {
	cookie := loginAndGetCookie(t)
	req := authReq(http.MethodDelete, "/admin/api/licenses/", nil, cookie)
	w := httptest.NewRecorder()
	AdminAuthMiddleware(AdminRevokeLicenseHandler)(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestAdminRevokeLicense_KeyTooLong(t *testing.T) {
	cookie := loginAndGetCookie(t)
	longKey := strings.Repeat("x", 129)
	req := authReq(http.MethodDelete, "/admin/api/licenses/"+longKey, nil, cookie)
	w := httptest.NewRecorder()
	AdminAuthMiddleware(AdminRevokeLicenseHandler)(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestAdminRevokeLicense_WrongMethod(t *testing.T) {
	cookie := loginAndGetCookie(t)
	req := authReq(http.MethodGet, "/admin/api/licenses/somekey", nil, cookie)
	w := httptest.NewRecorder()
	AdminAuthMiddleware(AdminRevokeLicenseHandler)(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", w.Code)
	}
}

// ── Stats / Scans without DB ──────────────────────────────────────────────

func TestAdminStatsHandler_NoDB(t *testing.T) {
	// DB pool is nil in unit tests — should return 500.
	cookie := loginAndGetCookie(t)
	req := authReq(http.MethodGet, "/admin/api/stats", nil, cookie)
	w := httptest.NewRecorder()
	AdminAuthMiddleware(AdminStatsHandler)(w, req)
	// Without DB the query fails; we accept 500 here.
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("want 500 (no DB), got %d body=%s", w.Code, w.Body.String())
	}
}

func TestAdminListLicensesHandler_WrongMethod(t *testing.T) {
	cookie := loginAndGetCookie(t)
	req := authReq(http.MethodPut, "/admin/api/licenses", nil, cookie)
	w := httptest.NewRecorder()
	AdminAuthMiddleware(AdminListLicensesHandler)(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", w.Code)
	}
}

func TestAdminScansHandler_WrongMethod(t *testing.T) {
	cookie := loginAndGetCookie(t)
	req := authReq(http.MethodPost, "/admin/api/scans", nil, cookie)
	w := httptest.NewRecorder()
	AdminAuthMiddleware(AdminScansHandler)(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", w.Code)
	}
}

// ── UI handler ────────────────────────────────────────────────────────────

func TestAdminUIHandler_ServesHTML(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	w := httptest.NewRecorder()
	AdminUIHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("want text/html, got %q", ct)
	}
	if !strings.Contains(w.Body.String(), "ciotx Admin") {
		t.Fatal("expected HTML to contain 'ciotx Admin'")
	}
	// Security headers
	if w.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("expected X-Frame-Options: DENY")
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("expected X-Content-Type-Options: nosniff")
	}
}

// ── remoteIP extraction ───────────────────────────────────────────────────

func TestRemoteIP_FromLoopback(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.5")
	ip := remoteIP(req)
	if ip != "203.0.113.5" {
		t.Fatalf("want client IP from XFF, got %q", ip)
	}
}

func TestRemoteIP_FromPublicRemote(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.99:1234"
	req.Header.Set("X-Forwarded-For", "evil.attacker.ip")
	ip := remoteIP(req)
	// XFF should be ignored for public RemoteAddr.
	if ip != "203.0.113.99" {
		t.Fatalf("want RemoteAddr IP, got %q", ip)
	}
}

// ── HMAC token internals ──────────────────────────────────────────────────

func TestSignedToken_ValidAndExpired(t *testing.T) {
	future := signedToken(time.Now().Add(1 * time.Hour))
	if !verifyToken(future) {
		t.Fatal("future token should be valid")
	}
	past := signedToken(time.Now().Add(-1 * time.Hour))
	if verifyToken(past) {
		t.Fatal("past token should be invalid")
	}
}

func TestSignedToken_TamperedPayload(t *testing.T) {
	token := signedToken(time.Now().Add(1 * time.Hour))
	parts := strings.SplitN(token, ".", 2)
	tampered := "deadbeef." + parts[1]
	if verifyToken(tampered) {
		t.Fatal("tampered payload should not verify")
	}
}

func TestSignedToken_TamperedSignature(t *testing.T) {
	token := signedToken(time.Now().Add(1 * time.Hour))
	parts := strings.SplitN(token, ".", 2)
	tampered := parts[0] + ".aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if verifyToken(tampered) {
		t.Fatal("tampered sig should not verify")
	}
}

func TestSignedToken_MissingDot(t *testing.T) {
	if verifyToken("nodot") {
		t.Fatal("no-dot token should not verify")
	}
}

func TestSignedToken_EmptyString(t *testing.T) {
	if verifyToken("") {
		t.Fatal("empty token should not verify")
	}
}
