package github

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

// generateTestKey creates a small RSA key for tests (1024-bit — fast, not for prod).
func generateTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate test RSA key: %v", err)
	}
	return key
}

func encodePKCS1PEM(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

func encodePKCS8PEM(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal PKCS8: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: b,
	})
}

// ── parseRSAPrivateKey ─────────────────────────────────────────────────────

func TestParseRSAPrivateKey_PKCS1(t *testing.T) {
	key := generateTestKey(t)
	parsed, err := parseRSAPrivateKey(encodePKCS1PEM(key))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.N.Cmp(key.N) != 0 {
		t.Fatal("parsed key does not match original")
	}
}

func TestParseRSAPrivateKey_PKCS8(t *testing.T) {
	key := generateTestKey(t)
	parsed, err := parseRSAPrivateKey(encodePKCS8PEM(t, key))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.N.Cmp(key.N) != 0 {
		t.Fatal("parsed key does not match original")
	}
}

func TestParseRSAPrivateKey_Empty(t *testing.T) {
	if _, err := parseRSAPrivateKey([]byte{}); err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestParseRSAPrivateKey_NoPEM(t *testing.T) {
	if _, err := parseRSAPrivateKey([]byte("not a pem")); err == nil {
		t.Fatal("expected error for non-PEM input")
	}
}

func TestParseRSAPrivateKey_GarbageDER(t *testing.T) {
	garbage := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: []byte("not-valid-asn1"),
	})
	if _, err := parseRSAPrivateKey(garbage); err == nil {
		t.Fatal("expected error for garbage DER bytes")
	}
}

// ── GenerateJWT ───────────────────────────────────────────────────────────

func TestGenerateJWT_ThreeParts(t *testing.T) {
	key := generateTestKey(t)
	cfg := &AppConfig{AppID: "12345", PrivateKey: key}
	jwt, err := GenerateJWT(cfg)
	if err != nil {
		t.Fatalf("GenerateJWT error: %v", err)
	}
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d: %q", len(parts), jwt)
	}
	for i, p := range parts {
		if p == "" {
			t.Fatalf("JWT part %d is empty", i)
		}
	}
}

func TestGenerateJWT_NonEmptySignature(t *testing.T) {
	key := generateTestKey(t)
	cfg := &AppConfig{AppID: "99", PrivateKey: key}
	jwt, err := GenerateJWT(cfg)
	if err != nil {
		t.Fatalf("GenerateJWT error: %v", err)
	}
	// The signature (third segment) should be non-trivial (RSA-1024 produces ~171 base64 chars).
	parts := strings.Split(jwt, ".")
	if len(parts[2]) < 100 {
		t.Fatalf("signature segment looks too short: %q", parts[2])
	}
}

func TestGenerateJWT_OnlyBase64URLChars(t *testing.T) {
	key := generateTestKey(t)
	cfg := &AppConfig{AppID: "42", PrivateKey: key}
	jwt, err := GenerateJWT(cfg)
	if err != nil {
		t.Fatalf("GenerateJWT error: %v", err)
	}
	// JWT must use only base64url chars (+ dots as separators).
	for _, c := range jwt {
		if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.", c) {
			t.Fatalf("non-base64url char %q in JWT", c)
		}
	}
}

// ── SanitizeBranchName ────────────────────────────────────────────────────

func TestSanitizeBranchName(t *testing.T) {
	// SanitizeBranchName lowercases and keeps only [a-z0-9-].
	// Spaces, underscores, and punctuation are removed (not replaced with dashes).
	cases := []struct{ in, want string }{
		{"CWE-89", "cwe-89"},
		{"already-clean", "already-clean"},
		{"UPPER", "upper"},
		{"CWE 89", "cwe89"},        // spaces are dropped, not replaced
		{"CWE_79", "cwe79"},        // underscores are dropped
		{"CWE!@#$79", "cwe79"},     // special chars dropped
		{"CWE-78:cmd", "cwe-78cmd"},// colon dropped
		{"", ""},
	}
	for _, c := range cases {
		got := SanitizeBranchName(c.in)
		if got != c.want {
			t.Errorf("SanitizeBranchName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
