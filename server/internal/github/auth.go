// Package github is INTERNAL to the server — never referenced from CLI code.
// It wraps the GitHub REST API for the GitHub App integration.
package github

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"
)

// AppConfig holds GitHub App credentials loaded once from env at startup.
type AppConfig struct {
	AppID      string
	PrivateKey *rsa.PrivateKey
}

var (
	appOnce   sync.Once
	appConfig *AppConfig
	appErr    error
)

// App returns the parsed GitHub App config, loading it from env on first call.
// Returns an error if the required env vars are missing or malformed.
func App() (*AppConfig, error) {
	appOnce.Do(func() {
		id := os.Getenv("GITHUB_APP_ID")
		if id == "" {
			appErr = fmt.Errorf("GITHUB_APP_ID not set")
			return
		}

		// Support two formats:
		//   GITHUB_APP_PRIVATE_KEY_BASE64 — base64-encoded PEM (easy in .env)
		//   GITHUB_APP_PRIVATE_KEY        — raw PEM with literal \n (less portable)
		var pemBytes []byte
		if b64 := os.Getenv("GITHUB_APP_PRIVATE_KEY_BASE64"); b64 != "" {
			decoded, err := base64.StdEncoding.DecodeString(b64)
			if err != nil {
				appErr = fmt.Errorf("GITHUB_APP_PRIVATE_KEY_BASE64 is not valid base64: %w", err)
				return
			}
			pemBytes = decoded
		} else if raw := os.Getenv("GITHUB_APP_PRIVATE_KEY"); raw != "" {
			pemBytes = []byte(raw)
		} else {
			appErr = fmt.Errorf("GITHUB_APP_PRIVATE_KEY_BASE64 or GITHUB_APP_PRIVATE_KEY not set")
			return
		}

		key, err := parseRSAPrivateKey(pemBytes)
		if err != nil {
			appErr = fmt.Errorf("parse GitHub App private key: %w", err)
			return
		}
		appConfig = &AppConfig{AppID: id, PrivateKey: key}
	})
	return appConfig, appErr
}

func parseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	// Try PKCS8 first (GitHub's downloaded key format), then PKCS1.
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rk, ok := key.(*rsa.PrivateKey); ok {
			return rk, nil
		}
		return nil, fmt.Errorf("PKCS8 key is not RSA")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// GenerateJWT creates a GitHub App JWT valid for 10 minutes.
// GitHub requires: iat=now-60s (clock skew), exp=now+600s.
func GenerateJWT(cfg *AppConfig) (string, error) {
	now := time.Now().Unix()
	header := base64.RawURLEncoding.EncodeToString(
		[]byte(`{"alg":"RS256","typ":"JWT"}`),
	)
	payloadJSON, err := json.Marshal(map[string]interface{}{
		"iat": now - 60,
		"exp": now + 600,
		"iss": cfg.AppID,
	})
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	unsigned := header + "." + payload

	h := sha256.New()
	h.Write([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, cfg.PrivateKey, crypto.SHA256, h.Sum(nil))
	if err != nil {
		return "", fmt.Errorf("sign JWT: %w", err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// installationTokenResp is the GitHub API response for installation access tokens.
type installationTokenResp struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// GetInstallationToken exchanges the App JWT for a short-lived installation token.
// Installation tokens expire after 1 hour; callers should not cache them.
func GetInstallationToken(ctx context.Context, cfg *AppConfig, installationID int64) (string, error) {
	jwt, err := GenerateJWT(cfg)
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("https://api.github.com/app/installations/%d/access_tokens", installationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "ciotx-server/1.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request installation token: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))

	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("installation token: HTTP %d: %s", resp.StatusCode, body)
	}

	var t installationTokenResp
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&t); err != nil {
		return "", fmt.Errorf("parse installation token: %w", err)
	}
	return t.Token, nil
}
