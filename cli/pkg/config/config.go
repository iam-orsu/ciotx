// Package config manages the ciotx CLI configuration stored in ~/.ciotx/config.json.
// It holds ONLY the user's license key — the one credential the user interacts with.
// The API endpoint is compiled in via ldflags and is NOT user-configurable.
// This is intentional: users must not be able to redirect traffic to a third-party server.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	configDir  = ".ciotx"
	configFile = "config.json"
)

// Config holds persistent CLI settings.
// Deliberately minimal — only what the user legitimately needs to store.
type Config struct {
	LicenseKey string `json:"license_key"`
}

// configPath returns the absolute path to ~/.ciotx/config.json
func configPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(home, configDir, configFile), nil
}

// Load reads the config from disk. Returns an empty Config if not yet authenticated.
func Load() (*Config, error) {
	path, err := configPath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &Config{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &cfg, nil
}

// Save writes the config to disk at ~/.ciotx/config.json with restrictive permissions.
func Save(cfg *Config) error {
	path, err := configPath()
	if err != nil {
		return err
	}

	// 0700 on dir: only owner can list it. 0600 on file: only owner can read/write.
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

// IsAuthenticated returns true if a license key is stored.
func (c *Config) IsAuthenticated() bool {
	return c.LicenseKey != ""
}
