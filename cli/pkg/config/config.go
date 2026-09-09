// Package config manages the ciotx CLI configuration stored in ~/.ciotx/config.json.
// It holds the user's license key (the only credential the user ever interacts with).
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const configDir = ".ciotx"
const configFile = "config.json"

// Config holds persistent CLI settings.
type Config struct {
	LicenseKey string `json:"license_key"`
	APIEndpoint string `json:"api_endpoint"` // Injected at build time via ldflags
}

// configPath returns the absolute path to ~/.ciotx/config.json
func configPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(home, configDir, configFile), nil
}

// Load reads the config from disk. Returns empty Config if not found.
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

// Save writes the config to disk at ~/.ciotx/config.json
func Save(cfg *Config) error {
	path, err := configPath()
	if err != nil {
		return err
	}

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
