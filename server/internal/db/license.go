package db

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// License is a customer license record.
type License struct {
	ID               string     `json:"id"`
	LicenseKey       string     `json:"license_key"`
	Organization     string     `json:"organization"`
	Email            string     `json:"email"`
	Plan             string     `json:"plan"`
	MaxScansPerMonth int        `json:"max_scans_per_month"`
	ScansThisMonth   int        `json:"scans_this_month"`
	ScanMonth        string     `json:"scan_month"`
	IsActive         bool       `json:"is_active"`
	ExpiresAt        *time.Time `json:"expires_at"`
	CreatedAt        time.Time  `json:"created_at"`
}

// IsQuotaExceeded returns true if the license has used all its scans this calendar month.
func (l *License) IsQuotaExceeded() bool {
	currentMonth := time.Now().UTC().Format("2006-01")
	if l.ScanMonth != currentMonth {
		// Counter is from a previous month — effectively 0 scans this month.
		return false
	}
	return l.ScansThisMonth >= l.MaxScansPerMonth
}

// IsExpired returns true if the license has a set expiry date that has passed.
func (l *License) IsExpired() bool {
	if l.ExpiresAt == nil {
		return false
	}
	return time.Now().UTC().After(*l.ExpiresAt)
}

// GetLicenseByKey fetches a license by its key. Returns pgx.ErrNoRows if not found.
// Returns pgx.ErrNoRows (not a panic) when the DB pool is not initialized,
// so callers can fall through to a master-key fallback safely.
func GetLicenseByKey(ctx context.Context, key string) (*License, error) {
	if !IsAvailable() {
		return nil, pgx.ErrNoRows
	}
	row := Pool().QueryRow(ctx, `
		SELECT id, license_key, organization, email, plan,
		       max_scans_per_month, scans_this_month, scan_month,
		       is_active, expires_at, created_at
		FROM licenses
		WHERE license_key = $1
	`, key)

	var l License
	if err := row.Scan(
		&l.ID, &l.LicenseKey, &l.Organization, &l.Email, &l.Plan,
		&l.MaxScansPerMonth, &l.ScansThisMonth, &l.ScanMonth,
		&l.IsActive, &l.ExpiresAt, &l.CreatedAt,
	); err != nil {
		return nil, err
	}
	return &l, nil
}

// IncrementScanCount atomically increments (or resets then increments) the scan counter.
// The reset-on-new-month logic is done entirely in SQL to avoid race conditions.
func IncrementScanCount(ctx context.Context, licenseID string) error {
	if !IsAvailable() {
		return fmt.Errorf("database unavailable")
	}
	currentMonth := time.Now().UTC().Format("2006-01")
	_, err := Pool().Exec(ctx, `
		UPDATE licenses SET
			scans_this_month = CASE
				WHEN scan_month = $2 THEN scans_this_month + 1
				ELSE 1
			END,
			scan_month  = $2,
			updated_at  = NOW()
		WHERE id = $1
	`, licenseID, currentMonth)
	return err
}

// RecordScan writes a row to scan_history after a completed scan.
func RecordScan(ctx context.Context, licenseID, clientVersion string, findingsCount, criticalCount, highCount int, durationMS int64) error {
	if !IsAvailable() {
		return fmt.Errorf("database unavailable")
	}
	_, err := Pool().Exec(ctx, `
		INSERT INTO scan_history
			(license_id, findings_count, critical_count, high_count, duration_ms, client_version)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, licenseID, findingsCount, criticalCount, highCount, durationMS, clientVersion)
	return err
}

// CreateLicense generates a new license key and inserts it into the database.
func CreateLicense(ctx context.Context, org, email, plan string, maxScans int, expiresAt *time.Time) (string, error) {
	if !IsAvailable() {
		return "", fmt.Errorf("database unavailable")
	}
	key := "ciotx_" + randomHex(24) // 48-char random suffix → 55-char total key
	_, err := Pool().Exec(ctx, `
		INSERT INTO licenses (license_key, organization, email, plan, max_scans_per_month, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, key, org, email, plan, maxScans, expiresAt)
	if err != nil {
		return "", err
	}
	return key, nil
}

// RevokeLicense deactivates a key without deleting its history.
func RevokeLicense(ctx context.Context, key string) error {
	if !IsAvailable() {
		return fmt.Errorf("database unavailable")
	}
	tag, err := Pool().Exec(ctx, `
		UPDATE licenses SET is_active = FALSE, updated_at = NOW()
		WHERE license_key = $1
	`, key)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// ListLicenses returns all licenses ordered newest first.
func ListLicenses(ctx context.Context) ([]*License, error) {
	if !IsAvailable() {
		return nil, fmt.Errorf("database unavailable")
	}
	rows, err := Pool().Query(ctx, `
		SELECT id, license_key, organization, email, plan,
		       max_scans_per_month, scans_this_month, scan_month,
		       is_active, expires_at, created_at
		FROM licenses
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var licenses []*License
	for rows.Next() {
		var l License
		if err := rows.Scan(
			&l.ID, &l.LicenseKey, &l.Organization, &l.Email, &l.Plan,
			&l.MaxScansPerMonth, &l.ScansThisMonth, &l.ScanMonth,
			&l.IsActive, &l.ExpiresAt, &l.CreatedAt,
		); err != nil {
			return nil, err
		}
		licenses = append(licenses, &l)
	}
	return licenses, rows.Err()
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("[db] crypto/rand failed: %v", err))
	}
	return hex.EncodeToString(b)
}
