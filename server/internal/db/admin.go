package db

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ErrNotFound is returned when a queried record does not exist.
var ErrNotFound = errors.New("record not found")

// AdminStats contains aggregate metrics for the operator dashboard.
type AdminStats struct {
	ActiveLicenses int `json:"active_licenses"`
	TotalLicenses  int `json:"total_licenses"`
	ScansToday     int `json:"scans_today"`
	ScansThisMonth int `json:"scans_this_month"`
	TotalScans     int `json:"total_scans"`
}

// GetAdminStats returns aggregate statistics across all licenses and scans.
func GetAdminStats(ctx context.Context) (*AdminStats, error) {
	if !IsAvailable() {
		return nil, fmt.Errorf("database unavailable")
	}

	var s AdminStats
	row := Pool().QueryRow(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE is_active = TRUE AND (expires_at IS NULL OR expires_at > NOW())),
			COUNT(*),
			(SELECT COALESCE(COUNT(*), 0) FROM scan_history
			 WHERE created_at >= date_trunc('day', NOW() AT TIME ZONE 'UTC')),
			(SELECT COALESCE(COUNT(*), 0) FROM scan_history
			 WHERE created_at >= date_trunc('month', NOW() AT TIME ZONE 'UTC')),
			(SELECT COALESCE(COUNT(*), 0) FROM scan_history)
		FROM licenses
	`)
	if err := row.Scan(
		&s.ActiveLicenses, &s.TotalLicenses,
		&s.ScansToday, &s.ScansThisMonth, &s.TotalScans,
	); err != nil {
		return nil, err
	}
	return &s, nil
}

// AdminScanRecord is one row from scan_history joined with the license owner.
type AdminScanRecord struct {
	Organization  string    `json:"organization"`
	FindingsCount int       `json:"findings_count"`
	CriticalCount int       `json:"critical_count"`
	HighCount     int       `json:"high_count"`
	DurationMS    int64     `json:"duration_ms"`
	ClientVersion string    `json:"client_version"`
	CreatedAt     time.Time `json:"created_at"`
}

// GetRecentScansAll returns the most recent scans across all licenses, newest first.
func GetRecentScansAll(ctx context.Context, limit int) ([]*AdminScanRecord, error) {
	if !IsAvailable() {
		return nil, nil
	}
	if limit < 1 || limit > 100 {
		limit = 25
	}

	rows, err := Pool().Query(ctx, `
		SELECT l.organization, sh.findings_count, sh.critical_count, sh.high_count,
		       sh.duration_ms, sh.client_version, sh.created_at
		FROM scan_history sh
		JOIN licenses l ON sh.license_id = l.id
		ORDER BY sh.created_at DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []*AdminScanRecord
	for rows.Next() {
		var rec AdminScanRecord
		if err := rows.Scan(
			&rec.Organization, &rec.FindingsCount, &rec.CriticalCount,
			&rec.HighCount, &rec.DurationMS, &rec.ClientVersion, &rec.CreatedAt,
		); err != nil {
			return nil, err
		}
		records = append(records, &rec)
	}
	return records, rows.Err()
}
