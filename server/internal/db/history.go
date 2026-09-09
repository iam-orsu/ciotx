package db

import (
	"context"
	"time"
)

// ScanRecord is one row from scan_history.
type ScanRecord struct {
	ID            string
	FindingsCount int
	CriticalCount int
	HighCount     int
	DurationMS    int64
	ClientVersion string
	CreatedAt     time.Time
}

// GetScanHistory returns the most recent scan records for a license, newest first.
// Returns nil slice (no error) when the DB is unavailable.
func GetScanHistory(ctx context.Context, licenseID string, limit int) ([]*ScanRecord, error) {
	if !IsAvailable() {
		return nil, nil
	}
	if limit < 1 || limit > 50 {
		limit = 10
	}

	rows, err := Pool().Query(ctx, `
		SELECT id, findings_count, critical_count, high_count,
		       duration_ms, client_version, created_at
		FROM scan_history
		WHERE license_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`, licenseID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []*ScanRecord
	for rows.Next() {
		var rec ScanRecord
		if err := rows.Scan(
			&rec.ID, &rec.FindingsCount, &rec.CriticalCount, &rec.HighCount,
			&rec.DurationMS, &rec.ClientVersion, &rec.CreatedAt,
		); err != nil {
			return nil, err
		}
		records = append(records, &rec)
	}
	return records, rows.Err()
}

// GetLicenseScanStats returns total scan count and last scan time for a license.
// lastScanAt is nil if no scans have been recorded yet.
func GetLicenseScanStats(ctx context.Context, licenseID string) (totalScans int, lastScanAt *time.Time, err error) {
	if !IsAvailable() {
		return 0, nil, nil
	}
	row := Pool().QueryRow(ctx, `
		SELECT COUNT(*), MAX(created_at)
		FROM scan_history
		WHERE license_id = $1
	`, licenseID)

	if err := row.Scan(&totalScans, &lastScanAt); err != nil {
		return 0, nil, err
	}
	return totalScans, lastScanAt, nil
}
