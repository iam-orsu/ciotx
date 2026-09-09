// Package types defines shared data models used across the CLI.
package types

// Finding represents a single confirmed security vulnerability returned by the ciotx backend.
type Finding struct {
	RuleID             string  `json:"rule_id"`
	Title              string  `json:"title"`
	Severity           string  `json:"severity"`
	CWE                string  `json:"cwe"`
	File               string  `json:"file"`
	LineStart          int     `json:"line_start"`
	LineEnd            int     `json:"line_end"`
	Evidence           string  `json:"evidence"`
	DataFlow           string  `json:"data_flow"`
	Description        string  `json:"description"`
	Remediation        string  `json:"remediation"`
	Confidence         float64 `json:"confidence"`
	AuditStatus        string  `json:"audit_status"`
	AuditJustification string  `json:"audit_justification"`
}
