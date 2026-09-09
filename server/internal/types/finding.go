// Package types defines the shared data models for the ciotx server.
// These are INTERNAL types — they are never exposed with third-party branding.
package types

// Finding is a confirmed security vulnerability.
// All LLM-specific fields are stripped before this reaches the API response.
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
