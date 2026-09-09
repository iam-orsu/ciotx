package llm

import (
	"testing"
)

func TestNormalizeSeverity(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"critical", "Critical"},
		{"CRITICAL", "Critical"},
		{"Critical", "Critical"},
		{"high", "High"},
		{"HIGH", "High"},
		{"medium", "Medium"},
		{"MEDIUM", "Medium"},
		{"low", "Low"},
		{"LOW", "Low"},
		{"unknown", "Medium"},
		{"", "Medium"},
		{"info", "Medium"},
	}
	for _, tc := range cases {
		got := normalizeSeverity(tc.input)
		if got != tc.want {
			t.Errorf("normalizeSeverity(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestParseFindings_WrappedJSON(t *testing.T) {
	raw := `{"findings": [{"rule_id":"SQLI-001","title":"SQL Injection","severity":"Critical","cwe":"CWE-89","file":"main.go","line_start":10,"line_end":12,"evidence":"db.Exec(query)","data_flow":"user -> query -> db","description":"SQL injection","remediation":"use parameterized queries"}]}`
	findings, err := parseFindings(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.RuleID != "SQLI-001" {
		t.Errorf("RuleID = %q, want SQLI-001", f.RuleID)
	}
	if f.Severity != "Critical" {
		t.Errorf("Severity = %q, want Critical", f.Severity)
	}
	if f.File != "main.go" {
		t.Errorf("File = %q, want main.go", f.File)
	}
}

func TestParseFindings_CodeFence(t *testing.T) {
	raw := "```json\n{\"findings\": [{\"rule_id\":\"XSS-001\",\"title\":\"XSS\",\"severity\":\"high\",\"cwe\":\"CWE-79\",\"file\":\"app.js\",\"line_start\":5,\"line_end\":5,\"evidence\":\"res.send(input)\",\"data_flow\":\"req -> input -> res\",\"description\":\"XSS\",\"remediation\":\"escape output\"}]}\n```"
	findings, err := parseFindings(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != "High" {
		t.Errorf("Severity = %q, want High (normalized)", findings[0].Severity)
	}
}

func TestParseFindings_Empty(t *testing.T) {
	raw := `{"findings": []}`
	findings, err := parseFindings(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseFindings_WindowsPaths(t *testing.T) {
	raw := `{"findings": [{"rule_id":"R","title":"T","severity":"low","cwe":"CWE-1","file":"src\\main.go","line_start":1,"line_end":1,"evidence":"e","data_flow":"d","description":"d","remediation":"r"}]}`
	findings, err := parseFindings(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].File != "src/main.go" {
		t.Errorf("File = %q, want src/main.go (backslashes normalized)", findings[0].File)
	}
}

func TestParseFindings_Garbage(t *testing.T) {
	findings, err := parseFindings("not json at all")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for garbage input, got %d", len(findings))
	}
}
