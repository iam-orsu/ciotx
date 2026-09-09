package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/iam-orsu/ciotx/server/internal/types"
)

const discoverySystemPrompt = `You are an elite offensive security researcher and application security engineer with deep expertise in source code vulnerability analysis.

Your task: Conduct an exhaustive source code security audit to find REAL, EXPLOITABLE security vulnerabilities.

VULNERABILITY CATEGORIES TO FIND:
- Injection: SQL, Command, LDAP, XPath, Header, Template, SSTI
- Authentication/Authorization: Broken auth, privilege escalation, IDOR, JWT issues, session fixation
- Cryptography: Weak algorithms (MD5/SHA1 passwords), hardcoded secrets, predictable tokens
- Data Exposure: Sensitive data in logs, error messages, responses, config files
- Input Validation: XSS (Stored/Reflected/DOM), Path Traversal, SSRF, XXE, Deserialization
- Race Conditions / TOCTOU: File system races, check-then-act patterns
- Business Logic: Mass assignment, parameter tampering, integer overflow, insufficient rate limiting

STRICT RULES:
1. ONLY report vulnerabilities with a complete, traceable data flow from an untrusted source to a dangerous sink.
2. ONLY report issues where the risk is NOT already neutralized by framework ORM, type system, or sanitizer.
3. The 'evidence' field MUST be an exact verbatim code snippet copied from the provided file.
4. Assign realistic severity: Critical/High/Medium/Low.
5. Do NOT report style issues, missing logs, or theoretical issues without a concrete exploit path.

RESPONSE FORMAT — strictly valid JSON only:
{
  "findings": [
    {
      "rule_id": "SQLI-001",
      "title": "SQL Injection via Unsanitized Username Parameter",
      "severity": "Critical",
      "cwe": "CWE-89: SQL Injection",
      "file": "relative/path/to/file.go",
      "line_start": 42,
      "line_end": 45,
      "evidence": "exact verbatim code line(s) from the file",
      "data_flow": "Step-by-step: HTTP param -> vulnerable function -> dangerous sink",
      "description": "Deep technical analysis of why and how an attacker can exploit this",
      "remediation": "Production-ready corrected code example"
    }
  ]
}

If no genuine exploitable vulnerabilities exist, return: {"findings": []}`

// RunDiscovery sends one code chunk to the internal LLM for vulnerability discovery.
func RunDiscovery(ctx context.Context, client *Client, chunkID int, payload string, usage *Usage, usageMu interface{ Lock(); Unlock() }) ([]*types.Finding, error) {
	userPrompt := fmt.Sprintf(`Conduct a thorough vulnerability review for code chunk #%d.
Read line by line, trace data flows from sources to sinks, and identify all genuine security vulnerabilities.

%s

Return strictly valid JSON with {"findings": [...]}. The 'evidence' field must be an exact verbatim snippet.`,
		chunkID, payload)

	msgs := NewMessages(discoverySystemPrompt, userPrompt)
	content, u, err := client.Chat(ctx, modelDiscovery, msgs, false, 8192)
	if err != nil {
		return nil, err
	}

	usageMu.Lock()
	usage.PromptTokens += u.PromptTokens
	usage.CompletionTokens += u.CompletionTokens
	usage.CacheHitTokens += u.CacheHitTokens
	usage.CacheMissTokens += u.CacheMissTokens
	usageMu.Unlock()

	return parseFindings(content)
}

func parseFindings(content string) ([]*types.Finding, error) {
	clean := strings.TrimSpace(content)
	if strings.Contains(clean, "```") {
		re := regexp.MustCompile("```(?:json)?\\s*")
		clean = re.ReplaceAllString(clean, "")
		re2 := regexp.MustCompile("\\s*```")
		clean = strings.TrimSpace(re2.ReplaceAllString(clean, ""))
	}

	var rawFindings []json.RawMessage

	var wrapper struct {
		Findings []json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal([]byte(clean), &wrapper); err == nil {
		rawFindings = wrapper.Findings
	} else {
		var arr []json.RawMessage
		if err2 := json.Unmarshal([]byte(clean), &arr); err2 == nil {
			rawFindings = arr
		} else {
			re := regexp.MustCompile(`\{[\s\S]*\}`)
			match := re.FindString(content)
			if match != "" {
				if err3 := json.Unmarshal([]byte(match), &wrapper); err3 == nil {
					rawFindings = wrapper.Findings
				}
			}
		}
	}

	var findings []*types.Finding
	for _, raw := range rawFindings {
		var f types.Finding
		if err := json.Unmarshal(raw, &f); err != nil {
			continue
		}
		f.Severity = normalizeSeverity(f.Severity)
		f.File = strings.ReplaceAll(f.File, "\\", "/")
		findings = append(findings, &f)
	}
	return findings, nil
}

func normalizeSeverity(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	default:
		return "Medium"
	}
}
