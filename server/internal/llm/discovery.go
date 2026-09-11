package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/iam-orsu/ciotx/server/internal/types"
)

// jsonObjectRe extracts the outermost JSON object from a freeform LLM response
// as a last-resort fallback when the response is neither wrapped JSON nor a bare array.
var jsonObjectRe = regexp.MustCompile(`\{[\s\S]*\}`)

const discoverySystemPrompt = `You are an elite offensive security researcher and application security engineer with deep expertise in source code vulnerability analysis.

Your task: Conduct an exhaustive source code security audit to find REAL, EXPLOITABLE security vulnerabilities.

MANDATORY VULNERABILITY CHECKLIST — for every file, you MUST consider each class before concluding the file is clean:

OWASP TOP 10:
 1. Injection: SQL (CWE-89), Command (CWE-78), LDAP, XPath, Header, Template, SSTI (CWE-94)
 2. Broken Authentication: weak session tokens, missing expiry, credential stuffing openings (CWE-287, CWE-384)
 3. Sensitive Data Exposure: secrets in logs, error messages, responses, hardcoded credentials (CWE-312, CWE-798)
 4. XML External Entities (XXE): unsafe XML parsers (CWE-611)
 5. Broken Access Control: IDOR, missing authz checks, privilege escalation (CWE-639, CWE-862)
 6. Security Misconfiguration: dangerous defaults, verbose errors, directory listing
 7. XSS: Stored (CWE-79), Reflected (CWE-79), DOM-based
 8. Insecure Deserialization: unsafe object unmarshalling (CWE-502)
 9. Vulnerable Components: known-bad API usage, deprecated crypto
10. Insufficient Logging: missing audit trails for sensitive actions

ADDITIONAL CLASSES:
- Path Traversal / Directory Traversal (CWE-22)
- Server-Side Request Forgery — SSRF (CWE-918)
- Race Conditions / TOCTOU (CWE-362, CWE-367)
- Integer Overflow / Underflow (CWE-190)
- Cryptographic weaknesses: MD5/SHA1 for passwords, weak random, short keys (CWE-326, CWE-338)
- Business Logic: mass assignment, parameter tampering, insufficient rate limiting
- Memory safety: buffer overflow, use-after-free, null dereference (C/C++ only)

EFFORT REQUIREMENT:
For each file, reason through at least 5 of the above vulnerability patterns before concluding the file is clean.
Trace every function that accepts external input — HTTP params, headers, cookies, file content, env vars, database values.

REPORTING PHILOSOPHY:
Err on the side of reporting. It is better to report a potential finding than to miss a real one.
The adversarial audit stage that follows will filter false positives — your job is NOT to filter, it is to find.
If you see something suspicious, report it with the evidence. Do not dismiss borderline cases.

RULES:
1. Report vulnerabilities with a traceable data flow from an untrusted source to a dangerous sink.
2. The 'evidence' field MUST be an exact verbatim code snippet copied from the provided file.
3. Assign realistic severity: Critical/High/Medium/Low.
4. Do NOT report pure style issues, missing log lines, or theoretical issues with zero exploit path.

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
	content, u, err := client.Chat(ctx, modelDiscovery, msgs, false, 16000)
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
		clean = auditFenceOpenRe.ReplaceAllString(clean, "")
		clean = strings.TrimSpace(auditFenceCloseRe.ReplaceAllString(clean, ""))
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
			match := jsonObjectRe.FindString(content)
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
