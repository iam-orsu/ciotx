package llm

import (
	"context"
	"fmt"
	"strings"

	"github.com/iam-orsu/ciotx/server/internal/types"
)

const prBodySystemPrompt = `You are an Application Security Engineer writing a GitHub PR description for a confirmed security finding.
Your audience is the developer who wrote the vulnerable code. Be clear, technical, and actionable.
Write valid GitHub-Flavoured Markdown. Do NOT mention any AI vendor, model name, or tool internals.
Return only the PR body markdown — no preamble, no JSON wrapping, no code fences around the whole response.`

// RunPRBody generates a markdown PR body for a security finding using the audit model.
// Always returns a non-nil body — on LLM failure it falls back to a plain-text body
// so the caller is never blocked from opening the PR.
func RunPRBody(ctx context.Context, c *Client, finding *types.Finding, fileContent string) (string, error) {
	cweURL := cweLink(finding.CWE)

	userPrompt := fmt.Sprintf(
		"Generate a GitHub PR body for this confirmed security finding.\n\n"+
			"Finding:\n"+
			"  Title:       %s\n"+
			"  CWE:         %s\n"+
			"  Severity:    %s\n"+
			"  File:        %s\n"+
			"  Lines:       %d–%d\n"+
			"  Evidence:    %s\n"+
			"  Data Flow:   %s\n"+
			"  Description: %s\n\n"+
			"The PR body MUST follow this exact structure:\n\n"+
			"## Security Finding: %s (%s)\n"+
			"**Severity:** %s\n"+
			"**File:** `%s` — Lines %d–%d\n"+
			"**Standard:** [%s](%s)\n\n"+
			"### Vulnerable Code\n"+
			"```\n"+
			"%s\n"+
			"```\n\n"+
			"### What the vulnerability is\n"+
			"[2–3 sentence plain English explanation of the bug and how an attacker could exploit it]\n\n"+
			"### Attack scenario\n"+
			"[Concrete example: \"An attacker could send...\" showing a real exploitation path]\n\n"+
			"### Recommended remediation\n"+
			"[Specific verbal guidance — do NOT include code. Explain what pattern to use, what to avoid, and why.]\n\n"+
			"### References\n"+
			"- [%s](%s)\n\n"+
			"---\n"+
			"*This PR was opened automatically by ciotx. No code has been modified — remediation is at the developer’s discretion.*",
		finding.Title, finding.CWE, finding.Severity,
		finding.File, finding.LineStart, finding.LineEnd,
		finding.Evidence, finding.DataFlow, finding.Description,
		finding.Title, finding.CWE,
		finding.Severity,
		finding.File, finding.LineStart, finding.LineEnd,
		finding.CWE, cweURL,
		finding.Evidence,
		finding.CWE, cweURL,
	)

	content, _, err := c.Chat(ctx, modelAudit, NewMessages(prBodySystemPrompt, userPrompt), false, 4096)
	if err != nil {
		return fallbackPRBody(finding), fmt.Errorf("pr body generation failed: %w", err)
	}

	body := strings.TrimSpace(content)
	if body == "" {
		return fallbackPRBody(finding), nil
	}
	return body, nil
}

func fallbackPRBody(f *types.Finding) string {
	return fmt.Sprintf(
		"## Security Finding: %s (%s)\n\n"+
			"**Severity:** %s\n"+
			"**File:** `%s` — Lines %d–%d\n\n"+
			"### Vulnerable Code\n```\n%s\n```\n\n"+
			"### Description\n%s\n\n"+
			"---\n*This PR was opened automatically by ciotx. No code has been modified.*",
		f.Title, f.CWE, f.Severity,
		f.File, f.LineStart, f.LineEnd,
		f.Evidence, f.Description,
	)
}

// cweLink converts a CWE string (e.g. "CWE-89: SQL Injection" or "CWE-89")
// into the MITRE CWE reference URL.
func cweLink(cwe string) string {
	id := cwe
	if i := strings.Index(cwe, ":"); i != -1 {
		id = strings.TrimSpace(cwe[:i])
	}
	id = strings.TrimPrefix(strings.TrimPrefix(id, "CWE-"), "cwe-")
	if id == "" || id == cwe {
		return "https://cwe.mitre.org/"
	}
	return fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", id)
}
