package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/iam-orsu/ciotx/server/internal/types"
)

// FixResult is the structured output from RunFix.
type FixResult struct {
	FixedContent string // Full corrected file content (apply as-is)
	PRTitle      string // e.g. "fix: SQL injection in user login (CWE-89)"
	PRBody       string // Markdown PR description
}

// fixResponse is the JSON schema the LLM must return.
type fixResponse struct {
	FixedContent string `json:"fixed_content"`
	PRTitle      string `json:"pr_title"`
	PRBody       string `json:"pr_body"`
}

// fixSystemPromptBase is the system prompt for fix generation.
// Backtick fences in the PR template are written as separate string literals
// to avoid terminating the raw string.
var fixSystemPromptBase = "You are a security engineer producing minimal, production-safe code fixes.\n" +
	"You receive a confirmed security vulnerability and the full source file that contains it.\n" +
	"Your task:\n" +
	"1. Write the SMALLEST change that eliminates the vulnerability without breaking other functionality.\n" +
	"2. Do NOT refactor, rename, or change unrelated code.\n" +
	"3. Do NOT add comments explaining what you changed.\n" +
	"4. Return ONLY valid JSON — no markdown fences, no prose outside the JSON.\n\n" +
	"JSON schema:\n" +
	"{\n" +
	"  \"fixed_content\": \"<entire corrected file as a string — preserve all original whitespace and line endings>\",\n" +
	"  \"pr_title\": \"<50 chars max: 'fix: <short description> ({cwe})'>\",\n" +
	"  \"pr_body\": \"<markdown PR description with: severity, file, what was wrong, what changed, evidence>\"\n" +
	"}\n\n" +
	"The pr_body MUST follow this structure:\n" +
	"## Security Fix\n" +
	"**Vulnerability**: {cwe} — {title}\n" +
	"**Severity**: {severity}\n" +
	"**File**: `{file}:{line}`\n\n" +
	"### What was wrong\n" +
	"{description}\n\n" +
	"### What changed\n" +
	"One or two sentences describing the minimal change.\n\n" +
	"### Evidence\n" +
	"```\n" +
	"{evidence}\n" +
	"```\n\n" +
	"---\n" +
	"*Automated security fix by ciotx.*"

// RunFix asks the LLM to generate a minimal code fix for a single confirmed finding.
// fileContent is the full decoded text of finding.File.
// Returns an error if the LLM cannot produce a parseable fix.
func RunFix(ctx context.Context, c *Client, finding *types.Finding, fileContent string) (*FixResult, error) {
	systemPrompt := buildFixSystemPrompt(finding)

	userPrompt := fmt.Sprintf(
		"VULNERABILITY:\nCWE       : %s\nTitle     : %s\nSeverity  : %s\n"+
			"File      : %s\nLines     : %d-%d\nDescription: %s\nEvidence  : %s\n\n"+
			"SOURCE FILE (%s):\n%s",
		finding.CWE, finding.Title, finding.Severity,
		finding.File, finding.LineStart, finding.LineEnd,
		finding.Description, finding.Evidence,
		finding.File, fileContent,
	)

	content, _, err := c.Chat(ctx, modelAudit,
		NewMessages(systemPrompt, userPrompt),
		true,  // JSON mode
		8192,  // enough for full file + PR body
	)
	if err != nil {
		return nil, fmt.Errorf("fix generation failed: %w", err)
	}

	// Strip markdown fences if the model wrapped the JSON despite instructions.
	content = strings.TrimSpace(content)
	if strings.HasPrefix(content, "```") {
		if i := strings.Index(content, "\n"); i != -1 {
			content = content[i+1:]
		}
		content = strings.TrimSuffix(strings.TrimSpace(content), "```")
		content = strings.TrimSpace(content)
	}

	var fix fixResponse
	if err := json.Unmarshal([]byte(content), &fix); err != nil {
		return nil, fmt.Errorf("fix response parse error: %w (raw: %.200s)", err, content)
	}
	if strings.TrimSpace(fix.FixedContent) == "" {
		return nil, fmt.Errorf("LLM returned empty fixed_content")
	}
	if strings.TrimSpace(fix.PRTitle) == "" {
		fix.PRTitle = fmt.Sprintf("fix: %s (%s)", finding.Title, finding.CWE)
	}
	if strings.TrimSpace(fix.PRBody) == "" {
		fix.PRBody = buildDefaultPRBody(finding)
	}

	return &FixResult{
		FixedContent: fix.FixedContent,
		PRTitle:      truncate(fix.PRTitle, 72),
		PRBody:       fix.PRBody,
	}, nil
}

// buildFixSystemPrompt injects the finding's values into the system prompt template.
func buildFixSystemPrompt(f *types.Finding) string {
	r := strings.NewReplacer(
		"{cwe}", f.CWE,
		"{title}", f.Title,
		"{severity}", f.Severity,
		"{file}", f.File,
		"{line}", fmt.Sprintf("%d", f.LineStart),
		"{description}", f.Description,
		"{evidence}", f.Evidence,
	)
	return r.Replace(fixSystemPromptBase)
}

func buildDefaultPRBody(f *types.Finding) string {
	return fmt.Sprintf(
		"## Security Fix\n\n"+
			"**Vulnerability**: %s — %s\n"+
			"**Severity**: %s\n"+
			"**File**: `%s:%d`\n\n"+
			"### What was wrong\n%s\n\n"+
			"### Evidence\n```\n%s\n```\n\n---\n*Automated security fix by ciotx.*",
		f.CWE, f.Title, f.Severity,
		f.File, f.LineStart,
		f.Description,
		f.Evidence,
	)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
