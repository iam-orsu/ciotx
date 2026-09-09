# ciotx

> Autonomous Deep-Reasoning Source Code Security Auditor

![License](https://img.shields.io/github/license/iam-orsu/ciotx)
![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go)

`ciotx` is an enterprise-grade, zero-dependency security auditing agent that autonomously scans codebases for real, exploitable vulnerabilities using AI-powered deep reasoning and a two-pass adversarial verification gate.

## Quick Install (Linux / macOS)

```bash
curl -fsSL https://get.ciotx.ai/install.sh | sh
```

## Usage

```bash
# Full repository audit
ciotx scan /path/to/repo

# Faster scan with chat model
ciotx scan . --model deepseek-chat --workers 4

# Skip false-positive filter
ciotx scan . --no-audit

# Cost estimate only (no API calls)
ciotx scan . --dry-run
```

## How It Works

1. **Ingestion** — Indexes all source files, skipping test fixtures, lock files, and vendor directories
2. **Chunking** — Partitions into ~15k-token semantic chunks for optimal LLM context
3. **Discovery Pass** — DeepSeek Reasoner (R1) analyzes each chunk with an attacker mindset
4. **Verification Gate** — Evidence re-anchoring drops hallucinations and non-existent findings
5. **Adversarial Audit** — A second skeptical model filters false positives before reporting

## Supported Languages

Python, Go, JavaScript/TypeScript, Java, C#, C/C++, PHP, Ruby, Rust, Solidity, SQL, Shell, and more.

## Configuration

```bash
export CIOTX_DEEPSEEK_API_KEY="sk-..."
ciotx scan .
```

## Build From Source

```bash
git clone https://github.com/iam-orsu/ciotx.git
cd ciotx
go build -o ciotx ./cmd/ciotx
./ciotx --version
```
