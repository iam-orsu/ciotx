# ciotx

> Source Code Security Auditor — Find real, exploitable vulnerabilities before they ship.

[![License](https://img.shields.io/github/license/iam-orsu/ciotx)](LICENSE)

## Install

```bash
curl -fsSL https://api.ciotx.ai/install.sh | sh
```

## Usage

```bash
# Authenticate once with your license key
ciotx auth login

# Scan your codebase
ciotx scan .
ciotx scan /path/to/repo
```

That's it. ciotx handles everything else automatically.

## How It Works

1. **Reads your source files locally** — only code, never secrets or config
2. **Sends code chunks to ciotx servers** over encrypted HTTPS
3. **Deep analysis** identifies real, exploitable vulnerabilities
4. **Adversarial verification** eliminates false positives automatically
5. **Generates a report** — interactive HTML + JSON on your machine

## Supported Languages

Python · Go · JavaScript · TypeScript · Java · C# · C/C++ · PHP · Ruby · Rust · Solidity · SQL · Shell

## Get Your License Key

Visit [ciotx.ai](https://ciotx.ai) to get started.

---

## For Self-Hosting / Operators

### Prerequisites
- VPS with Docker & Docker Compose installed
- Domain with DNS A record pointing to your VPS IP

### Deploy

```bash
# 1. Clone the repository
git clone https://github.com/iam-orsu/ciotx.git
cd ciotx

# 2. Configure your environment
cp .env.example .env
nano .env   # Set: DOMAIN_NAME, VPS_SERVER_IP, SSL_EMAIL, LLM_API_KEY, MASTER_LICENSE_KEY

# 3. Run the deployment script (does everything — Docker, SSL, build, launch)
chmod +x scripts/deploy.sh
./scripts/deploy.sh
```

That's it. The script handles:
- Installing Docker if not present
- Verifying DNS is configured correctly
- Obtaining a free SSL certificate from Let's Encrypt
- Building and launching the full Docker stack
- Running a health check to confirm everything is live

### Environment Variables (.env)

| Variable | Description |
|:---|:---|
| `DOMAIN_NAME` | Your domain (e.g. `api.ciotx.ai`) |
| `VPS_SERVER_IP` | Your server public IP |
| `SSL_EMAIL` | Email for SSL cert registration |
| `LLM_API_KEY` | Internal analysis key (never exposed to users) |
| `MASTER_LICENSE_KEY` | Dev/test license key |

### Project Structure

```
ciotx/
├── cli/          — User-facing binary (ciotx scan .)
├── server/       — Backend API (hidden from users)
├── nginx/        — Reverse proxy with TLS
├── scripts/      — Deployment & install scripts
└── docker-compose.yml
```
