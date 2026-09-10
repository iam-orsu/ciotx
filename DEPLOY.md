# Deploying ciotx on a Fresh VPS

This guide walks you through a complete production deployment of ciotx on a fresh Ubuntu VPS — from DNS configuration to issuing your first license key and scanning a real codebase. Everything runs in Docker. The whole process takes about 10–15 minutes.

---

## What You Will End Up With

- `https://yourdomain.com/v1/scan` — the scan API your users hit
- `https://yourdomain.com/admin` — your operator dashboard (license management, usage stats)
- `https://yourdomain.com/install.sh` — one-line installer for the `ciotx` CLI
- `https://yourdomain.com/health` — health endpoint for uptime monitoring
- Auto-renewing TLS certificate via Let's Encrypt
- PostgreSQL database with automatic schema migrations
- Optional: GitHub App integration that scans every push and opens fix PRs automatically

---

## Requirements

| Item | Minimum | Recommended |
|:-----|:--------|:------------|
| VPS RAM | 2 GB | 4 GB |
| VPS CPU | 1 vCPU | 2 vCPU |
| Disk | 20 GB | 40 GB |
| OS | Ubuntu 22.04 LTS | Ubuntu 24.04 LTS |
| Domain | Required | — |
| DeepSeek API Key | Required | — |

> **Why DeepSeek?** ciotx uses DeepSeek's reasoning model (`deepseek-reasoner`) for vulnerability discovery and a fast chat model (`deepseek-chat`) for adversarial verification. The API key lives entirely inside your Docker container and is never exposed to your users.

---

## Step 1 — Get Your DeepSeek API Key

1. Go to [platform.deepseek.com](https://platform.deepseek.com)
2. Sign up or log in
3. Navigate to **API Keys** → **Create new secret key**
4. Copy the key — it starts with `sk-`
5. Add some credits to your account (a typical scan costs $0.01–$0.05)

Keep this key handy. You will paste it into `.env` in a few minutes.

---

## Step 2 — Point Your Domain at the VPS

Before touching the server, set up DNS. Let's Encrypt needs to verify your domain before issuing a TLS certificate.

1. Log into your domain registrar or DNS provider
2. Create an **A record**:
   - **Name:** `api` (or `@` for root domain, or whatever subdomain you want)
   - **Value:** your VPS public IP address
   - **TTL:** 300 (5 minutes is fine)

**Example:**
```
api.yourdomain.com  →  A  →  123.45.67.89
```

DNS propagation usually takes 1–5 minutes. You can verify it with:
```bash
dig +short api.yourdomain.com
# Should print your VPS IP
```

> Do not proceed to Step 4 until the DNS record resolves correctly. The SSL certificate request will fail if DNS has not propagated.

---

## Step 3 — SSH into Your VPS

```bash
ssh root@YOUR_VPS_IP
```

If your provider created a non-root user, use `sudo -i` to become root or prefix the deploy command with `sudo`.

---

## Step 4 — Clone the Repository

```bash
git clone https://github.com/iam-orsu/ciotx.git
cd ciotx
```

---

## Step 5 — Configure Your Environment

Copy the example config and open it for editing:

```bash
cp .env.example .env
nano .env
```

Fill in every variable. Here is exactly what each one means:

```bash
# ── Your domain (the A record you created in Step 2) ──────────────────
DOMAIN_NAME=api.yourdomain.com

# ── Your VPS public IP ─────────────────────────────────────────────────
VPS_SERVER_IP=123.45.67.89

# ── Email for Let's Encrypt — receives expiry warnings ────────────────
SSL_EMAIL=you@youremail.com

# ── DeepSeek API key (from Step 1) ────────────────────────────────────
# This key NEVER leaves your server. Users only talk to your domain.
LLM_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# ── Master license key ────────────────────────────────────────────────
# This is your personal bypass key for testing. Generate a strong one:
#   openssl rand -hex 32
MASTER_LICENSE_KEY=ciotx_prod_your_strong_random_value_here

# ── PostgreSQL password ────────────────────────────────────────────────
# Generate with: openssl rand -hex 32
POSTGRES_PASSWORD=your_strong_database_password_here

# ── Admin panel password ──────────────────────────────────────────────
# Password for /admin dashboard. Leave empty to disable the admin panel.
# Generate with: openssl rand -base64 24
ADMIN_PASSWORD=your_strong_admin_password_here

# ── GitHub App integration (optional — skip for now, add later) ───────
# Leave these three lines as-is if you don't need GitHub PR integration.
GITHUB_APP_ID=
GITHUB_APP_PRIVATE_KEY_BASE64=
GITHUB_WEBHOOK_SECRET=
```

**Save the file** (`Ctrl+O`, `Enter`, `Ctrl+X` in nano).

> **Security:** `.env` is in `.gitignore`. It will never be committed. Keep a secure copy elsewhere — if you lose it, you lose your master key.

---

## Step 6 — Run the Deploy Script

```bash
chmod +x scripts/deploy.sh
sudo ./scripts/deploy.sh
```

The script will:

1. **Validate** your `.env` — catches common mistakes (placeholder values, weak passwords, wrong key format)
2. **Install Docker** — if not already installed (uses the official `get.docker.com` script)
3. **Verify DNS** — confirms your domain resolves to the right IP before requesting a certificate
4. **Obtain SSL certificate** — starts a temporary nginx to complete the Let's Encrypt HTTP-01 challenge
5. **Build CLI binaries** — compiles `ciotx` for Linux, macOS, and Windows with your domain baked in
6. **Build Docker images** — multi-stage Go build + nginx config generation
7. **Launch the full stack** — postgres, api, nginx, certbot in Docker
8. **Health check** — polls `https://yourdomain.com/health` until it returns 200

**Expected output (abbreviated):**
```
[*] Step 0 — Configuration
[+] Configuration validated:
[*]   Domain : api.yourdomain.com
[*]   VPS IP : 123.45.67.89

[*] Step 1 — Docker
[+] Docker 27.3.1 already installed.

[*] Step 2 — DNS Verification
[+] DNS OK: api.yourdomain.com → 123.45.67.89

[*] Step 3 — SSL Certificate
[+] SSL certificate obtained for api.yourdomain.com!

[*] Step 4 — Building CLI Binaries
[+] All CLI binaries built in dist/

[*] Step 5 — Building & Deploying
[*] Building Docker images...
[*] Starting all services...

[*] Step 6 — Health Verification
[+] Health check passed — API is live at https://api.yourdomain.com

╔══════════════════════════════════════════════╗
║         ciotx Deployed Successfully!         ║
╚══════════════════════════════════════════════╝
```

The entire process takes **3–8 minutes** depending on VPS speed and network.

---

## Step 7 — Open the Admin Dashboard

Visit `https://yourdomain.com/admin` in your browser.

Log in with the `ADMIN_PASSWORD` you set in `.env`.

You will see:
- **Stats grid** — total licenses, total scans, scans today/this month
- **License table** — all issued keys with org, plan, usage, expiry
- **Recent scans** — latest scan history across all customers

The dashboard auto-refreshes every 60 seconds.

---

## Step 8 — Issue Your First License Key

You can issue license keys from the admin dashboard or from the command line.

### From the Admin Dashboard

1. Open `https://yourdomain.com/admin`
2. Click **New License**
3. Fill in: organization name, email, plan (`starter` / `pro` / `enterprise`), monthly scan limit, optional expiry date
4. Click **Create** — the key appears immediately
5. Copy it and send it to your customer

### From the Command Line (on the VPS)

```bash
docker compose exec api /ciotx-server license create \
  --org "Acme Corp" \
  --email security@acme.com \
  --plan pro \
  --scans 500
```

Output:
```
License created successfully
Key   : ciotx_a3f2b1c4d5e6f7...
Org   : Acme Corp
Email : security@acme.com
Plan  : pro
Scans : 500/month
```

**Other license management commands:**

```bash
# List all licenses
docker compose exec api /ciotx-server license list

# Revoke a key
docker compose exec api /ciotx-server license revoke ciotx_a3f2b1c4d5e6...

# View per-license scan history
docker compose exec api /ciotx-server license stats
```

---

## Step 9 — Test the Full Scan Flow

Install the CLI on your local machine:

```bash
curl -fsSL https://yourdomain.com/install.sh | sh
```

Authenticate with the master key (or a license key you just created):

```bash
ciotx auth login
# Enter your license key when prompted
```

Scan a codebase:

```bash
ciotx scan /path/to/your/project
```

After the scan completes (1–5 minutes for a typical codebase), ciotx generates two files in the current directory:

- `ciotx-report.html` — interactive report with filterable findings, severity badges, code evidence, and remediation guidance. Open it in a browser.
- `ciotx-report.json` — machine-readable findings for CI/CD integration.

Check your account status:
```bash
ciotx status
# Shows: plan, scans used this month, scans remaining
```

View scan history:
```bash
ciotx history
ciotx history --limit 20
```

---

## Step 10 — (Optional) Set Up GitHub App Integration

This enables ciotx to automatically scan every push to your customers' repositories and open pull requests with security fixes. Skip this section if you don't need GitHub integration.

### Create the GitHub App

1. Go to [github.com/settings/apps/new](https://github.com/settings/apps/new)
2. Fill in:
   - **GitHub App name:** `ciotx-security` (or anything you like)
   - **Homepage URL:** `https://yourdomain.com`
   - **Webhook URL:** `https://yourdomain.com/webhooks/github`
   - **Webhook secret:** generate one with `openssl rand -hex 32` — save it, you'll need it in a moment
3. Under **Repository permissions**, set:
   - **Contents:** Read & write (to commit fixes)
   - **Pull requests:** Read & write (to open PRs)
4. Under **Subscribe to events**, check:
   - **Push**
   - **Installation**
5. Click **Create GitHub App**

### Get the App Credentials

After creating the app:
1. Note the **App ID** shown at the top of the app settings page
2. Scroll down to **Private keys** → **Generate a private key** — a `.pem` file downloads
3. Base64-encode the private key:
   ```bash
   base64 -w 0 your-app-name.private-key.pem
   ```
   Copy the entire output (it will be a long single line).

### Add Credentials to .env

On your VPS, edit `.env`:
```bash
nano .env
```

Fill in the three GitHub variables:
```bash
GITHUB_APP_ID=123456
GITHUB_APP_PRIVATE_KEY_BASE64=LS0tLS1CRUdJTi...  # the long base64 string
GITHUB_WEBHOOK_SECRET=your_webhook_secret_from_step_1
```

### Redeploy

```bash
docker compose up -d api
```

The scan workers start automatically when `GITHUB_APP_ID` is set.

### Install the App on a Repository

1. Go to your GitHub App's settings page → **Install App**
2. Install it on the organization or specific repositories you want scanned
3. Push a commit to the default branch of an installed repository
4. ciotx detects the push via webhook, scans the code, and opens PRs for Critical and High findings within a few minutes

---

## Useful Commands

### View live logs

```bash
# All services
docker compose logs -f

# Just the API server
docker compose logs -f api

# Just nginx (to see incoming requests)
docker compose logs -f nginx
```

### Check service status

```bash
docker compose ps
```

### Restart a specific service

```bash
docker compose restart api
docker compose restart nginx
```

### Stop and start everything

```bash
docker compose down
docker compose up -d
```

### Renew SSL certificate manually

```bash
docker compose run --rm certbot renew --force-renewal
docker compose restart nginx
```

### Database access

```bash
docker compose exec postgres psql -U ciotx -d ciotx
```

---

## Updating ciotx

When a new version is released:

```bash
# On your VPS
git pull
sudo ./scripts/deploy.sh
```

The deploy script rebuilds images, restarts containers, and runs any new database migrations automatically. Existing license keys and scan history are preserved.

---

## Troubleshooting

### Health check fails after deploy

```bash
# See what the API server is saying
docker compose logs api

# Common causes:
# - LLM_API_KEY is wrong or has no credits
# - POSTGRES_PASSWORD mismatch
# - Port 80/443 blocked by VPS firewall
```

### Port 80 or 443 is blocked

Most VPS providers ship with a firewall. Open the ports:

```bash
# UFW (Ubuntu default)
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 22/tcp
ufw enable

# Or with iptables
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
```

### SSL certificate fails

Confirm DNS is correct first:
```bash
dig +short yourdomain.com
# Must show your VPS IP
```

Let's Encrypt has a rate limit of 5 certificate requests per domain per week. If you hit it, wait and try again. Use the staging environment to test:
```bash
# Edit scripts/deploy.sh, add --staging to the certbot certonly command
# Then request again (staging certs are not trusted by browsers but won't count against the rate limit)
```

### Admin panel shows 503

`ADMIN_PASSWORD` is not set or the api container hasn't started yet. Check:
```bash
docker compose ps api
docker compose logs api | grep ADMIN
```

### GitHub webhooks show "webhook not configured"

`GITHUB_WEBHOOK_SECRET` is not set or is empty in your `.env`. After adding it:
```bash
docker compose up -d api
```

### Scan jobs are stuck

If jobs are stuck in `running` state after a server restart (visible as no PR activity despite pushes), restart the api container:
```bash
docker compose restart api
```

On startup, the worker pool automatically resets stuck jobs and retries them.

---

## Architecture at a Glance

```
User Machine                    Your VPS (Docker)
────────────                    ──────────────────────────────────────
ciotx CLI          ──HTTPS──▶  nginx (TLS termination)
  │                                │
  │ ciotx scan .                   │  /v1/scan, /v1/status, /v1/history
  │ ciotx auth login               │  /admin,  /webhooks/github
  │ ciotx status                   ▼
  │                            Go API server
  │                              │        │
  │                              │        ▼
  │                         PostgreSQL   DeepSeek API
  │                         (licenses,   (internal — never
  │                          scan jobs,   visible to users)
  │                          history)
  │
  └──▶ Opens ciotx-report.html in browser

GitHub Repo ──push event──▶ /webhooks/github
                                │
                                ▼
                            Scan worker (background)
                            Fetches code via GitHub API
                            Runs discovery + audit
                            Opens fix PRs automatically
```

---

## Security Notes

- The DeepSeek API key is stored only inside the Docker container. It is never logged, never returned in API responses, and never visible to your users or their code.
- Users authenticate with license keys (`ciotx_...`). These are stored hashed in PostgreSQL and never returned in plaintext after creation.
- The admin panel is protected by a session cookie with HMAC-SHA256 signature. Sessions expire after 8 hours and are invalidated by server restart.
- Rate limiting is enforced at the nginx layer (10 requests/minute for scan endpoints, 60 requests/minute for admin) and in the Go application (per-key concurrency limit of 2 concurrent scans).
- PostgreSQL is not exposed to the host network — it is only reachable from other containers on the internal Docker bridge network.
- All containers run as non-root users.
