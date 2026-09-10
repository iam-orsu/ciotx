# ciotx — Complete Deployment Guide

This guide takes you from zero to a fully running ciotx instance — with GitHub PR integration enabled — on a fresh VPS. Follow every step in order. The whole thing takes about 15–20 minutes.

At the end, your friend will be able to run `ciotx scan .` on their laptop, see all the vulnerabilities in their repo, and every push they make will automatically open a GitHub pull request with the fix already written.

---

## What You Will Have When This Is Done

- `https://yourdomain.com` — your ciotx server, live and serving real traffic
- `https://yourdomain.com/admin` — your dashboard to issue and manage license keys
- `https://yourdomain.com/install.sh` — the one-liner your friends/customers run to install the CLI
- GitHub App installed on any repo → every push triggers a deep security scan → PRs with fixes open automatically
- Auto-renewing TLS certificate (Let's Encrypt)
- PostgreSQL database with automatic migrations

---

## Before You Start — Collect Everything

You need three things ready before you run a single command. Get them all first so you are not hunting for things mid-deploy.

### Thing 1 — DeepSeek API Key

ciotx uses DeepSeek's AI models internally. This key never leaves your server — your users never see it.

1. Go to **[platform.deepseek.com](https://platform.deepseek.com)**
2. Sign up or log in
3. Click **API Keys** in the left sidebar → **Create new secret key**
4. Copy the key (starts with `sk-`) — you need it in Step 5
5. Add credits to your account. A typical codebase scan costs **$0.01–$0.05**

---

### Thing 2 — GitHub App (Required for Auto-Scanning and Fix PRs)

This is what makes ciotx scan code automatically on every push and open pull requests with fixes. Do this before you deploy.

**Go to [github.com/settings/apps/new](https://github.com/settings/apps/new)**

Fill in the form exactly like this:

| Field | What to put |
|:------|:------------|
| **GitHub App name** | `ciotx` (or `ciotx-security`, must be globally unique) |
| **Homepage URL** | `https://yourdomain.com` (your actual domain from Step 3) |
| **Webhook** | Check **Active** |
| **Webhook URL** | `https://yourdomain.com/webhooks/github` |
| **Webhook secret** | Run `openssl rand -hex 32` in your terminal — paste the output here AND save it, you need it later |

Scroll down to **Repository permissions** and set:

| Permission | Level |
|:-----------|:------|
| **Contents** | Read and write |
| **Pull requests** | Read and write |
| **Metadata** | Read-only (auto-set) |

Scroll down to **Subscribe to events** and check:
- ✅ **Push**
- ✅ **Installation**

At the bottom, select **Any account** (so your customers can install it on their repos).

Click **Create GitHub App**.

**After creation — collect three values:**

**App ID** — shown right at the top of the App settings page under the App name. It's a number like `123456`. Copy it.

**Private Key** — scroll down to the **Private keys** section → click **Generate a private key**. A `.pem` file downloads to your computer. Do not lose it.

Now base64-encode the private key. Run this in your terminal (on your laptop, where the file downloaded):

```bash
# macOS / Linux
base64 -i your-app-name.2024-01-01.private-key.pem | tr -d '\n'

# If that doesn't work on Linux:
base64 -w 0 your-app-name.2024-01-01.private-key.pem
```

Copy the entire output — it will be one very long line starting with `LS0t...`. This is your `GITHUB_APP_PRIVATE_KEY_BASE64`.

**Webhook Secret** — this is what you generated with `openssl rand -hex 32` and pasted into the form. You saved it, right? That's your `GITHUB_WEBHOOK_SECRET`.

You now have three values:
- `GITHUB_APP_ID` = the number (e.g. `123456`)
- `GITHUB_APP_PRIVATE_KEY_BASE64` = the long base64 string
- `GITHUB_WEBHOOK_SECRET` = the hex string you generated

Keep these handy for Step 5.

---

### Thing 3 — A Domain Name Pointing at Your VPS

You need a domain with an A record pointing to your VPS IP. Let's Encrypt will not issue a certificate without this.

1. Get a VPS — any provider (DigitalOcean, Hetzner, Vultr, Linode, OVH). **Minimum 2 GB RAM**, Ubuntu 22.04 or 24.04 LTS.
2. Note its public IP (e.g. `123.45.67.89`)
3. In your domain registrar's DNS settings, add an A record:
   - **Name:** `api` (creates `api.yourdomain.com`) or `@` (root domain)
   - **Value:** your VPS IP
   - **TTL:** 300

Verify it propagated before continuing:
```bash
# Run this on your laptop
dig +short api.yourdomain.com
# Should print your VPS IP. If it prints nothing, wait 2–5 minutes and try again.
```

Do not proceed until `dig` returns the correct IP.

---

## Step 1 — SSH Into Your VPS

```bash
ssh root@YOUR_VPS_IP
```

Most VPS providers give you root access. If yours created a non-root user, run `sudo -i` after logging in.

---

## Step 2 — Open Your Firewall

Most VPS providers block ports by default. Open what you need:

```bash
# Ubuntu with UFW
ufw allow 22/tcp    # SSH (don't lock yourself out)
ufw allow 80/tcp    # HTTP (needed for SSL cert + ACME renewal)
ufw allow 443/tcp   # HTTPS
ufw --force enable
ufw status
```

---

## Step 3 — Clone the Repository

```bash
git clone https://github.com/iam-orsu/ciotx.git
cd ciotx
```

---

## Step 4 — Generate Your Secret Values

Run these on the VPS now. You will paste the output into `.env` in the next step.

```bash
# Master license key — your personal admin bypass key
echo "MASTER_LICENSE_KEY=ciotx_$(openssl rand -hex 32)"

# PostgreSQL password
echo "POSTGRES_PASSWORD=$(openssl rand -hex 32)"

# Admin dashboard password
echo "ADMIN_PASSWORD=$(openssl rand -base64 18 | tr -d '=+/' | cut -c1-24)"
```

Copy each output line. You need these in a moment.

---

## Step 5 — Configure Your Environment

```bash
cp .env.example .env
nano .env
```

Fill in every single value. Here is a completed example — replace everything with your real values:

```bash
# ── Your domain ────────────────────────────────────────────────────────
DOMAIN_NAME=api.yourdomain.com

# ── Your VPS public IP ─────────────────────────────────────────────────
VPS_SERVER_IP=123.45.67.89

# ── Email for Let's Encrypt ────────────────────────────────────────────
SSL_EMAIL=you@youremail.com

# ── DeepSeek API key (from Thing 1) ───────────────────────────────────
LLM_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# ── Generated secrets (from Step 4) ───────────────────────────────────
MASTER_LICENSE_KEY=ciotx_a1b2c3d4e5f6...your generated value...
POSTGRES_PASSWORD=a1b2c3d4e5f6...your generated value...
ADMIN_PASSWORD=YourGeneratedAdminPassword

# ── GitHub App (from Thing 2) ─────────────────────────────────────────
GITHUB_APP_ID=123456
GITHUB_APP_PRIVATE_KEY_BASE64=LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQo...
GITHUB_WEBHOOK_SECRET=a1b2c3d4e5f6...your webhook secret...
```

**Save the file:** `Ctrl+O` → `Enter` → `Ctrl+X`

> **Keep a secure backup of `.env`.** It contains your master key and all secrets. The `.gitignore` prevents it from being committed, but store a copy somewhere safe (password manager, encrypted note, etc.).

---

## Step 6 — Deploy

```bash
chmod +x scripts/deploy.sh
sudo ./scripts/deploy.sh
```

The script will:

1. **Validate** your `.env` — all required vars including GitHub credentials
2. **Install Docker** — if not already present
3. **Verify DNS** — confirms your domain resolves before touching certificates
4. **Get SSL certificate** — automatic via Let's Encrypt
5. **Build CLI binaries** — compiles `ciotx` for Linux, macOS, and Windows with your domain baked in as the API endpoint
6. **Build and launch Docker stack** — postgres, api server, nginx, certbot
7. **Health check** — polls your domain until it responds 200

You will see output like this:

```
══════════════════════════════════════════════
  Step 0 — Configuration
══════════════════════════════════════════════

[+] Configuration validated:
[*]   Domain : api.yourdomain.com
[*]   VPS IP : 123.45.67.89

══════════════════════════════════════════════
  Step 1 — Docker
══════════════════════════════════════════════

[+] Docker 27.3.1 already installed.

══════════════════════════════════════════════
  Step 3 — SSL Certificate
══════════════════════════════════════════════

[+] SSL certificate obtained for api.yourdomain.com!

══════════════════════════════════════════════
  Step 5 — Building & Deploying
══════════════════════════════════════════════

[*] Building Docker images (this takes a few minutes on first run)...
[*] Starting all services...
[+] Health check passed — API is live at https://api.yourdomain.com

╔══════════════════════════════════════════════╗
║         ciotx Deployed Successfully!         ║
╚══════════════════════════════════════════════╝

  API Endpoint  : https://api.yourdomain.com
  Admin Panel   : https://api.yourdomain.com/admin
  Install Script: https://api.yourdomain.com/install.sh

  Your master license key: ciotx_a1b2c3d4...
```

Total time: **5–10 minutes** on a fresh VPS.

---

## Step 7 — Log Into the Admin Dashboard

Open `https://yourdomain.com/admin` in your browser.

Enter the `ADMIN_PASSWORD` from your `.env`.

You will see:

- **Stats** — total licenses issued, scans today, scans this month, all-time scans
- **Licenses** — table of every license key you have issued, with org name, plan, monthly usage, and expiry
- **Recent Scans** — the last 50 scans across all customers, with finding counts and duration

The dashboard refreshes every 60 seconds automatically.

---

## Step 8 — Issue a License Key to Your Friend

You need to give your friend a license key before they can scan anything.

### Option A — From the Admin Dashboard (easiest)

1. Go to `https://yourdomain.com/admin`
2. Click **New License**
3. Fill in their org name, email, choose a plan, set the monthly scan limit
4. Click **Create**
5. Copy the key that appears — it looks like `ciotx_a3f2b1c4d5e6f7...`
6. Send it to them

### Option B — From the VPS command line

```bash
cd ~/ciotx

docker compose exec api /ciotx-server license create \
  --org "Your Friend's Company" \
  --email friend@theircompany.com \
  --plan pro \
  --scans 500
```

Output:
```
License created successfully
Key   : ciotx_a3f2b1c4d5e6f7a8b9c0...
Org   : Your Friend's Company
Email : friend@theircompany.com
Plan  : pro
Scans : 500/month
```

Send them the key.

---

## Step 9 — Install the GitHub App on Your Friend's Repo

Go to your GitHub App's settings page:
`https://github.com/settings/apps/YOUR-APP-NAME`

Click **Install App** in the left sidebar.

Click **Install** next to your friend's GitHub account or their organization.

Choose **All repositories** or select specific repos.

Click **Install**.

That's it. The App is now watching every push to their repos.

---

## Step 10 — Your Friend's Laptop

Send your friend these three things:
1. Their license key (`ciotx_...`)
2. The install command (or just the domain so they can get it themselves)
3. The instructions below

---

### What Your Friend Does — Step by Step

**They need:** their laptop (macOS, Linux, or Windows), their GitHub repo cloned locally, and the license key you sent them.

---

#### Install the ciotx CLI

Open a terminal and run:

```bash
curl -fsSL https://yourdomain.com/install.sh | sh
```

This downloads the right binary for their OS and architecture and puts it in `/usr/local/bin/ciotx`. Takes about 5 seconds.

Verify it worked:
```bash
ciotx --help
```

---

#### Connect to Your ciotx Server

```bash
ciotx auth login
```

They will see:
```
Enter your license key: _
```

They paste the key you sent them (`ciotx_a3f2b1...`) and press Enter.

```
✓ License verified
  Organization : Your Friend's Company
  Plan         : pro
  Scans used   : 0 / 500 this month
  Status       : active

Logged in. Run 'ciotx scan .' to scan your current directory.
```

The key is saved to `~/.ciotx/config.json` on their machine. They only need to do this once.

---

#### Scan Their Codebase

```bash
cd /path/to/their/project
ciotx scan .
```

They will see a progress indicator as the scan runs:

```
ciotx — Security Auditor
  Version  : 1.0.0
  Endpoint : https://api.yourdomain.com

  Ingesting codebase...
  ✓ 47 files  |  12,304 lines  |  6 chunks

  Running analysis... (this takes 1–5 minutes)

  ✓ Discovery complete
  ✓ Verification complete  — 3 hallucinations dropped
  ✓ Audit complete         — 1 false positive filtered

  ─────────────────────────────────────────────────
  Found 4 confirmed vulnerabilities
  ─────────────────────────────────────────────────
  Critical  2   ██████████
  High      1   █████
  Medium    1   █████
  Low       0

  Report saved:
    ciotx-report.html
    ciotx-report.json
```

They open `ciotx-report.html` in their browser. The report shows:
- Every confirmed vulnerability with severity badge
- Exact file name and line number
- The vulnerable code highlighted
- A description of how it can be exploited
- Step-by-step remediation guidance
- Filterable by severity, searchable by file name

---

#### The GitHub PR Part — What Happens Automatically

As soon as your friend pushes any commit to their default branch (main/master):

1. GitHub sends a push webhook to `https://yourdomain.com/webhooks/github`
2. Your server enqueues a scan job
3. A background worker fetches the full repo code via the GitHub API
4. It runs the same discovery + verification + audit pipeline
5. For every Critical and High severity finding, it generates a code fix
6. It opens a pull request on their repo with the fix already written

Their repo now has pull requests that look like:

```
PR: fix: CWE-89 SQL Injection — db/users.go:43
 
Branch: ciotx/fix-cwe-89-a3f2b1c4

ciotx detected a confirmed SQL Injection vulnerability:

File: db/users.go
Line: 43
Evidence: db.Exec("SELECT * FROM users WHERE id = " + userID)

This fix replaces string concatenation with a parameterized query,
eliminating the injection vector.

--- db/users.go
+++ db/users.go
@@ -41,7 +41,7 @@
 func GetUser(db *sql.DB, userID string) (*User, error) {
-    row := db.QueryRow("SELECT * FROM users WHERE id = " + userID)
+    row := db.QueryRow("SELECT * FROM users WHERE id = $1", userID)
     ...
 }
```

Your friend reviews the PR, merges it, done.

---

#### Other Commands Your Friend Can Run

```bash
# Check account status and monthly usage
ciotx status

# See the last 10 scans with finding counts
ciotx history

# See the last 20 scans
ciotx history --limit 20

# Scan a specific directory
ciotx scan /path/to/project
```

---

## Managing Licenses

```bash
# See all issued keys, their usage, and plan
docker compose exec api /ciotx-server license list

# Revoke a key immediately (blocks all further scans)
docker compose exec api /ciotx-server license revoke ciotx_a3f2b1c4...

# See per-license scan history
docker compose exec api /ciotx-server license stats
```

---

## Useful Commands on the VPS

```bash
# Live logs from all containers
docker compose logs -f

# Live logs from just the API (see every scan, webhook, etc.)
docker compose logs -f api

# Check if all containers are running
docker compose ps

# Restart just the API server (e.g. after changing .env)
docker compose restart api

# Full stop
docker compose down

# Start everything again
docker compose up -d
```

---

## Updating ciotx

```bash
cd ~/ciotx
git pull
sudo ./scripts/deploy.sh
```

The script rebuilds images and runs any new database migrations. Existing licenses, scan history, and data are preserved.

---

## Troubleshooting

### "webhook not configured" error from GitHub

Your `GITHUB_WEBHOOK_SECRET` in `.env` is empty or wrong. Fix:
```bash
nano .env   # set GITHUB_WEBHOOK_SECRET to what you entered in the GitHub App form
docker compose restart api
```

### Scan workers not starting / no PRs opening

Check that `GITHUB_APP_ID` is set:
```bash
docker compose logs api | grep -i github
# Should show: "github scan workers started count=2"
# If it shows: "GITHUB_APP_ID not set" — edit .env and restart
```

### GitHub App says "delivery failed"

Check if your server is reachable:
```bash
curl -s https://yourdomain.com/health
# Should return: {"status":"ok","service":"ciotx"}
```

If it doesn't respond, check `docker compose ps` and `docker compose logs nginx`.

### Health check fails during deploy

```bash
docker compose logs api
# Common causes:
# - LLM_API_KEY wrong → "missing required environment variable"
# - Port 80/443 blocked → check firewall (Step 2)
# - DNS not propagated → check 'dig +short yourdomain.com'
```

### SSL certificate fails

```bash
# Check DNS first
dig +short yourdomain.com   # must return your VPS IP

# Let's Encrypt rate-limits to 5 certificates per domain per week.
# If you hit the limit, wait 1 week, or use a different subdomain.
```

### Stuck scan jobs (no PRs after pushes)

```bash
docker compose restart api
# The worker pool auto-resets any stuck jobs on startup
```

---

## Architecture

```
Your Friend's Machine            Your VPS (Docker Compose)
─────────────────────            ─────────────────────────────────────
ciotx CLI
 │
 │  ciotx auth login             ┌─ nginx (TLS, rate limiting) ─────┐
 │  ciotx scan .      ──HTTPS──▶ │                                   │
 │                               │  /v1/scan      → Go API server    │
 │                               │  /v1/status    → Go API server    │
 │  ciotx-report.html            │  /admin        → Go API server    │
 └─ opens in browser             │  /install.sh   → served static    │
                                 │  /releases/    → CLI binaries     │
                                 └───────────────────────────────────┘
                                           │
                                           ├── PostgreSQL
                                           │   licenses, scan history,
                                           │   scan_jobs queue
                                           │
                                           └── DeepSeek API (internal)
                                               discovery + audit models
                                               never visible to users

Their GitHub Repo
 │
 │  git push main    ──webhook──▶ /webhooks/github
 │                                       │
 │                               Background worker
 │                               1. Fetches repo via GitHub API
 │                               2. Runs discovery + audit
 │                               3. Generates code fixes
 │                               4. Opens PRs on their repo  ──▶ PR created ✓
 │
 └── Merges the fix PR
```

---

## Security

- **Your AI key is invisible to users.** DeepSeek's API key is a constant inside the Docker container. It never appears in logs, responses, or error messages.
- **Users only see your domain.** The CLI bakes in `https://yourdomain.com` at compile time. There is no way for users to change the endpoint.
- **License keys are one-way.** Keys are stored in PostgreSQL and validated server-side. You revoke a key in one command and it stops working immediately.
- **Admin sessions expire in 8 hours** and are signed with a random HMAC key that changes on every server restart.
- **PostgreSQL is internal only.** The database port is never exposed outside the Docker network.
- **Rate limiting is in nginx.** 10 scan requests per minute per IP, 60 admin requests per minute per IP. DoS from any single IP is bounded.
