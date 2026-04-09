# Quick Start

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Go | 1.20+ | `go version` |
| Node.js | 18+ | `node --version` |
| msfconsole | any | `which msfconsole` |
| nmap | any | `which nmap` |
| PostgreSQL | 12+ | Optional — omit for in-memory mode |

---

## Option A — Zero-Config (In-Memory Store)

No database setup required. All data is lost on restart.

**1. Configure the backend**

```bash
cat > backend/.env <<'EOF'
JWT_SECRET=change-this-to-a-long-random-string
EOF
```

**2. Start everything**

```bash
chmod +x start.sh
./start.sh
```

Backend starts on `http://localhost:8080`, frontend on `http://localhost:3000`.

**3. Open the app**

Navigate to `http://localhost:3000`, register an account, and log in.

---

## Option B — PostgreSQL (Persistent Storage)

**1. Set up the database**

```bash
chmod +x setup-postgres.sh
sudo ./setup-postgres.sh
```

Or manually:

```bash
sudo systemctl start postgresql
sudo -u postgres createdb msf_web
```

**2. Configure the backend**

```bash
cat > backend/.env <<'EOF'
JWT_SECRET=change-this-to-a-long-random-string
DATABASE_URL=postgresql://postgres:@localhost:5432/msf_web?sslmode=disable
EOF
```

**3. Start everything**

```bash
chmod +x start.sh
./start.sh
```

---

## First Use

### Create a project

1. Log in and click **New Project**.
2. Enter a name and your target network range (e.g. `192.168.1.0/24`).
3. Click **Scan Network** to run a ping sweep and discover live hosts.
4. Click **Add as Session** next to any discovered host.

### Work a session

Open a session to reach the main workspace. The MSF Console is always visible on the right. The left panel has six action tabs:

| Tab | What it does |
|---|---|
| **Vulnerability Scan** | Runs `nmap -sV -O --script=vuln,vulners` against the target. Scan runs in the background — navigate away freely. |
| **Enumeration** | Parses the scan XML into a service list and suggests Metasploit modules per service. |
| **CVE Analysis** | Aggregates CVEs from all sessions in the project, fetches CVSS scores, and searches GitHub for public PoCs. |
| **Shells** | Lists active MSF sessions. Interact, upgrade to Meterpreter, background, or kill. Auto-refreshes when a new session opens. |
| **Post Exploitation** | Quick-command buttons and recommended modules filtered by session type and OS. Output is parsed for credentials, hashes, and other loot. |
| **Report** | Generates a structured engagement report covering the full session. |

### MSF Console tips

- Type commands directly in the console input at the bottom of the screen.
- Arrow keys cycle through command history.
- The console auto-reconnects if the connection drops.
- When you **Interact** with a shell or Meterpreter session, the console enters that session. Panel actions that need the MSF prompt (e.g. running modules, listing sessions) will automatically background the active session first.

---

## Stopping

Press `Ctrl+C` in the terminal running `start.sh`. Both the backend and frontend are stopped cleanly.

---

## Production Build

Build a single static binary that serves the React app on port 8080:

```bash
# Build the React frontend
cd frontend
npm run build          # output → frontend/build/

# Build and run the Go backend
cd ../backend
go build -o msf-server
./msf-server
```

Set additional environment variables in `backend/.env` for production:

```
COOKIE_SECURE=true
ALLOWED_ORIGIN=https://your-domain.example.com
```

---

## Troubleshooting

**`msfconsole` not found**
Add `MSFCONSOLE_PATH=/full/path/to/msfconsole` to `backend/.env`.

**WebSocket disconnects immediately**
Check that `JWT_SECRET` is set in `backend/.env`. A missing secret causes token validation to fail and the WS connection to close.

**Scan never completes**
Scan output is written to `/tmp/msf-scans/`. Check that directory for `.txt` and `.xml` files. Errors are written to `<ip>-output.txt.err`.

**Port 3000 already in use**
`npm start` will offer to use a different port. The frontend proxy is configured for port 8080, so the backend port must not change.

**PostgreSQL connection refused**
Verify `sudo systemctl status postgresql` and that the `msf_web` database exists: `sudo -u postgres psql -l`.
