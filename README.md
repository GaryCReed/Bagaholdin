# Bagaholdin

> **Legal Notice:** This tool is intended **solely for educational purposes** and for use on networks you own or have **explicit written permission** to test. Unauthorised use against systems you do not own or have permission to access is illegal and unethical. The authors accept no liability for misuse.

A Metasploit Pro-style web interface for managing penetration test engagements. Bagaholdin is in a **workable state** — core features function as described, but it is under active development and not production-hardened. Treat it as a learning platform rather than a finished tool.

Each project groups target hosts into sessions, providing a live msfconsole terminal, automated scanning, CVE analysis, post-exploitation tooling, loot extraction, WiFi attack support, and structured report generation — all through a browser.

---

## Features

### Project Management
- **Projects and network scanning** — Group targets under a named project with a network range. Discover live hosts with an nmap ping sweep and add them as sessions with a single click. Select multiple hosts and add them in bulk.
- **Network Topology** — Visual SVG map of all hosts discovered within a project. Hosts are colour-coded by worst CVE severity (Critical/High/Medium/Low/Clean/Offline) with Bezier connectors from the inferred gateway node. Shows IP, hostname, OS, open port count, and CVE count per node.
- **Project Report** — Aggregated professional penetration test report across all sessions in a project. Covers cover page, table of contents, executive summary with KPI boxes and charts, host summaries, consolidated CVE findings with remediation advice, post-exploitation findings, and a legal disclaimer. Print-ready PDF output.

### Per-Session Workspace
- **Live msfconsole console** — Each session spawns a dedicated msfconsole process. Commands stream in real-time via WebSocket with command history and auto-reconnect.
- **Vulnerability scanner** — Runs `nmap -sV -O --osscan-guess --script=vuln,vulners` against the target and parses results into a structured service list with OS detection.
- **Enumeration panel** — Parses nmap XML output and maps each open port to relevant Metasploit modules, filtered by OS and service type.
- **CVE analysis** — Fetches CVEs from NVD, enriches with CVSS scores and GitHub public PoC repositories. Results are persisted in the database (not just the browser) so they survive navigation and appear in project-level reports.
- **Shells panel** — Lists active msfconsole sessions. Supports interact, upgrade shell to Meterpreter, background, and kill. Auto-refreshes when a new session opens.
- **Post exploitation** — Quick-command buttons and recommended module lists filtered by session type (Meterpreter/shell) and OS (Linux/Windows). Output is automatically parsed for credentials, hashes, user accounts, system info, and other artefacts.
- **Loot extraction** — Post-ex command output is parsed and saved to a per-session loot store. Visible in the session report and project report.
- **Session Report** — Structured engagement report covering scan summary, NSE findings, CVE analysis with remediation, post-exploitation output, and extracted loot. Print-ready PDF output.
- **Notes** — Free-text notes saved per session.
- **Searchsploit** — Search the local Exploit-DB copy for modules matching the target's services.

### Password Attacks
- **Hashcat** — GPU-accelerated WPA/WPA2 handshake cracking. Upload `.cap`/`.hccapx` files. Select from 50+ ISP-derived mask presets grouped by router/SSID family (BT Hub, TALKTALK, Virgin Media, Orange, Sky, Plusnet, and more), or enter a custom mask. Supports custom charset arguments (`-1`) for restricted keyspaces.
- **WiFi handshake capture** — Monitor mode management, target AP scanning, and handshake capture via airodump-ng, all from the browser.
- **Bruteforce** — Hydra-based credential brute-forcing against network services.

### Infrastructure
- **Authentication** — JWT-based login stored in an httpOnly cookie. Bcrypt password hashing.
- **Storage** — SQLite by default (file created next to the binary). PostgreSQL supported. In-memory store for zero-config use.
- **Binary portability** — The binary resolves `.env` and the SQLite database relative to its own location, so it can be run from any working directory.

---

## Quick Start

See [QUICKSTART.md](QUICKSTART.md).

---

## Technology Stack

| Layer | Technology |
|---|---|
| Backend | Go 1.20+, Chi router, Gorilla WebSocket |
| Frontend | React 18, TypeScript, React Router |
| Database | SQLite (default) or PostgreSQL or in-memory |
| Auth | JWT (httpOnly cookie, 24-hour expiry, bcrypt) |
| Scanning | nmap |
| Console | msfconsole (one process per session) |
| Password attacks | hashcat, hydra, aircrack-ng suite |

---

## Project Structure

```
.
├── backend/
│   ├── main.go          # Router, all HTTP handlers, server entry point
│   ├── db.go            # Database models, queries (SQLite + PostgreSQL + in-memory)
│   ├── auth.go          # JWT generation, validation, cookie helpers
│   ├── websocket.go     # WebSocket upgrade, session fan-out broadcaster
│   ├── executor.go      # msfconsole process lifecycle, stdin/stdout fan-out
│   ├── scanner.go       # nmap execution, XML parsing, OS/service detection
│   ├── loot.go          # Post-ex output parsing, loot persistence
│   ├── env.go           # .env loader
│   ├── helpers.go       # JSON encoding utilities
│   └── go.mod
├── frontend/
│   └── src/
│       └── components/
│           ├── LoginPage.tsx           # Login
│           ├── ProjectsPage.tsx        # Project list and creation
│           ├── Dashboard.tsx           # Network scanner, session list, topology/report buttons
│           ├── SessionDetail.tsx       # Main workspace (all action panels)
│           ├── Console.tsx             # Live msfconsole terminal
│           ├── ReportPage.tsx          # Per-session engagement report
│           ├── ProjectReportPage.tsx   # Aggregated project-level report
│           └── TopographyPage.tsx      # Graphical network topology map
├── docs/
├── start.sh             # Start backend + frontend dev server together
├── install.sh           # Build frontend + binary for production
├── QUICKSTART.md
└── README.md
```

---

## Workflow

```
Login
  │
  ▼
Create Project  ──►  Scan Network  ──►  Add Hosts as Sessions
  │                       │
  │                       ├──► Network Topology  (graphical host map)
  │                       └──► Project Report    (aggregated PDF report)
  │
  ▼
Open Session
  │
  ├─► 1. Vulnerability Scan      nmap -sV -O --script=vuln,vulners
  │
  ├─► 2. Enumeration             Services + MSF modules from scan XML
  │
  ├─► 3. CVE Analysis            CVEs → NVD CVSS scores → GitHub PoCs → DB
  │
  ├─► 4. Shells                  Manage active MSF sessions
  │
  ├─► 5. Post Exploitation       Quick commands + recommended modules + loot
  │
  ├─► 6. Password Attacks        Hashcat (WiFi), Hydra (services)
  │
  └─► 7. Report                  Per-session structured report (PDF)
```

The MSF Console is always visible alongside the action panels. Commands typed there go directly to the session's msfconsole process; output from any panel action also streams through the console.

---

## API Reference

### Auth (public)
| Method | Path | Description |
|---|---|---|
| POST | `/api/auth/login` | Login, sets httpOnly JWT cookie |
| POST | `/api/auth/logout` | Clear cookie |

### Projects
| Method | Path | Description |
|---|---|---|
| GET | `/api/projects` | List user's projects |
| POST | `/api/projects` | Create project |
| GET | `/api/projects/{id}` | Get project |
| PUT | `/api/projects/{id}` | Update project |
| DELETE | `/api/projects/{id}` | Delete project and all sessions |
| GET | `/api/projects/{id}/sessions` | List sessions in project |
| POST | `/api/projects/{id}/sessions` | Add session to project |
| GET | `/api/projects/{id}/hosts` | List discovered hosts |
| POST | `/api/projects/{id}/scan` | Run nmap ping sweep |

### Sessions
| Method | Path | Description |
|---|---|---|
| GET | `/api/sessions` | List all user sessions |
| POST | `/api/sessions` | Create standalone session |
| GET | `/api/sessions/{id}` | Get session |
| DELETE | `/api/sessions/{id}` | Delete session |

### Session Actions
| Method | Path | Description |
|---|---|---|
| POST | `/api/sessions/{id}/vuln-scan` | Start vulnerability scan (async) |
| GET | `/api/sessions/{id}/vuln-scan` | Poll scan status and results |
| POST | `/api/sessions/{id}/enumerate` | Parse scan XML into service list |
| POST | `/api/sessions/{id}/cve-analysis` | Run CVE analysis |
| GET | `/api/sessions/{id}/cve-results` | Retrieve stored CVE results |
| POST | `/api/sessions/{id}/cve-results` | Save CVE results to database |
| POST | `/api/sessions/{id}/shell` | Send command to msfconsole |
| GET | `/api/sessions/{id}/msf-sessions` | List active MSF sessions |
| POST | `/api/sessions/{id}/loot` | Save loot from post-ex output |
| GET | `/api/sessions/{id}/loot` | Retrieve session loot |
| GET | `/api/sessions/{id}/notes` | Retrieve session notes |
| POST | `/api/sessions/{id}/notes` | Save session notes |
| GET | `/api/sessions/{id}/searchsploit` | Search Exploit-DB |
| POST | `/api/sessions/{id}/bruteforce` | Start Hydra bruteforce |
| GET | `/api/sessions/{id}/bruteforce` | Poll bruteforce status |
| DELETE | `/api/sessions/{id}/bruteforce` | Stop bruteforce |
| POST | `/api/sessions/{id}/hashcat` | Start hashcat job |
| GET | `/api/sessions/{id}/hashcat` | Poll hashcat status |
| DELETE | `/api/sessions/{id}/hashcat` | Stop hashcat job |

### Other
| Method | Path | Description |
|---|---|---|
| GET | `/api/ws?session={id}` | WebSocket — live msfconsole stream |
| GET | `/api/network` | Local network interfaces |
| GET | `/api/health` | Health / auth check |

---

## Environment Variables

Create `backend/.env`:

```env
# Required
JWT_SECRET=change-this-to-a-long-random-string

# Database — omit for SQLite next to the binary, or set to memory:// for in-memory
DATABASE_URL=sqlite3://bagaholdin.db

# Optional
MSFCONSOLE_PATH=/usr/bin/msfconsole   # defaults to 'msfconsole' on PATH
COOKIE_SECURE=true                     # set in production (HTTPS only)
ALLOWED_ORIGIN=https://your-domain     # restrict WebSocket origin in production
```

---

## Building for Production

```bash
# 1. Build the React frontend
cd frontend
npm run build          # output → frontend/build/

# 2. Build the Go backend (serves API + static files on :8080)
cd ../backend
go build -o bagaholdin .
./bagaholdin
```

Or use the provided script:

```bash
chmod +x install.sh
./install.sh           # builds frontend then compiles backend/bagaholdin
```

The binary serves the React build as static files. Only port 8080 needs to be exposed. The `.env` file and SQLite database are resolved relative to the binary, so the binary can be run from any directory.

---

## Security Notes

- All protected routes require a valid JWT cookie set at login.
- Passwords are hashed with bcrypt (cost 10).
- Auth routes are rate-limited to 10 requests per minute per IP.
- The WebSocket endpoint validates the JWT before upgrading.
- Set `COOKIE_SECURE=true` and `ALLOWED_ORIGIN` when deploying over HTTPS.
- **Only use this tool on networks you own or have explicit written authorisation to test.**

---

## Legal

This software is provided for **educational purposes only**. Use it to learn about penetration testing concepts in a controlled lab environment, on your own systems, or on systems where you hold explicit written permission from the owner.

**Do not use this tool against systems you do not own or are not authorised to test.** Doing so is illegal in most jurisdictions and carries serious consequences. The authors and contributors accept no responsibility for any unlawful use.

---

## License

MIT
