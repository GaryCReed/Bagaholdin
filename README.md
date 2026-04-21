# Bagaholdin

> **Legal Notice:** This tool is intended **solely for educational purposes** and for use on networks you own or have **explicit written permission** to test. Unauthorised use against systems you do not own or have permission to access is illegal and unethical. The authors accept no liability for misuse.

A Metasploit Pro-style web interface for managing penetration test engagements. Bagaholdin is currently in a **workable state** — core features function as described, but it is under active development and not production-hardened. Expect rough edges, and treat it as a learning platform rather than a finished tool.

Each project groups target hosts into sessions, providing a live msfconsole terminal, automated scanning, CVE analysis, post-exploitation tooling, loot extraction, and structured report generation — all through a browser.

---

## Status

This project is **workable, not finished.** The following areas are functional:

- Project and session management
- Live msfconsole console over WebSocket
- nmap-based network and vulnerability scanning
- CVE lookup and GitHub PoC search
- Post-exploitation quick commands and loot extraction
- Engagement report generation

Known rough edges exist across the UI and backend. Contributions and issues are welcome.

---

## Features

- **Projects and network scanning** — Group targets under a project. Discover live hosts with an nmap ping sweep and add them as sessions in one click.
- **Live msfconsole console** — Each session spawns a dedicated msfconsole process. Commands stream in real-time via WebSocket with command history and auto-reconnect.
- **Vulnerability scanner** — Runs `nmap -sV -O --osscan-guess --script=vuln,vulners` against the target and parses results into a structured service list with OS detection.
- **Enumeration panel** — Parses nmap XML output and maps each open port to relevant Metasploit modules, filtered by OS and service type.
- **CVE analysis** — Aggregates CVEs found across all sessions in a project, fetches CVSS scores from NVD, and searches GitHub for public PoC repositories.
- **Shells panel** — Lists active msfconsole sessions. Supports interact, upgrade shell to Meterpreter, background, and kill. Auto-refreshes when a new session opens.
- **Post exploitation** — Quick-command buttons and recommended module lists filtered by session type (Meterpreter/shell) and OS (Linux/Windows).
- **Loot extraction** — Post-ex command output is parsed automatically for credentials, hashes, user accounts, system info, and other artefacts, saved to a per-session loot file.
- **Report generation** — Produces a structured engagement report covering scan summary, CVE findings, post-ex output, and extracted loot.
- **Authentication** — JWT-based login stored in an httpOnly cookie. Bcrypt password hashing.
- **Storage** — SQLite for persistent storage, or in-memory store for zero-config use.

---

## Quick Start

See [QUICKSTART.md](QUICKSTART.md).

---

## Technology Stack

| Layer | Technology |
|---|---|
| Backend | Go 1.20+, Chi router, Gorilla WebSocket |
| Frontend | React 18, TypeScript, React Router |
| Database | SQLite (default) or in-memory |
| Auth | JWT (httpOnly cookie, 24-hour expiry, bcrypt) |
| Scanning | nmap |
| Console | msfconsole (one process per session) |

---

## Project Structure

```
.
├── backend/
│   ├── main.go          # Router, all HTTP handlers, server entry point
│   ├── db.go            # Database models, queries (SQLite + in-memory)
│   ├── auth.go          # JWT generation, validation, cookie helpers
│   ├── websocket.go     # WebSocket upgrade, session fan-out broadcaster
│   ├── executor.go      # msfconsole process lifecycle, stdin/stdout fan-out
│   ├── scanner.go       # nmap execution, XML parsing, OS/service detection
│   ├── loot.go          # Post-ex output parsing, loot XML persistence
│   ├── env.go           # .env loader
│   ├── helpers.go       # JSON encoding utilities
│   └── go.mod
├── frontend/
│   └── src/
│       └── components/
│           ├── LoginPage.tsx       # Login
│           ├── ProjectsPage.tsx    # Project list, create project, network info
│           ├── Dashboard.tsx       # Network scanner, session cards
│           ├── SessionDetail.tsx   # Main workspace (all action panels)
│           ├── Console.tsx         # Live msfconsole terminal
│           └── ReportPage.tsx      # Engagement report
├── docs/
├── start.sh             # Start backend + frontend together
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
  │
  ▼
Open Session
  │
  ├─► 1. Vulnerability Scan   nmap -sV -O --script=vuln,vulners
  │
  ├─► 2. Enumeration          Services + MSF modules from scan XML
  │
  ├─► 3. CVE Analysis         CVEs → NVD scores → GitHub PoCs
  │
  ├─► 4. Shells               Manage active MSF sessions
  │
  ├─► 5. Post Exploitation    Quick commands + recommended modules
  │
  └─► 6. Report               Structured engagement report
```

The MSF Console is always visible alongside the action panels. Commands typed there go directly to the session's msfconsole process; output from any panel action also streams through the console.

---

## API Reference

### Auth (public)
| Method | Path | Description |
|---|---|---|
| POST | `/api/auth/login` | Login, sets cookie |
| POST | `/api/auth/logout` | Clear cookie |

### Projects
| Method | Path | Description |
|---|---|---|
| GET | `/api/projects` | List user's projects |
| POST | `/api/projects` | Create project |
| GET | `/api/projects/{id}` | Get project |
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
| GET | `/api/sessions/{id}/vuln-scan` | Poll scan status / results |
| POST | `/api/sessions/{id}/enumerate` | Parse scan XML into service list |
| POST | `/api/sessions/{id}/cve-analysis` | Run CVE analysis across project |
| POST | `/api/sessions/{id}/shell` | Send command to msfconsole, return output |
| GET | `/api/sessions/{id}/msf-sessions` | List active MSF sessions |
| POST | `/api/sessions/{id}/loot` | Save loot from post-ex output |
| GET | `/api/sessions/{id}/loot` | Retrieve session loot |

### Other
| Method | Path | Description |
|---|---|---|
| GET | `/api/ws?session={id}` | WebSocket — live msfconsole stream |
| GET | `/api/network` | Local network interfaces |
| GET | `/api/health` | Health check |

---

## Environment Variables

Create `backend/.env`:

```
# Required
JWT_SECRET=change-this-to-a-long-random-string

# Database — omit for default SQLite, or set to memory:// for in-memory store
DATABASE_URL=postgresql://postgres:@localhost:5432/msf_web?sslmode=disable

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

# 2. Build and run the Go backend (serves API + static files on :8080)
cd ../backend
go build -o msf-server
./msf-server
```

The Go binary serves the React build as static files, so only port 8080 needs to be exposed.

---

## Security Notes

- All protected routes require a valid JWT cookie set at login.
- Passwords are hashed with bcrypt (cost 10).
- Auth routes are rate-limited to 10 requests per minute per IP.
- The WebSocket endpoint validates the JWT before upgrading the connection.
- Set `COOKIE_SECURE=true` and `ALLOWED_ORIGIN` when deploying over HTTPS.
- **Only use this tool on networks you own or have explicit written authorisation to test.**

---

## Legal

This software is provided for **educational purposes only**. Use it to learn about penetration testing concepts in a controlled lab environment, on your own systems, or on systems where you hold explicit written permission from the owner.

**Do not use this tool against systems you do not own or are not authorised to test.** Doing so is illegal in most jurisdictions and carries serious consequences. The authors and contributors accept no responsibility for any unlawful use.

---

## License

MIT
