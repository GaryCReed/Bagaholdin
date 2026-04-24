# Bagaholdin — Development Guide

## Architecture Overview

Bagaholdin is a single Go binary that embeds the compiled React frontend and serves everything on port 8080.

```
frontend/          React 18 + TypeScript source
frontend/build/    Production build (npm run build)
backend/ui/        Copy of frontend/build — embedded into binary at compile time
backend/           Go source (Chi router, Gorilla WebSocket, CGo SQLite)
backend/bagaholdin Compiled binary (gitignored)
```

### Build Pipeline

**Critical:** The binary embeds `backend/ui/` at compile time via `//go:embed all:ui` in `embed.go`. You must copy the frontend build into that directory before compiling or the binary will serve a stale UI.

```bash
# Full production build (use install.sh or do manually):
cd frontend && npm run build
rm -rf ../backend/ui && cp -r build ../backend/ui
cd ../backend && go build -o bagaholdin .
./bagaholdin        # serves on :8080, opens browser automatically
```

For development (hot reload):
```bash
# Terminal 1 — backend API
cd backend && go run .

# Terminal 2 — frontend dev server (proxies /api to :8080)
cd frontend && npm start     # opens :3000, hot reloads on save
```

---

## Backend

### Entry Point

`backend/main.go` — HTTP router setup, all handler registrations, server startup, browser launch.

Key functions:
- `baseDir()` — resolves the directory the binary lives in; used to anchor `.env` and SQLite paths so the binary can be run from any working directory
- `init()` — loads `.env` from `baseDir()/.env`, re-reads `JWT_SECRET` after `.env` is loaded
- `main()` — mounts router, serves embedded static files, starts `http.ListenAndServe(:8080)`, opens default browser after 500 ms

### Router

All protected routes sit under Chi middleware that validates the JWT cookie. Public routes: `POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/ws` (WebSocket, validates JWT before upgrade).

### Database

`backend/db.go` — supports three backends, selected via `DATABASE_URL`:

| Value | Backend |
|---|---|
| unset or `sqlite3://…` | SQLite (CGo, file next to binary) |
| `memory://` | In-memory (MemoryDB struct, no persistence) |
| `postgresql://…` | PostgreSQL (lib/pq driver) |

Default: SQLite file `bagaholdin.db` created next to the binary.

**Schema tables:** `users`, `sessions`, `projects`, `project_hosts`, `exploits`, `commands`, `cve_results`

`SaveCVEResults` / `GetCVEResults` store CVE analysis as a raw JSON blob (one row per session, upsert on conflict).

### Authentication

`backend/auth.go` — Linux PAM authentication via `authenticateLinuxUser()`. JWT signed with `JWT_SECRET` (HS256, 24 h expiry), stored as an httpOnly cookie. `COOKIE_SECURE=true` enables the Secure flag for HTTPS deployments.

Auth routes are rate-limited to 10 req/min per IP via `httprate`. All mutating session-action routes are rate-limited to 120 req/min per IP.

### WebSocket / MSF Console

`backend/websocket.go` — upgrades the connection, validates JWT, fans output from the session's msfconsole executor to all connected clients.

`backend/executor.go` — manages one `msfconsole -q` process per session. Commands sent via `ExecuteCommand(cmd)` write to msfconsole stdin; stdout/stderr are fanned out to a broadcaster. Handles reconnection and process restart.

### Scanner

`backend/scanner.go` — wraps nmap. Vuln scan runs asynchronously: nmap writes XML to `/tmp/msf-scans/<ip>.xml` then the handler parses services, OS info, and NSE script output. Results polled via `GET /api/sessions/{id}/vuln-scan`.

CVE analysis (`handleCVEAnalysis`) greps the MSF module tree for matching CVE strings and returns module paths alongside the CVE identifiers found in the nmap XML.

### Loot System

`backend/loot.go` — all post-exploitation artefacts are written to `/tmp/loot-{sessionID}.xml` as a structured XML document.

**Loot item types and their sources:**

| Type | Trigger |
|---|---|
| `credential` | hashdump, smart_hashdump, mimipenguin, lsa_secrets, cachedump output |
| `session_credential` | msfconsole session-opened event |
| `bruteforce_credential` | Hydra found line |
| `current_user` | getuid / whoami / id output |
| `system_info` | sysinfo / systeminfo / uname / ver output |
| `privileges` | getprivs / whoami /all |
| `groups` | group membership lines |
| `user_account` | /etc/passwd entries |
| `user_list` | net user output |
| `network_hosts` | arp output |
| `privilege_escalation` | getsystem result |
| `is_admin` | is_admin output |
| `environment` | env / set output (filtered for secret/key/pass/token) |
| `wifi_handshake` | Handshake capture complete |
| `sqlmap_finding` | sqlmap scan findings |
| `wpscan_finding` | wpscan findings |
| `ad_discovery` | nmap ldap-rootdse / smb-os-discovery output |
| `kerbrute_users` | kerbrute VALID USERNAME lines |
| `smb_enum` | enum4linux / enum4linux-ng output |
| `crackmapexec_finding` | crackmapexec [+] success lines |

`AppendLoot(sessionID, target, cmd, output)` is the main entry point — it calls `extractLoot()` which dispatches to per-type parsers based on the `cmd` string.

### Async Job Pattern

Long-running tools (Hydra, hashcat, sqlmap, feroxbuster, wpscan, crackmapexec) follow the same pattern:

1. `POST /sessions/{id}/tool` — start: create job struct with `cmd.Process`, store in `sync.Map`, begin goroutine that streams output to a buffer
2. `GET /sessions/{id}/tool` — poll: return current output + done flag
3. `DELETE /sessions/{id}/tool` — stop: call `Process.Kill()`, mark done

Job state is stored in package-level `sync.Map` (not the database). State is lost on restart.

### File Paths (all in /tmp)

| Purpose | Path |
|---|---|
| Nmap scan XML | `/tmp/msf-scans/<ip>.xml` |
| Nmap raw output | `/tmp/msf-scans/<ip>-output.txt` |
| Loot document | `/tmp/loot-<sessionID>.xml` |
| Session notes | `/tmp/msf-notes-<sessionID>.txt` |
| Hydra output | `/tmp/hydra-<sessionID>.txt` |
| SQLmap output | `/tmp/sqlmap-<sessionID>/` |
| Feroxbuster output | `/tmp/ferox-<sessionID>/results.txt` |
| Hashcat cracked | `/tmp/hashcat-<sessionID>-cracked.txt` |
| WiFi captures | `/tmp/wifi-cap-<sessionID>-*.cap` |
| WiFi hashes | `/tmp/wifi-cap-<sessionID>-*.22000` |

On clean shutdown (`SIGINT`/`SIGTERM`) these directories are removed automatically.

---

## Frontend

React 18 + TypeScript, bootstrapped with Create React App.

### Key Components

| Component | Purpose |
|---|---|
| `App.tsx` | Router, auth state, project fetch wrapper |
| `LoginPage.tsx` | PAM credential entry |
| `ProjectsPage.tsx` | Project CRUD, project-level tool panels |
| `Dashboard.tsx` | Per-project: network scan, session list, topology/report buttons |
| `SessionDetail.tsx` | 18-tab per-session workspace |
| `Console.tsx` | Live WebSocket msfconsole terminal with ANSI colour parsing |
| `ReportPage.tsx` | Per-session professional PDF report |
| `ProjectReportPage.tsx` | Aggregated project-level PDF report |
| `TopographyPage.tsx` | Draggable SVG network topology map |
| `HandshakeCapturePanel.tsx` | WiFi monitor mode, AP scan, handshake capture |

### State Persistence

- **CVE results** — SQLite (`cve_results` table); localStorage used as a fast read-back cache
- **Vuln scan output** — localStorage only (`session-{id}-vuln`)
- **Enumeration results** — localStorage only (`session-{id}-enum`)
- **OS info** — localStorage only (`session-{id}-os`)
- **Topology drag positions + node labels** — localStorage (`topology-{projectId}-pos`, `topology-{projectId}-labels`)

### CSS Variables

Dark theme defined in `frontend/src/index.css` as CSS custom properties. Report pages use explicit hex values — no CSS variables — so they print correctly.

### API Proxy (dev only)

`frontend/package.json` has `"proxy": "http://localhost:8080"` — all `/api/*` requests are forwarded to the backend during `npm start`. In production the Go binary serves both the API and the static files.

---

## Environment Variables (`backend/.env`)

| Variable | Default | Description |
|---|---|---|
| `JWT_SECRET` | (required) | HS256 signing key — use a long random string |
| `DATABASE_URL` | SQLite next to binary | `sqlite3://path.db`, `memory://`, or `postgresql://…` |
| `MSFCONSOLE_PATH` | `msfconsole` | Full path if not on PATH |
| `COOKIE_SECURE` | `false` | Set `true` in production (HTTPS) |
| `ALLOWED_ORIGIN` | (any) | Restrict WebSocket origin in production |

---

## Adding a New Tool Integration

1. **Backend handler** (`backend/main.go` or a new `backend/<tool>.go`):
   - Follow the async start/poll/stop pattern for long-running tools
   - For short tools, synchronous handler with `context.WithTimeout` is sufficient
   - Parse output and call `AppendLoot` or a new `Append*` function in `loot.go`

2. **Loot parser** (`backend/loot.go`):
   - Add a new loot type string
   - Add an `Append<Tool>` function that parses raw output into `[]LootField`
   - Append a `LootItem` with the appropriate `Type`, `Source`, `Timestamp`, and `Fields`

3. **Route** (`backend/main.go`):
   - Register under the authenticated group: `r.Post("/sessions/{id}/tool", handleStartTool(db))`

4. **Frontend panel** (`frontend/src/components/SessionDetail.tsx`):
   - Add a new tab ID and label to `ACTIONS`
   - Add `{activeAction === N && <ToolPanel ... />}` in the render
   - Update the console-hide condition if the panel should be full-width

5. **Rebuild**: `npm run build` → `rm -rf backend/ui && cp -r frontend/build backend/ui` → `go build -o bagaholdin .`
