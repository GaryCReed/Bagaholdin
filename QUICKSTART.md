# Quick Start

> **Legal Notice:** Bagaholdin is for **educational purposes only** and must only be used on networks you own or have **explicit written permission** to test. Unauthorised use is illegal.

> **Status:** This project is in a **workable state** — it functions, but is not production-hardened. Treat it as a learning platform.

---

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Go | 1.20+ | `go version` |
| Node.js | 18+ | `node --version` |
| msfconsole | any | `which msfconsole` |
| nmap | any | `which nmap` |
| hashcat | any | `which hashcat` — for WiFi cracking |
| hydra | any | `which hydra` — for bruteforce |

---

## Starting the App

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

Backend starts on `http://localhost:8080`, frontend dev server on `http://localhost:3000`.

**3. Open the app**

Navigate to `http://localhost:3000` and log in using your Linux system credentials.

---

## First Use

### Create a project

1. Log in and click **New Project**.
2. Enter a name and your target network range (e.g. `192.168.1.0/24`).
3. Click **Scan Network** to run an nmap ping sweep and discover live hosts.
4. Tick the hosts you want and click **+ Add Selected**, or click **+ Add** next to individual hosts.

### Project-level views (right column of the Dashboard)

| Button | What it does |
|---|---|
| **View Topology** | Opens a graphical network map of all discovered hosts. Hosts are colour-coded by worst CVE severity and connected to the inferred gateway node. |
| **Generate Report** | Opens an aggregated professional penetration test report covering all sessions in the project — executive summary, host summaries, consolidated CVE findings with remediation advice, and post-exploitation findings. |

### Work a session

Open a session to reach the main workspace. The MSF Console is always visible on the right. The left panel has action tabs:

| Tab | What it does |
|---|---|
| **Vulnerability Scan** | Runs `nmap -sV -O --script=vuln,vulners` against the target. Runs in the background — navigate away freely. Results persist. |
| **Enumeration** | Parses scan XML into a structured service list and suggests Metasploit modules per service. |
| **CVE Analysis** | Fetches CVEs from NVD, enriches with CVSS scores and GitHub PoC repositories. Results are saved to the database and feed into the project report. |
| **Shells** | Lists active MSF sessions. Interact, upgrade to Meterpreter, background, or kill. Auto-refreshes when a new session opens. |
| **Post Exploitation** | Quick-command buttons and recommended modules filtered by session type and OS. Output is automatically parsed for credentials, hashes, user accounts, system info, and other artefacts (loot). |
| **Password Attacks** | WiFi handshake upload and hashcat cracking with 50+ ISP mask presets, or Hydra bruteforce against network services. |
| **Report** | Structured per-session engagement report. Print or save as PDF. |

### MSF Console tips

- Type commands directly in the console input at the bottom of the screen.
- Arrow keys cycle through command history.
- The console auto-reconnects if the connection drops.
- When you **Interact** with a shell or Meterpreter session, the console enters that session. Panel actions that need the MSF prompt (e.g. running modules, listing sessions) will automatically background the active session first.

---

## Network Topology

Click **View Topology** on the project dashboard to open the topology map in a new tab.

- The **gateway node** (top-centre, blue) is inferred from the project network range (e.g. `192.168.1.1` for `192.168.1.0/24`).
- **Host nodes** below are colour-coded by worst CVE severity. Solid connectors indicate hosts with active sessions; dashed connectors indicate discovered-but-unsessioned hosts.
- Each node shows IP, hostname (if resolved), session name, detected OS, open port count, and CVE count.
- Click **Print / Save as PDF** in the toolbar to export.

---

## WiFi / Password Attacks

1. In a session, go to the **Password Attacks** tab.
2. To crack a WPA/WPA2 handshake:
   - Upload a `.cap` or `.hccapx` file, **or** capture one live using the WiFi Capture panel.
   - Select a mask from the **ISP / WiFi mask presets** dropdown. Presets are grouped by router family (BT Hub, TALKTALK, Virgin Media, Sky, Plusnet, Orange, etc.) and reflect the correct keyspace, length, and character exclusions for each SSID type.
   - Optionally enter a custom mask or wordlist.
   - Click **Start**.
3. For service bruteforcing, use the **Hydra** section — select a protocol, enter credentials or a wordlist, and start.

---

## Stopping

Press `Ctrl+C` in the terminal running `start.sh`. Both the backend and frontend are stopped cleanly.

---

## Production Build

Build a single self-contained binary that serves the React app on port 8080.

> **Important — two-step build:** The binary embeds the React UI at compile time from `backend/ui/`. You must copy the frontend build into that directory **before** running `go build`, otherwise the binary will serve a stale or empty UI.

```bash
# Option 1 — use the install script (handles both steps automatically)
chmod +x install.sh
./install.sh

# Option 2 — manual (both steps required)
cd frontend && npm run build
rm -rf ../backend/ui && cp -r build ../backend/ui   # ← required before go build
cd ../backend && go build -o bagaholdin .
```

Run the binary:

```bash
cd backend
./bagaholdin
```

The binary resolves `.env` and the SQLite database relative to itself, so it can be placed and run from any directory. Only port 8080 needs to be exposed.

Set additional environment variables in `backend/.env` for production:

```env
COOKIE_SECURE=true
ALLOWED_ORIGIN=https://your-domain.example.com
```

---

## Troubleshooting

**`msfconsole` not found**
Add `MSFCONSOLE_PATH=/full/path/to/msfconsole` to `backend/.env`.

**`hashcat` or `hydra` not found**
Install them via your package manager (`sudo apt install hashcat hydra`) or add their full paths to `backend/.env`.

**WebSocket disconnects immediately**
Check that `JWT_SECRET` is set in `backend/.env`. A missing or empty secret causes token validation to fail and the WebSocket connection to close.

**Scan never completes**
Scan output is written to `/tmp/msf-scans/`. Check that directory for `.txt` and `.xml` files. Errors are written to `<ip>-output.txt.err`.

**CVEs not appearing in the project report**
Open each session, go to **CVE Analysis**, and run the analysis if it has not been run yet. Results are saved to the database automatically once loaded. If results were analysed before the current version, re-running CVE Analysis will persist them correctly.

**Port 3000 already in use**
`npm start` will offer to use a different port. The frontend dev proxy is configured for port 8080, so the backend port must not change.

**Database file in the wrong location**
The binary creates `bagaholdin.db` in the same directory as itself. If running with `go run .`, the database is created in the current working directory. Set `DATABASE_URL=sqlite3:///absolute/path/to/bagaholdin.db` in `.env` to fix the location explicitly.
