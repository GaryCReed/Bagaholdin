import { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import axios from 'axios';
import './ReportPage.css';

// ── Types ──────────────────────────────────────────────────────────────────

interface Session { id: number; session_name: string; target_host: string; is_running: boolean }
interface CVEMetrics { description: string; baseScore: number; severity: string; vector: string; cvssVersion: string }
interface GitHubRepo { full_name: string; description: string | null; stargazers_count: number; updated_at: string; html_url: string }
interface CVEResult { cve: string; modules: string[]; targets?: string[]; metrics?: CVEMetrics | null; githubRepos?: GitHubRepo[] | null }
interface LootField { name: string; value: string }
interface LootItem { type: string; source: string; timestamp: string; fields: LootField[] }
interface ServiceResult { port: number; protocol: string; state: string; name: string; product: string; version: string }
interface OSInfo { name: string; family: string; os_gen: string; accuracy: number }
interface VulnFinding { script: string; title: string; state: string; cves: string[]; risk: string; disclosed: string }

// ── Constants ──────────────────────────────────────────────────────────────

const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'];

const SEV_COLOR: Record<string, string> = {
  CRITICAL: '#b71c1c',
  HIGH:     '#e64a19',
  MEDIUM:   '#f57c00',
  LOW:      '#1565c0',
  NONE:     '#546e7a',
};

const SEV_BG: Record<string, string> = {
  CRITICAL: '#fff5f5',
  HIGH:     '#fff3f0',
  MEDIUM:   '#fff8f0',
  LOW:      '#f0f5ff',
  NONE:     '#f4f6f8',
};

const LOOT_LABEL: Record<string, string> = {
  system_info: 'System Information', current_user: 'Current User Context',
  privilege_escalation: 'Privilege Escalation', privileges: 'User Privileges',
  is_admin: 'Administrative Status', credential: 'Credentials',
  user_list: 'User Accounts', user_account: 'User Accounts (/etc/passwd)',
  network_hosts: 'Network Hosts (ARP)', environment: 'Environment Variables',
  groups: 'Group Memberships',
};

// ── SVG Charts ─────────────────────────────────────────────────────────────

interface Seg { value: number; color: string; label: string }

function DonutChart({ segs, total }: { segs: Seg[]; total: number }) {
  if (total === 0) return null;
  const cx = 88, cy = 88, r = 62, sw = 24;
  const C = 2 * Math.PI * r;
  let cumPct = 0;
  return (
    <svg width="176" height="176" viewBox="0 0 176 176">
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="#ebebeb" strokeWidth={sw} />
      {segs.filter(s => s.value > 0).map((s, i) => {
        const pct = s.value / total;
        const dash = pct * C;
        const rot = -90 + cumPct * 360;
        cumPct += pct;
        return (
          <circle key={i} cx={cx} cy={cy} r={r} fill="none"
            stroke={s.color} strokeWidth={sw}
            strokeDasharray={`${dash.toFixed(2)} ${(C - dash).toFixed(2)}`}
            transform={`rotate(${rot.toFixed(2)} ${cx} ${cy})`}
            strokeLinecap="butt" />
        );
      })}
      <text x={cx} y={cy - 8} textAnchor="middle" fontSize="30" fontWeight="700" fill="#111" fontFamily="Arial,sans-serif">{total}</text>
      <text x={cx} y={cy + 14} textAnchor="middle" fontSize="11" fill="#777" fontFamily="Arial,sans-serif">total</text>
    </svg>
  );
}

function CVSSBars({ findings }: { findings: CVEResult[] }) {
  const scored = findings.filter(f => (f.metrics?.baseScore ?? 0) > 0);
  const sorted = [...scored].sort((a, b) => (b.metrics!.baseScore) - (a.metrics!.baseScore)).slice(0, 12);
  if (sorted.length === 0) return null;
  const BH = 22, GAP = 6, LW = 116, BW = 270, NW = 38;
  const W = LW + BW + NW, H = sorted.length * (BH + GAP);
  return (
    <svg width={W} height={H} viewBox={`0 0 ${W} ${H}`}>
      {sorted.map((f, i) => {
        const score = f.metrics!.baseScore;
        const bw = Math.max((score / 10) * BW, 3);
        const y = i * (BH + GAP);
        const col = SEV_COLOR[f.metrics!.severity] || '#546e7a';
        return (
          <g key={f.cve}>
            <text x={LW - 8} y={y + BH / 2 + 4} fontSize="9.5" fill="#555"
              fontFamily="'Courier New',monospace" textAnchor="end">
              {f.cve.replace('CVE-', '')}
            </text>
            <rect x={LW} y={y} width={bw} height={BH} fill={col} rx="3" opacity="0.9" />
            <text x={LW + bw + 6} y={y + BH / 2 + 4} fontSize="11" fill="#222"
              fontFamily="Arial,sans-serif" fontWeight="700">
              {score.toFixed(1)}
            </text>
          </g>
        );
      })}
    </svg>
  );
}

// ── Helpers ────────────────────────────────────────────────────────────────

function parseNSE(output: string): VulnFinding[] {
  const findings: VulnFinding[] = [];
  const lines = output.split('\n');
  let cur: VulnFinding | null = null;
  let inV = false, tsSet = false;
  const flush = () => {
    if (cur && (cur.state.toUpperCase().includes('VULNERABLE') || cur.cves.length > 0)) findings.push(cur);
    cur = null; inV = false; tsSet = false;
  };
  for (const raw of lines) {
    const s = raw.replace(/^\|[_ ]?/, '').trim();
    const sm = raw.match(/^\|\s+([\w-]+):\s*$/);
    if (sm) { flush(); cur = { script: sm[1], title: '', state: '', cves: [], risk: '', disclosed: '' }; continue; }
    if (!cur) continue;
    const lo = s.toLowerCase();
    if (lo === 'vulnerable:' || lo === 'likely vulnerable:') { cur.state = s.replace(':', ''); inV = true; continue; }
    if (inV) {
      const st = s.match(/^State:\s+(.+)/i); if (st) { cur.state = st[1].trim(); continue; }
      for (const m of s.matchAll(/CVE-\d{4}-\d+/gi)) cur.cves.push(m[0].toUpperCase());
      const rf = s.match(/^Risk factor:\s+(.+)/i); if (rf) { cur.risk = rf[1].trim(); continue; }
      const dd = s.match(/^Disclosure date:\s+(.+)/i); if (dd) { cur.disclosed = dd[1].trim(); continue; }
      if (!tsSet && s && !s.match(/^(State|IDs|Risk|Disclosure|References|http|https):/i)) { cur.title = s; tsSet = true; }
    }
  }
  flush();
  const seen = new Set<string>();
  return findings.filter(f => { if (seen.has(f.script)) return false; seen.add(f.script); return true; });
}

// ── Risk Assessment Matrix ─────────────────────────────────────────────────

function RiskMatrix({ findings }: { findings: CVEResult[] }) {
  if (findings.length === 0) return null;

  // Likelihood: HIGH if has MSF module, MEDIUM if has GitHub PoC, LOW otherwise
  const likelihood = (f: CVEResult): number => {
    if (f.modules?.length > 0) return 2;         // HIGH
    if ((f.githubRepos?.length ?? 0) > 0) return 1; // MEDIUM
    return 0;                                     // LOW
  };
  // Impact: derived from CVSS score
  const impact = (f: CVEResult): number => {
    const s = f.metrics?.baseScore ?? 0;
    if (s >= 9.0) return 2; // HIGH
    if (s >= 4.0) return 1; // MEDIUM
    return 0;               // LOW
  };

  // Cell colour (likelihood × impact → risk)
  const cellRisk = (l: number, i: number): string => {
    const r = l + i;
    if (r >= 4) return '#c62828'; // CRITICAL
    if (r === 3) return '#e64a19'; // HIGH
    if (r === 2) return '#f57c00'; // MEDIUM
    return '#1565c0';             // LOW
  };

  const labels = ['Low', 'Medium', 'High'];

  return (
    <div style={{ marginTop: 20 }}>
      <h3 className="rp-sub-title">Risk Assessment Matrix</h3>
      <div style={{ display: 'flex', gap: 24, alignItems: 'flex-start', flexWrap: 'wrap' }}>
        <svg width="240" height="220" viewBox="0 0 240 220" fontFamily="Arial,sans-serif">
          {/* Axis labels */}
          <text x="120" y="14" textAnchor="middle" fontSize="10" fill="#555">Likelihood →</text>
          <text x="14" y="120" textAnchor="middle" fontSize="10" fill="#555" transform="rotate(-90 14 120)">Impact →</text>
          {[0,1,2].map(col => (
            <text key={col} x={50 + col * 60 + 30} y="30" textAnchor="middle" fontSize="9" fill="#777">{labels[col]}</text>
          ))}
          {[0,1,2].map(row => (
            <text key={row} x="36" y={50 + (2 - row) * 56 + 32} textAnchor="middle" fontSize="9" fill="#777">{labels[row]}</text>
          ))}
          {/* Grid cells */}
          {[0,1,2].map(row => [0,1,2].map(col => (
            <rect key={`${row}-${col}`}
              x={50 + col * 60} y={50 + (2 - row) * 56}
              width={58} height={54} rx="4"
              fill={cellRisk(col, row)} opacity="0.18" stroke={cellRisk(col, row)} strokeWidth="1"
            />
          )))}
          {/* Plot findings */}
          {findings.filter(f => (f.metrics?.baseScore ?? 0) > 0 || f.modules?.length > 0).map((f, i) => {
            const l = likelihood(f), im = impact(f);
            const x = 50 + l * 60 + 29 + (i % 3) * 8 - 8;
            const y = 50 + (2 - im) * 56 + 27;
            const col = SEV_COLOR[f.metrics?.severity || 'NONE'] || '#546e7a';
            return (
              <circle key={f.cve} cx={x} cy={y} r="6" fill={col} opacity="0.85"><title>{f.cve}</title></circle>
            );
          })}
        </svg>
        <div style={{ fontSize: 11, color: '#555', lineHeight: 1.6, maxWidth: 260 }}>
          <p><strong>Likelihood</strong></p>
          <p>High — Confirmed Metasploit module</p>
          <p>Medium — Public PoC on GitHub</p>
          <p>Low — No known public exploit</p>
          <br />
          <p><strong>Impact</strong></p>
          <p>High — CVSS ≥ 9.0</p>
          <p>Medium — CVSS 4.0–8.9</p>
          <p>Low — CVSS &lt; 4.0</p>
        </div>
      </div>
    </div>
  );
}

// ── Tools & Techniques Used ────────────────────────────────────────────────

interface ToolsUsedProps {
  vulnOutput?: string;
  cveResults?: CVEResult[];
  lootItems?: LootItem[];
}

function ToolsUsed({ vulnOutput, cveResults, lootItems }: ToolsUsedProps) {
  const tools: { name: string; purpose: string }[] = [];

  if (vulnOutput) {
    tools.push({ name: 'nmap', purpose: 'Network service enumeration and vulnerability scanning (NSE scripts: vuln, vulners)' });
  }
  if (cveResults && cveResults.length > 0) {
    tools.push({ name: 'NVD API (nvd.nist.gov)', purpose: 'CVE lookup and CVSS score enrichment' });
    if (cveResults.some(r => r.modules?.length > 0)) {
      tools.push({ name: 'Metasploit Framework', purpose: 'CVE-to-module mapping and exploit validation' });
    }
    if (cveResults.some(r => (r.githubRepos?.length ?? 0) > 0)) {
      tools.push({ name: 'GitHub API', purpose: 'Public proof-of-concept exploit repository identification' });
    }
  }
  if (lootItems) {
    const types = new Set(lootItems.map(i => i.type));
    const sources = lootItems.map(i => i.source.toLowerCase()).join(' ');
    if (types.has('credential') || types.has('current_user') || types.has('system_info'))
      tools.push({ name: 'Meterpreter / MSF post modules', purpose: 'Post-exploitation data collection (hashes, system info, user context)' });
    if (sources.includes('hydra') || types.has('bruteforce_credential'))
      tools.push({ name: 'Hydra', purpose: 'Network service credential brute-forcing' });
    if (sources.includes('kerbrute') || types.has('kerbrute_users'))
      tools.push({ name: 'Kerbrute', purpose: 'Kerberos user enumeration against Active Directory' });
    if (sources.includes('enum4linux') || types.has('smb_enum'))
      tools.push({ name: 'enum4linux-ng', purpose: 'SMB/RPC enumeration (users, groups, shares, password policy)' });
    if (sources.includes('crackmapexec') || types.has('crackmapexec_finding'))
      tools.push({ name: 'CrackMapExec', purpose: 'Active Directory authentication and enumeration' });
    if (types.has('sqlmap_finding'))
      tools.push({ name: 'sqlmap', purpose: 'SQL injection detection and exploitation' });
    if (types.has('wpscan_finding'))
      tools.push({ name: 'WPScan', purpose: 'WordPress vulnerability and user enumeration' });
    if (types.has('ad_discovery'))
      tools.push({ name: 'nmap (LDAP/SMB scripts)', purpose: 'Active Directory domain discovery (ldap-rootdse, smb-os-discovery)' });
    if (types.has('wifi_handshake'))
      tools.push({ name: 'aircrack-ng suite / hashcat', purpose: 'WPA/WPA2 handshake capture and password cracking' });
  }

  if (tools.length === 0) return null;

  return (
    <div style={{ marginTop: 20 }}>
      <h3 className="rp-sub-title">Tools &amp; Techniques</h3>
      <table className="rp-table">
        <thead><tr><th>Tool / Resource</th><th>Purpose</th></tr></thead>
        <tbody>
          {tools.map(t => (
            <tr key={t.name}>
              <td className="rp-mono" style={{ whiteSpace: 'nowrap' }}>{t.name}</td>
              <td>{t.purpose}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function remediation(item: CVEResult): string {
  const d = (item.metrics?.description || '').toLowerCase();
  const sev = item.metrics?.severity || '';
  const sc = item.metrics?.baseScore || 0;
  if (d.includes('remote code execution') || d.includes(' rce'))
    return 'Apply vendor patch immediately and isolate the affected service from the network until remediated. Review system logs for indicators of prior exploitation. Implement network segmentation to restrict access.';
  if (d.includes('privilege escalation'))
    return 'Apply vendor patch. Audit local user privileges and sudo rules. Review SUID/SGID binaries. Enforce least-privilege principles across all accounts.';
  if (d.includes('sql injection'))
    return 'Apply vendor patch. Audit all database query construction for use of parameterised statements. Deploy a web application firewall as an interim compensating control. Audit the database for signs of data exfiltration.';
  if (d.includes('denial of service'))
    return 'Apply vendor patch. Implement rate limiting, connection throttling, and upstream traffic filtering on the affected service.';
  if (d.includes('information disclosure') || d.includes('information exposure'))
    return 'Apply vendor patch. Disable verbose error messages and unnecessary service banners. Restrict access to the affected endpoint using firewall rules or authentication.';
  if (sc >= 9.0 || sev === 'CRITICAL')
    return 'Apply vendor patches immediately — this is the highest remediation priority. Consider taking the affected service offline until patched. Review logs for indicators of compromise. Notify relevant stakeholders.';
  if (sc >= 7.0 || sev === 'HIGH')
    return 'Apply vendor patches as a near-term priority. Review access controls on the affected service and monitor for anomalous activity in the interim.';
  if (sc >= 4.0 || sev === 'MEDIUM')
    return 'Schedule patching within your standard maintenance cycle. Apply compensating controls such as firewall restrictions or access limitations as an interim measure.';
  return 'Apply vendor patches during routine maintenance. Review service configuration to disable unnecessary features or endpoints.';
}

// ── Component ──────────────────────────────────────────────────────────────

export default function ReportPage() {
  const { id } = useParams<{ id: string }>();
  const sessionId = parseInt(id || '0', 10);

  const [session,    setSession]    = useState<Session | null>(null);
  const [vulnOutput, setVulnOutput] = useState('');
  const [cveResults, setCveResults] = useState<CVEResult[]>([]);
  const [cveTarget,  setCveTarget]  = useState('');
  const [services,   setServices]   = useState<ServiceResult[]>([]);
  const [osInfo,     setOsInfo]     = useState<OSInfo | null>(null);
  const [lootItems,  setLootItems]  = useState<LootItem[]>([]);
  const [remarks,    setRemarks]    = useState('');
  const [pending,    setPending]    = useState(2); // session + vuln-scan
  const [loadErr,    setLoadErr]    = useState('');

  useEffect(() => {
    if (!sessionId) return;

    axios.get(`/api/sessions/${sessionId}`)
      .then(r => setSession(r.data.session))
      .catch(() => setLoadErr('Session not found or not authorised.'))
      .finally(() => setPending(p => p - 1));

    // Scan data: try backend first (authoritative), fall back to localStorage
    axios.get(`/api/sessions/${sessionId}/vuln-scan`)
      .then(r => {
        if (r.data.status === 'done') {
          if (r.data.output)            setVulnOutput(r.data.output);
          if (r.data.services?.length)  setServices(r.data.services);
          if (r.data.os_info)           setOsInfo(r.data.os_info);
        } else {
          applyStorageVuln(sessionId);
        }
      })
      .catch(() => applyStorageVuln(sessionId))
      .finally(() => setPending(p => p - 1));

    // CVE results: backend is authoritative, localStorage is fallback
    axios.get(`/api/sessions/${sessionId}/cve-results`)
      .then(r => {
        const results: CVEResult[] | null = r.data.results;
        if (results && results.length > 0) {
          setCveResults(results);
          if (results[0]?.targets?.[0]) setCveTarget(results[0].targets[0]);
        } else {
          // Fall back to localStorage
          try {
            const raw = localStorage.getItem(`session-${sessionId}-cve`);
            if (raw) { const { results: lr, target } = JSON.parse(raw); setCveResults(lr || []); setCveTarget(target || ''); }
          } catch {}
        }
      })
      .catch(() => {
        try {
          const raw = localStorage.getItem(`session-${sessionId}-cve`);
          if (raw) { const { results, target } = JSON.parse(raw); setCveResults(results || []); setCveTarget(target || ''); }
        } catch {}
      });

    // Remarks
    const savedRemarks = localStorage.getItem(`session-${sessionId}-remarks`);
    if (savedRemarks) setRemarks(savedRemarks);

    // Loot from backend (loads async — causes a re-render when done)
    axios.get(`/api/sessions/${sessionId}/loot`)
      .then(r => setLootItems(r.data.items || []))
      .catch(() => {});
  }, [sessionId]); // eslint-disable-line react-hooks/exhaustive-deps

  function applyStorageVuln(sid: number) {
    try {
      const v = localStorage.getItem(`session-${sid}-vuln`);
      if (v) setVulnOutput(v);
      const e = localStorage.getItem(`session-${sid}-enum`);
      if (e) { const { services: s } = JSON.parse(e); setServices(s || []); }
      const o = localStorage.getItem(`session-${sid}-os`);
      if (o) setOsInfo(JSON.parse(o));
    } catch {}
  }

  const handleRemarks = (v: string) => {
    setRemarks(v);
    localStorage.setItem(`session-${sessionId}-remarks`, v);
  };

  // ── Derived ────────────────────────────────────────────────────────────────

  const sorted = [...cveResults].sort((a, b) => {
    const ai = SEV_ORDER.indexOf(a.metrics?.severity || 'NONE');
    const bi = SEV_ORDER.indexOf(b.metrics?.severity || 'NONE');
    return (ai < 0 ? 99 : ai) - (bi < 0 ? 99 : bi);
  });

  const sevCounts = cveResults.reduce((acc, r) => {
    const s = r.metrics?.severity || 'NONE';
    acc[s] = (acc[s] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const donutSegs: Seg[] = SEV_ORDER
    .filter(s => sevCounts[s])
    .map(s => ({ value: sevCounts[s], color: SEV_COLOR[s], label: s }));

  const topSev    = SEV_ORDER.find(s => sevCounts[s]) || '';
  const riskLevel = topSev || (cveResults.length > 0 ? 'INFORMATIONAL' : 'NONE');
  const riskColor = SEV_COLOR[riskLevel] || '#546e7a';

  const openPorts  = services.filter(s => s.state === 'open');
  const nsFindings = vulnOutput ? parseNSE(vulnOutput) : [];

  const reportDate = new Date().toLocaleDateString('en-GB', { year: 'numeric', month: 'long', day: 'numeric' });
  const target     = cveTarget || session?.target_host || 'Unknown';

  if (pending > 0) return <div className="rp-loading">Compiling report…</div>;
  if (loadErr)    return <div className="rp-loading rp-load-err">{loadErr}</div>;

  return (
    <div className="rp-wrapper">

      {/* ── Screen toolbar ── */}
      <div className="rp-toolbar no-print">
        <div className="rp-toolbar-left">
          <span className="rp-toolbar-brand">Bagaholdin</span>
          <span className="rp-toolbar-sep">|</span>
          <span className="rp-toolbar-title">Penetration Test Report</span>
          <span className="rp-toolbar-hint">Add tester notes before printing.</span>
        </div>
        <button className="rp-btn-print" onClick={() => window.print()}>
          Print / Save as PDF
        </button>
      </div>

      {/* ── Document ── */}
      <div className="rp-document">

        {/* Fixed footer on every printed page */}
        <div className="rp-page-footer print-only">
          CONFIDENTIAL &nbsp;·&nbsp; {session?.session_name || `Session ${sessionId}`} &nbsp;·&nbsp; Bagaholdin Penetration Test Report
        </div>

        {/* ═══════════════════ COVER ═══════════════════ */}
        <div className="rp-cover">
          <div className="rp-cover-top-bar" style={{ background: riskColor }} />

          <div className="rp-cover-inner">
            {/* Shield SVG */}
            <svg className="rp-cover-shield" viewBox="0 0 80 90" xmlns="http://www.w3.org/2000/svg">
              <path d="M40 5 L72 17 L72 42 C72 62 57 77 40 85 C23 77 8 62 8 42 L8 17 Z"
                fill={riskColor} opacity="0.12" />
              <path d="M40 5 L72 17 L72 42 C72 62 57 77 40 85 C23 77 8 62 8 42 L8 17 Z"
                fill="none" stroke={riskColor} strokeWidth="3" />
              <text x="40" y="55" textAnchor="middle" fontSize="28" fontWeight="bold"
                fill={riskColor} fontFamily="Arial,sans-serif">!</text>
            </svg>

            <div className="rp-cover-eyebrow">Penetration Test Report</div>
            <h1 className="rp-cover-title">{session?.session_name || `Session ${sessionId}`}</h1>
            <div className="rp-cover-target">{session?.target_host || 'Unknown target'}</div>

            <div className="rp-cover-divider" />

            <table className="rp-cover-meta">
              <tbody>
                <tr>
                  <td>Report Date</td>
                  <td>{reportDate}</td>
                </tr>
                <tr>
                  <td>Target Host</td>
                  <td><strong>{session?.target_host || '—'}</strong></td>
                </tr>
                {osInfo && (
                  <tr>
                    <td>Operating System</td>
                    <td>{osInfo.name}{osInfo.os_gen ? ` ${osInfo.os_gen}` : ''}{osInfo.family ? ` (${osInfo.family})` : ''}</td>
                  </tr>
                )}
                <tr>
                  <td>Total Findings</td>
                  <td><strong>{cveResults.length}</strong></td>
                </tr>
                <tr>
                  <td>Overall Risk</td>
                  <td>
                    <span className="rp-risk-badge" style={{ background: riskColor }}>
                      {riskLevel}
                    </span>
                  </td>
                </tr>
                <tr>
                  <td>Classification</td>
                  <td><strong style={{ color: '#b71c1c' }}>Confidential</strong></td>
                </tr>
                <tr>
                  <td>Version</td>
                  <td>1.0 — Draft</td>
                </tr>
              </tbody>
            </table>
          </div>

          <div className="rp-cover-footer">
            Prepared using Bagaholdin &nbsp;·&nbsp; Educational &amp; authorised testing use only
          </div>
        </div>

        {/* ═══════════════════ TOC ═══════════════════ */}
        <section className="rp-section">
          <h2 className="rp-section-title">Contents</h2>
          <table className="rp-toc-table">
            <tbody>
              {([
                ['1', 'Executive Summary'],
                ['2', 'Scope and Methodology'],
                ['3', 'Attack Surface — Discovered Services'],
                ['4', 'Vulnerability Findings'],
                ['5', 'Post-Exploitation Findings'],
                ['6', 'NSE Script Findings'],
                ['7', 'Tester Notes & Conclusions'],
              ] as [string, string][]).map(([n, t]) => (
                <tr key={n}>
                  <td className="rp-toc-num">{n}.</td>
                  <td className="rp-toc-item">{t}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>

        {/* ═══════════════════ 1. EXECUTIVE SUMMARY ═══════════════════ */}
        <section className="rp-section">
          <h2 className="rp-section-title">1. Executive Summary</h2>

          <p>
            A penetration test was conducted against target host <strong>{target}</strong>.
            The assessment covered network service enumeration, automated vulnerability scanning,
            CVE cross-referencing against the National Vulnerability Database (NVD), and
            post-exploitation analysis where applicable.
          </p>

          {cveResults.length > 0 ? (
            <p>
              The assessment identified <strong>{cveResults.length} CVE{cveResults.length !== 1 ? 's' : ''}</strong>{' '}
              across <strong>{openPorts.length}</strong> open service{openPorts.length !== 1 ? 's' : ''}.
              The overall risk posture is rated{' '}
              <span className="rp-inline-badge" style={{ background: riskColor }}>{riskLevel}</span>.
              {sevCounts['CRITICAL']
                ? ` ${sevCounts['CRITICAL']} critical-severity finding${sevCounts['CRITICAL'] > 1 ? 's require' : ' requires'} immediate remediation.`
                : sevCounts['HIGH']
                  ? ` ${sevCounts['HIGH']} high-severity finding${sevCounts['HIGH'] > 1 ? 's require' : ' requires'} priority attention.`
                  : ''}
            </p>
          ) : (
            <p className="rp-no-data">
              {vulnOutput
                ? 'A vulnerability scan completed. No CVEs were identified. See Section 3 for the service enumeration.'
                : 'No scan data is available. Run Vulnerability Scan and CVE Analysis from the session view.'}
            </p>
          )}

          {/* KPI boxes */}
          {cveResults.length > 0 && (
            <div className="rp-kpi-row">
              <div className="rp-kpi" style={{ borderTopColor: '#333' }}>
                <div className="rp-kpi-num">{cveResults.length}</div>
                <div className="rp-kpi-lbl">Total CVEs</div>
              </div>
              {SEV_ORDER.filter(s => s !== 'NONE').map(sev => (
                <div key={sev} className="rp-kpi" style={{ borderTopColor: SEV_COLOR[sev] }}>
                  <div className="rp-kpi-num" style={{ color: SEV_COLOR[sev] }}>{sevCounts[sev] || 0}</div>
                  <div className="rp-kpi-lbl">{sev}</div>
                </div>
              ))}
              <div className="rp-kpi" style={{ borderTopColor: '#546e7a' }}>
                <div className="rp-kpi-num">{openPorts.length}</div>
                <div className="rp-kpi-lbl">Open Ports</div>
              </div>
            </div>
          )}

          {/* Charts */}
          {cveResults.length > 0 && (
            <div className="rp-charts-row">
              <div className="rp-chart-box">
                <div className="rp-chart-title">Severity Distribution</div>
                <div className="rp-chart-body rp-donut-body">
                  <DonutChart segs={donutSegs} total={cveResults.length} />
                  <div className="rp-legend">
                    {donutSegs.map(s => (
                      <div key={s.label} className="rp-legend-row">
                        <span className="rp-legend-dot" style={{ background: s.color }} />
                        <span className="rp-legend-name">{s.label}</span>
                        <span className="rp-legend-val">{s.value}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              <div className="rp-chart-box rp-chart-wide">
                <div className="rp-chart-title">CVSS Score Ranking (top {Math.min(cveResults.filter(f => (f.metrics?.baseScore ?? 0) > 0).length, 12)})</div>
                <div className="rp-chart-body">
                  <CVSSBars findings={cveResults} />
                </div>
              </div>
            </div>
          )}

          {/* Summary table */}
          {sorted.length > 0 && (
            <>
              <h3 className="rp-sub-title">Finding Summary</h3>
              <table className="rp-table">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>CVE</th>
                    <th>Severity</th>
                    <th>CVSS</th>
                    <th>Description</th>
                  </tr>
                </thead>
                <tbody>
                  {sorted.map((item, i) => (
                    <tr key={item.cve}>
                      <td className="rp-mono rp-id-col">VULN-{String(i + 1).padStart(3, '0')}</td>
                      <td className="rp-mono">{item.cve}</td>
                      <td>
                        <span className="rp-inline-badge" style={{ background: SEV_COLOR[item.metrics?.severity || 'NONE'] || '#546e7a' }}>
                          {item.metrics?.severity || 'N/A'}
                        </span>
                      </td>
                      <td className="rp-score-col">{item.metrics?.baseScore?.toFixed(1) || '—'}</td>
                      <td className="rp-desc-col">
                        {item.metrics?.description
                          ? item.metrics.description.slice(0, 120) + (item.metrics.description.length > 120 ? '…' : '')
                          : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}

          <RiskMatrix findings={cveResults} />
          <ToolsUsed vulnOutput={vulnOutput} cveResults={cveResults} lootItems={lootItems} />
        </section>

        {/* ═══════════════════ 2. METHODOLOGY ═══════════════════ */}
        <section className="rp-section">
          <h2 className="rp-section-title">2. Scope and Methodology</h2>

          <table className="rp-meta-table">
            <tbody>
              <tr><td>Target Host</td><td><strong>{session?.target_host || 'N/A'}</strong></td></tr>
              <tr><td>Session</td><td>{session?.session_name || `Session ${sessionId}`}</td></tr>
              <tr><td>Assessment Date</td><td>{reportDate}</td></tr>
              <tr><td>Tooling</td><td>Bagaholdin, Metasploit Framework, nmap</td></tr>
            </tbody>
          </table>

          <p style={{ marginTop: 18 }}>The assessment was conducted in the following phases:</p>

          <div className="rp-phases">
            {[
              ['Network Enumeration', 'Live host discovery using nmap ping sweep. Identified hosts added to engagement scope.'],
              ['Vulnerability Scan', 'Full service and OS fingerprint scan (nmap -v -sV -O --osscan-guess --script=vuln,vulners) to enumerate open ports, service versions, and known vulnerabilities.'],
              ['CVE Analysis', 'Identified CVEs cross-referenced against the NVD for CVSS scores and descriptions. Each CVE mapped to available Metasploit Framework modules.'],
              ['Exploit Research', 'For CVEs without Metasploit coverage, public proof-of-concept repositories on GitHub were identified and ranked by activity.'],
              ['Post-Exploitation', 'Where access was obtained, system state, credentials, user context, and network topology were enumerated.'],
            ].map(([title, desc], i) => (
              <div key={i} className="rp-phase">
                <div className="rp-phase-num">{i + 1}</div>
                <div className="rp-phase-body">
                  <div className="rp-phase-title">{title}</div>
                  <div className="rp-phase-desc">{desc}</div>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* ═══════════════════ 3. ATTACK SURFACE ═══════════════════ */}
        <section className="rp-section">
          <h2 className="rp-section-title">3. Attack Surface — Discovered Services</h2>

          {!osInfo && services.length === 0 ? (
            <p className="rp-no-data">No scan data. Run Vulnerability Scan from the session view.</p>
          ) : (
            <>
              {osInfo && (
                <div className="rp-os-card">
                  <div className="rp-os-header">
                    <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="#1565c0" strokeWidth="2">
                      <rect x="2" y="3" width="20" height="14" rx="2" /><path d="M8 21h8M12 17v4"/>
                    </svg>
                    <span className="rp-os-label">Detected Operating System</span>
                  </div>
                  <div className="rp-os-name">
                    {osInfo.name}{osInfo.os_gen ? ` ${osInfo.os_gen}` : ''}
                    {osInfo.family && <span className="rp-os-family"> ({osInfo.family})</span>}
                  </div>
                  {osInfo.accuracy < 90 && (
                    <div className="rp-os-note">Detection confidence: {osInfo.accuracy}% — result may be approximate</div>
                  )}
                </div>
              )}

              {services.length > 0 && (
                <>
                  <h3 className="rp-sub-title">
                    Port / Service Enumeration
                    <span className="rp-sub-note">{openPorts.length} open · {services.length - openPorts.length} filtered</span>
                  </h3>
                  <table className="rp-table rp-services-table">
                    <thead>
                      <tr><th>Port</th><th>Proto</th><th>State</th><th>Service</th><th>Product / Version</th></tr>
                    </thead>
                    <tbody>
                      {services.map(svc => (
                        <tr key={`${svc.port}-${svc.protocol}`}>
                          <td className="rp-mono rp-port-cell">{svc.port}</td>
                          <td>{svc.protocol.toUpperCase()}</td>
                          <td>
                            <span className={`rp-state-pill ${svc.state === 'open' ? 'rp-open' : 'rp-filtered'}`}>
                              {svc.state}
                            </span>
                          </td>
                          <td>{svc.name || '—'}</td>
                          <td className="rp-version-cell">{[svc.product, svc.version].filter(Boolean).join(' ') || '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </>
              )}
            </>
          )}
        </section>

        {/* ═══════════════════ 4. VULNERABILITY FINDINGS ═══════════════════ */}
        <section className="rp-section">
          <h2 className="rp-section-title">4. Vulnerability Findings</h2>

          {sorted.length === 0 ? (
            <p className="rp-no-data">No CVE findings. Run CVE Analysis from the session view.</p>
          ) : (
            sorted.map((item, idx) => {
              const fid   = `VULN-${String(idx + 1).padStart(3, '0')}`;
              const sev   = item.metrics?.severity || 'NONE';
              const score = item.metrics?.baseScore || 0;
              const col   = SEV_COLOR[sev] || '#546e7a';
              const bg    = SEV_BG[sev]   || '#f9f9f9';

              return (
                <div key={item.cve} className="rp-finding" style={{ borderLeftColor: col }}>

                  {/* Header */}
                  <div className="rp-fhdr">
                    <div className="rp-fhdr-left">
                      <span className="rp-fid">{fid}</span>
                      <span className="rp-fcve">{item.cve}</span>
                    </div>
                    <div className="rp-fhdr-right">
                      {sev !== 'NONE' && (
                        <span className="rp-sev-badge" style={{ background: col }}>{sev}</span>
                      )}
                      {score > 0 && (
                        <span className="rp-score-chip" style={{ color: col, borderColor: col }}>
                          CVSS&nbsp;{score.toFixed(1)}
                        </span>
                      )}
                      {item.metrics?.cvssVersion && (
                        <span className="rp-cvss-ver">v{item.metrics.cvssVersion}</span>
                      )}
                    </div>
                  </div>

                  {/* CVSS gauge */}
                  {score > 0 && (
                    <div className="rp-gauge">
                      <div className="rp-gauge-track">
                        <div className="rp-gauge-fill" style={{ width: `${score * 10}%`, background: col }} />
                      </div>
                      <span className="rp-gauge-val">{score.toFixed(1)} / 10.0</span>
                    </div>
                  )}

                  {/* Body rows */}
                  <div className="rp-fbody">

                    {item.targets && item.targets.length > 0 && (
                      <div className="rp-frow">
                        <span className="rp-flbl">Affected Hosts</span>
                        <span className="rp-fval">
                          {item.targets.map(t => <code key={t} className="rp-host-tag">{t}</code>)}
                        </span>
                      </div>
                    )}

                    {item.metrics?.description && (
                      <div className="rp-frow">
                        <span className="rp-flbl">Description</span>
                        <span className="rp-fval rp-desc-text">{item.metrics.description}</span>
                      </div>
                    )}

                    {item.metrics?.vector && (
                      <div className="rp-frow">
                        <span className="rp-flbl">CVSS Vector</span>
                        <code className="rp-vector">{item.metrics.vector}</code>
                      </div>
                    )}

                    {(item.modules.length > 0 || (item.githubRepos?.length ?? 0) > 0) && (
                      <div className="rp-frow">
                        <span className="rp-flbl">Exploitability</span>
                        <span className="rp-fval">
                          {item.modules.length > 0 ? (
                            <>
                              <span className="rp-exploit-note">Confirmed Metasploit Framework coverage — reliably exploitable:</span>
                              <ul className="rp-mod-list">
                                {item.modules.map(m => <li key={m}><code>{m}</code></li>)}
                              </ul>
                            </>
                          ) : (
                            <>
                              <span className="rp-exploit-note">No Metasploit module. Public PoC repositories found:</span>
                              <ul className="rp-mod-list">
                                {item.githubRepos!.map(r => (
                                  <li key={r.full_name}>
                                    <strong>{r.full_name}</strong>{' '}
                                    <span className="rp-stars">★ {r.stargazers_count.toLocaleString()}</span>
                                    {r.description && <span className="rp-rdesc"> — {r.description}</span>}
                                  </li>
                                ))}
                              </ul>
                            </>
                          )}
                        </span>
                      </div>
                    )}

                    <div className="rp-frow rp-remed" style={{ background: bg }}>
                      <span className="rp-flbl" style={{ color: col }}>Remediation</span>
                      <span className="rp-fval">{remediation(item)}</span>
                    </div>

                    <div className="rp-frow">
                      <span className="rp-flbl">Reference</span>
                      <span className="rp-fval rp-ref-url">
                        https://nvd.nist.gov/vuln/detail/{item.cve}
                      </span>
                    </div>

                  </div>
                </div>
              );
            })
          )}
        </section>

        {/* ═══════════════════ 5. POST-EXPLOITATION ═══════════════════ */}
        <section className="rp-section">
          <h2 className="rp-section-title">5. Post-Exploitation Findings</h2>

          {lootItems.length === 0 ? (
            <p className="rp-no-data">No post-exploitation data collected for this session.</p>
          ) : (
            <>
              <p>
                The following data was extracted from the target system during post-exploitation.
                All findings are sensitive and must be handled in accordance with applicable data
                handling and disclosure policies.
              </p>
              {Object.entries(
                lootItems.reduce((acc, it) => {
                  (acc[it.type] = acc[it.type] || []).push(it);
                  return acc;
                }, {} as Record<string, LootItem[]>)
              ).map(([type, items]) => (
                <div key={type} className="rp-loot-group">
                  <h3 className="rp-loot-title">{LOOT_LABEL[type] || type}</h3>
                  {items.map((it, i) => (
                    <table key={i} className="rp-table rp-loot-table">
                      <thead>
                        <tr>
                          <th colSpan={2} className="rp-loot-src">
                            <span>Source: <code>{it.source}</code></span>
                            <span className="rp-loot-ts">{new Date(it.timestamp).toLocaleString()}</span>
                          </th>
                        </tr>
                      </thead>
                      <tbody>
                        {it.fields.map(f => (
                          <tr key={f.name}>
                            <td className="rp-loot-key">{f.name}</td>
                            <td><pre className="rp-loot-pre">{f.value}</pre></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  ))}
                </div>
              ))}
            </>
          )}
        </section>

        {/* ═══════════════════ 6. NSE FINDINGS ═══════════════════ */}
        {nsFindings.length > 0 && (
          <section className="rp-section">
            <h2 className="rp-section-title">6. NSE Script Findings</h2>
            <p>The following vulnerabilities were flagged by nmap NSE scripts during the scan phase.</p>
            {nsFindings.map(f => (
              <div key={f.script} className="rp-nse">
                <div className="rp-nse-hdr">
                  <code className="rp-nse-script">{f.script}</code>
                  {f.risk && (
                    <span className="rp-sev-badge" style={{ background: SEV_COLOR[f.risk.toUpperCase()] || '#546e7a' }}>
                      {f.risk.toUpperCase()}
                    </span>
                  )}
                  <span className={`rp-nse-state ${f.state.toUpperCase().includes('VULNERABLE') ? 'rp-vuln' : 'rp-likely'}`}>
                    {f.state}
                  </span>
                </div>
                {f.title && <p className="rp-nse-title">{f.title}</p>}
                {f.cves.length > 0 && (
                  <p className="rp-nse-cves">
                    Associated CVEs:{' '}
                    {f.cves.map(c => <code key={c} className="rp-cve-pill">{c}</code>)}
                  </p>
                )}
                {f.disclosed && <p className="rp-nse-meta">Disclosed: {f.disclosed}</p>}
              </div>
            ))}
          </section>
        )}

        {/* ═══════════════════ 7. TESTER NOTES ═══════════════════ */}
        <section className="rp-section">
          <h2 className="rp-section-title">7. Tester Notes &amp; Conclusions</h2>
          <p className="rp-remarks-hint no-print">
            Enter additional observations, overall conclusions, or remediation priorities.
            This text will appear in the printed report.
          </p>
          <textarea
            className="rp-remarks-input no-print"
            value={remarks}
            onChange={e => handleRemarks(e.target.value)}
            placeholder="Enter tester observations, overall assessment, and remediation priorities here…"
            rows={10}
          />
          <div className="print-only rp-remarks-text">
            {remarks || <em>No tester notes entered.</em>}
          </div>
        </section>

        {/* ═══════════════════ DISCLAIMER ═══════════════════ */}
        <div className="rp-disclaimer">
          <strong>Legal Disclaimer</strong> — This report is confidential and intended solely for the
          authorised recipient. It must not be reproduced, distributed, or disclosed without written
          permission. Generated by Bagaholdin for educational and authorised penetration testing
          purposes only, on systems owned by or with explicit written permission of the system owner.
          The authors accept no liability for any unauthorised use of the information contained herein.
        </div>

      </div>
    </div>
  );
}
