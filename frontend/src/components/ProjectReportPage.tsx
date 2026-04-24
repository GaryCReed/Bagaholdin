import { useState, useEffect, useCallback } from 'react';
import { useParams } from 'react-router-dom';
import axios from 'axios';
import './ReportPage.css';

// ── Types ──────────────────────────────────────────────────────────────────

interface Project { id: number; name: string; network_range: string }
interface SessionSummary { id: number; session_name: string; target_host: string }
interface CVEMetrics { description: string; baseScore: number; severity: string; vector: string; cvssVersion: string }
interface GitHubRepo { full_name: string; description: string | null; stargazers_count: number; html_url: string }
interface CVEResult { cve: string; modules: string[]; targets?: string[]; metrics?: CVEMetrics | null; githubRepos?: GitHubRepo[] | null }
interface LootField { name: string; value: string }
interface LootItem { type: string; source: string; timestamp: string; fields: LootField[] }
interface ServiceResult { port: number; protocol: string; state: string; name: string; product: string; version: string }
interface OSInfo { name: string; family: string; os_gen: string; accuracy: number }

interface HostData {
  session: SessionSummary;
  vulnOutput: string;
  services: ServiceResult[];
  osInfo: OSInfo | null;
  cveResults: CVEResult[];
  lootItems: LootItem[];
  loaded: boolean;
}

// ── Constants ──────────────────────────────────────────────────────────────

const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'];
const SEV_COLOR: Record<string, string> = {
  CRITICAL: '#b71c1c', HIGH: '#e64a19', MEDIUM: '#f57c00', LOW: '#1565c0', NONE: '#546e7a',
};
const SEV_BG: Record<string, string> = {
  CRITICAL: '#fff5f5', HIGH: '#fff3f0', MEDIUM: '#fff8f0', LOW: '#f0f5ff', NONE: '#f4f6f8',
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
  const sorted = [...scored].sort((a, b) => b.metrics!.baseScore - a.metrics!.baseScore).slice(0, 12);
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

// ── Risk Matrix ────────────────────────────────────────────────────────────

function RiskMatrix({ findings }: { findings: CVEResult[] }) {
  if (findings.length === 0) return null;
  const likelihood = (f: CVEResult) => f.modules?.length > 0 ? 2 : (f.githubRepos?.length ?? 0) > 0 ? 1 : 0;
  const impact = (f: CVEResult) => { const s = f.metrics?.baseScore ?? 0; return s >= 9 ? 2 : s >= 4 ? 1 : 0; };
  const cellColor = (l: number, i: number) => {
    const r = l + i;
    return r >= 4 ? '#c62828' : r === 3 ? '#e64a19' : r === 2 ? '#f57c00' : '#1565c0';
  };
  const SEV_COLOR: Record<string, string> = { CRITICAL: '#c62828', HIGH: '#e64a19', MEDIUM: '#f57c00', LOW: '#1565c0', NONE: '#546e7a' };
  const labels = ['Low', 'Medium', 'High'];
  return (
    <div style={{ marginTop: 20 }}>
      <h3 className="rp-sub-title">Risk Assessment Matrix</h3>
      <div style={{ display: 'flex', gap: 24, alignItems: 'flex-start', flexWrap: 'wrap' }}>
        <svg width="240" height="220" viewBox="0 0 240 220" fontFamily="Arial,sans-serif">
          <text x="120" y="14" textAnchor="middle" fontSize="10" fill="#555">Likelihood →</text>
          <text x="14" y="120" textAnchor="middle" fontSize="10" fill="#555" transform="rotate(-90 14 120)">Impact →</text>
          {[0,1,2].map(col => <text key={col} x={50 + col * 60 + 30} y="30" textAnchor="middle" fontSize="9" fill="#777">{labels[col]}</text>)}
          {[0,1,2].map(row => <text key={row} x="36" y={50 + (2 - row) * 56 + 32} textAnchor="middle" fontSize="9" fill="#777">{labels[row]}</text>)}
          {[0,1,2].map(row => [0,1,2].map(col => (
            <rect key={`${row}-${col}`} x={50 + col * 60} y={50 + (2 - row) * 56} width={58} height={54} rx="4"
              fill={cellColor(col, row)} opacity="0.18" stroke={cellColor(col, row)} strokeWidth="1" />
          )))}
          {findings.filter(f => (f.metrics?.baseScore ?? 0) > 0).map((f, i) => {
            const l = likelihood(f), im = impact(f);
            return <circle key={f.cve} cx={50 + l * 60 + 29 + (i % 3) * 8 - 8} cy={50 + (2 - im) * 56 + 27}
              r="6" fill={SEV_COLOR[f.metrics?.severity || 'NONE'] || '#546e7a'} opacity="0.85" />;
          })}
        </svg>
        <div style={{ fontSize: 11, color: '#555', lineHeight: 1.6 }}>
          <p><strong>Likelihood:</strong> High=MSF module · Medium=GitHub PoC · Low=No exploit</p>
          <p><strong>Impact:</strong> High=CVSS≥9 · Medium=CVSS 4–8.9 · Low=CVSS&lt;4</p>
        </div>
      </div>
    </div>
  );
}

// ── Tools Used ─────────────────────────────────────────────────────────────

function ToolsUsed({ hostData }: { hostData: { vulnOutput: string; cveResults: CVEResult[]; lootItems: LootItem[] }[] }) {
  const tools: { name: string; purpose: string }[] = [];
  const allLoot = hostData.flatMap(h => h.lootItems);
  const allCVE  = hostData.flatMap(h => h.cveResults);
  const hasVuln = hostData.some(h => h.vulnOutput);

  if (hasVuln) tools.push({ name: 'nmap', purpose: 'Network service enumeration and NSE vulnerability scanning' });
  if (allCVE.length > 0) {
    tools.push({ name: 'NVD API', purpose: 'CVE lookup and CVSS score enrichment' });
    if (allCVE.some(r => r.modules?.length > 0)) tools.push({ name: 'Metasploit Framework', purpose: 'CVE-to-module mapping and exploit validation' });
    if (allCVE.some(r => (r.githubRepos?.length ?? 0) > 0)) tools.push({ name: 'GitHub API', purpose: 'Public PoC repository identification' });
  }
  const lootTypes = new Set(allLoot.map(i => i.type));
  const lootSrc   = allLoot.map(i => i.source.toLowerCase()).join(' ');
  if (lootTypes.has('credential') || lootTypes.has('current_user')) tools.push({ name: 'Meterpreter / MSF post modules', purpose: 'Post-exploitation data collection' });
  if (lootSrc.includes('hydra') || lootTypes.has('bruteforce_credential')) tools.push({ name: 'Hydra', purpose: 'Credential brute-forcing' });
  if (lootSrc.includes('kerbrute') || lootTypes.has('kerbrute_users')) tools.push({ name: 'Kerbrute', purpose: 'Kerberos user enumeration' });
  if (lootSrc.includes('enum4linux') || lootTypes.has('smb_enum')) tools.push({ name: 'enum4linux-ng', purpose: 'SMB/RPC enumeration' });
  if (lootSrc.includes('crackmapexec') || lootTypes.has('crackmapexec_finding')) tools.push({ name: 'CrackMapExec', purpose: 'AD authentication and enumeration' });
  if (lootTypes.has('sqlmap_finding')) tools.push({ name: 'sqlmap', purpose: 'SQL injection testing' });
  if (lootTypes.has('wpscan_finding')) tools.push({ name: 'WPScan', purpose: 'WordPress vulnerability enumeration' });
  if (lootTypes.has('ad_discovery')) tools.push({ name: 'nmap (LDAP/SMB scripts)', purpose: 'Active Directory domain discovery' });
  if (lootTypes.has('wifi_handshake')) tools.push({ name: 'aircrack-ng / hashcat', purpose: 'WPA/WPA2 handshake capture and cracking' });

  if (tools.length === 0) return null;
  return (
    <div style={{ marginTop: 20 }}>
      <h3 className="rp-sub-title">Tools &amp; Techniques</h3>
      <table className="rp-table">
        <thead><tr><th>Tool</th><th>Purpose</th></tr></thead>
        <tbody>{tools.map(t => <tr key={t.name}><td className="rp-mono" style={{ whiteSpace: 'nowrap' }}>{t.name}</td><td>{t.purpose}</td></tr>)}</tbody>
      </table>
    </div>
  );
}

// ── Remediation Roadmap ────────────────────────────────────────────────────

function RemediationRoadmap({ findings }: { findings: CVEResult[] }) {
  if (findings.length === 0) return null;
  const SEV_COLOR: Record<string, string> = { CRITICAL: '#c62828', HIGH: '#e64a19', MEDIUM: '#f57c00', LOW: '#1565c0', NONE: '#546e7a' };
  const effort = (f: CVEResult) => f.modules?.length > 0 ? 'Low (patch available)' : (f.githubRepos?.length ?? 0) > 0 ? 'Medium' : 'Low (patch)';
  const priority = (sev: string) => {
    if (sev === 'CRITICAL') return 'Immediate';
    if (sev === 'HIGH')     return 'Short-term (< 30 days)';
    if (sev === 'MEDIUM')   return 'Medium-term (< 90 days)';
    return 'Routine maintenance';
  };
  return (
    <div style={{ marginTop: 20, pageBreakBefore: 'auto' }}>
      <h3 className="rp-sub-title">Remediation Roadmap</h3>
      <table className="rp-table">
        <thead>
          <tr><th>Priority</th><th>ID</th><th>CVE</th><th>Severity</th><th>Effort</th><th>Recommendation</th></tr>
        </thead>
        <tbody>
          {findings.map((f, i) => {
            const sev = f.metrics?.severity || 'NONE';
            const col = SEV_COLOR[sev] || '#546e7a';
            return (
              <tr key={f.cve}>
                <td style={{ fontSize: 11, whiteSpace: 'nowrap' }}>{priority(sev)}</td>
                <td className="rp-mono" style={{ fontSize: 11 }}>VULN-{String(i + 1).padStart(3, '0')}</td>
                <td className="rp-mono" style={{ fontSize: 11 }}>{f.cve}</td>
                <td><span className="rp-inline-badge" style={{ background: col }}>{sev}</span></td>
                <td style={{ fontSize: 11 }}>{effort(f)}</td>
                <td style={{ fontSize: 11 }}>
                  {f.metrics?.description
                    ? 'Apply vendor patch. ' + (sev === 'CRITICAL' || sev === 'HIGH' ? 'Prioritise immediately.' : 'Schedule in next maintenance window.')
                    : 'Apply vendor patch and review service configuration.'}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// ── Helpers ────────────────────────────────────────────────────────────────

function remediation(item: CVEResult): string {
  const d = (item.metrics?.description || '').toLowerCase();
  const sev = item.metrics?.severity || '';
  const sc = item.metrics?.baseScore || 0;
  if (d.includes('remote code execution') || d.includes(' rce'))
    return 'Apply vendor patch immediately and isolate the affected service. Review logs for indicators of prior exploitation. Implement network segmentation.';
  if (d.includes('privilege escalation'))
    return 'Apply vendor patch. Audit local user privileges and sudo rules. Review SUID/SGID binaries. Enforce least-privilege.';
  if (d.includes('sql injection'))
    return 'Apply vendor patch. Audit all database query construction for parameterised statements. Deploy a WAF as an interim control.';
  if (d.includes('denial of service'))
    return 'Apply vendor patch. Implement rate limiting, connection throttling, and upstream traffic filtering.';
  if (d.includes('information disclosure') || d.includes('information exposure'))
    return 'Apply vendor patch. Disable verbose error messages and service banners. Restrict access via firewall rules.';
  if (sc >= 9.0 || sev === 'CRITICAL')
    return 'Apply vendor patches immediately. Consider taking the service offline until patched. Review logs for indicators of compromise.';
  if (sc >= 7.0 || sev === 'HIGH')
    return 'Apply vendor patches as a near-term priority. Review access controls and monitor for anomalous activity.';
  if (sc >= 4.0 || sev === 'MEDIUM')
    return 'Schedule patching within your standard maintenance cycle. Apply compensating controls as an interim measure.';
  return 'Apply vendor patches during routine maintenance. Review service configuration to disable unnecessary features.';
}

function parseNSEVulns(output: string): string[] {
  const vulns: string[] = [];
  const lines = output.split('\n');
  for (const line of lines) {
    if (/VULNERABLE|likely vulnerable/i.test(line)) {
      const m = line.match(/\|\s+([\w-]+):/);
      if (m) vulns.push(m[1]);
    }
  }
  return [...new Set(vulns)];
}

// ── Component ──────────────────────────────────────────────────────────────

export default function ProjectReportPage() {
  const { id } = useParams<{ id: string }>();
  const projectId = parseInt(id || '0', 10);

  const [project,   setProject]   = useState<Project | null>(null);
  const [hostData,  setHostData]  = useState<HostData[]>([]);
  const [pending,   setPending]   = useState(1);
  const [loadErr,   setLoadErr]   = useState('');

  // Fix App shell overflow (same as ReportPage)
  useEffect(() => {
    const el = document.querySelector<HTMLElement>('.app');
    if (el) { el.style.overflow = 'auto'; el.style.height = 'auto'; }
  }, []);

  const loadSessionData = useCallback(async (session: SessionSummary): Promise<HostData> => {
    const base: HostData = {
      session, vulnOutput: '', services: [], osInfo: null, cveResults: [], lootItems: [], loaded: false,
    };
    const [scanRes, cveRes, lootRes] = await Promise.allSettled([
      axios.get(`/api/sessions/${session.id}/vuln-scan`),
      axios.get(`/api/sessions/${session.id}/cve-results`),
      axios.get(`/api/sessions/${session.id}/loot`),
    ]);
    if (scanRes.status === 'fulfilled' && scanRes.value.data.status === 'done') {
      const d = scanRes.value.data;
      base.vulnOutput = d.output || '';
      base.services   = d.services || [];
      base.osInfo     = d.os_info  || null;
    }
    if (cveRes.status === 'fulfilled' && cveRes.value.data.results?.length > 0) {
      base.cveResults = cveRes.value.data.results;
    } else {
      // Fall back to localStorage (covers data saved before backend persistence)
      try {
        const ls = localStorage.getItem(`session-${session.id}-cve`);
        if (ls) {
          const { results } = JSON.parse(ls);
          if (results?.length > 0) base.cveResults = results;
        }
      } catch { /* ignore corrupt cache */ }
    }
    if (lootRes.status === 'fulfilled') {
      base.lootItems = lootRes.value.data.items || [];
    }
    base.loaded = true;
    return base;
  }, []);

  useEffect(() => {
    if (!projectId) return;
    Promise.all([
      axios.get(`/api/projects/${projectId}`),
      axios.get(`/api/projects/${projectId}/sessions`),
    ]).then(async ([projRes, sessRes]) => {
      setProject(projRes.data.project);
      const sessions: SessionSummary[] = sessRes.data.sessions || [];
      if (sessions.length === 0) { setHostData([]); setPending(0); return; }

      // Load each session in parallel, update state as each resolves
      setPending(sessions.length);
      const results: HostData[] = new Array(sessions.length).fill(null);
      await Promise.all(sessions.map(async (s, i) => {
        const data = await loadSessionData(s);
        results[i] = data;
        setPending(p => p - 1);
        setHostData([...results.filter(Boolean)]);
      }));
    }).catch(err => {
      setLoadErr(err.response?.data?.error || err.message || 'Failed to load project');
      setPending(0);
    });
  }, [projectId, loadSessionData]);

  // ── Derived ────────────────────────────────────────────────────────────────

  // Aggregate CVEs across all hosts, merging targets for duplicates
  const allCVEMap = new Map<string, CVEResult>();
  for (const hd of hostData) {
    for (const cve of hd.cveResults) {
      if (allCVEMap.has(cve.cve)) {
        const ex = allCVEMap.get(cve.cve)!;
        ex.targets = [...new Set([...(ex.targets || []), ...(cve.targets || [hd.session.target_host])])];
      } else {
        allCVEMap.set(cve.cve, { ...cve, targets: cve.targets?.length ? cve.targets : [hd.session.target_host] });
      }
    }
  }
  const allCVEs = [...allCVEMap.values()].sort((a, b) => {
    const ai = SEV_ORDER.indexOf(a.metrics?.severity || 'NONE');
    const bi = SEV_ORDER.indexOf(b.metrics?.severity || 'NONE');
    return (ai < 0 ? 99 : ai) - (bi < 0 ? 99 : bi);
  });

  const sevCounts = allCVEs.reduce((acc, r) => {
    const s = r.metrics?.severity || 'NONE';
    acc[s] = (acc[s] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const donutSegs: Seg[] = SEV_ORDER.filter(s => sevCounts[s])
    .map(s => ({ value: sevCounts[s], color: SEV_COLOR[s], label: s }));

  const topSev    = SEV_ORDER.find(s => sevCounts[s]) || '';
  const riskLevel = topSev || (allCVEs.length > 0 ? 'INFORMATIONAL' : 'NONE');
  const riskColor = SEV_COLOR[riskLevel] || '#546e7a';

  const totalOpenPorts = hostData.reduce((n, hd) => n + hd.services.filter(s => s.state === 'open').length, 0);
  const hostsWithLoot  = hostData.filter(hd => hd.lootItems.length > 0).length;

  const reportDate = new Date().toLocaleDateString('en-GB', { year: 'numeric', month: 'long', day: 'numeric' });

  // ── Loading / error ────────────────────────────────────────────────────────

  if (pending > 0 && hostData.length === 0) {
    return <div className="rp-loading">Compiling project report…</div>;
  }
  if (loadErr) return <div className="rp-loading rp-load-err">{loadErr}</div>;

  const scannedHosts = hostData.filter(hd => hd.services.length > 0 || hd.vulnOutput);

  return (
    <div className="rp-wrapper">

      {/* ── Screen toolbar ── */}
      <div className="rp-toolbar no-print">
        <div className="rp-toolbar-left">
          <span className="rp-toolbar-brand">Bagaholdin</span>
          <span className="rp-toolbar-sep">|</span>
          <span className="rp-toolbar-title">Project Report — {project?.name}</span>
          {pending > 0 && <span className="rp-toolbar-hint">Loading {pending} host(s)…</span>}
        </div>
        <button className="rp-btn-print" onClick={() => window.print()}>
          Print / Save as PDF
        </button>
      </div>

      <div className="rp-document">

        {/* Fixed footer on every printed page */}
        <div className="rp-page-footer print-only">
          CONFIDENTIAL &nbsp;·&nbsp; {project?.name} &nbsp;·&nbsp; Bagaholdin Project Penetration Test Report
        </div>

        {/* ═══════════════════ COVER ═══════════════════ */}
        <div className="rp-cover">
          <div className="rp-cover-top-bar" style={{ background: riskColor }} />
          <div className="rp-cover-inner">
            <svg className="rp-cover-shield" viewBox="0 0 80 90" xmlns="http://www.w3.org/2000/svg">
              <path d="M40 5 L72 17 L72 42 C72 62 57 77 40 85 C23 77 8 62 8 42 L8 17 Z"
                fill={riskColor} opacity="0.12" />
              <path d="M40 5 L72 17 L72 42 C72 62 57 77 40 85 C23 77 8 62 8 42 L8 17 Z"
                fill="none" stroke={riskColor} strokeWidth="3" />
              <text x="40" y="55" textAnchor="middle" fontSize="28" fontWeight="bold"
                fill={riskColor} fontFamily="Arial,sans-serif">!</text>
            </svg>

            <div className="rp-cover-eyebrow">Project Penetration Test Report</div>
            <h1 className="rp-cover-title">{project?.name || `Project ${projectId}`}</h1>
            {project?.network_range && (
              <div className="rp-cover-target">{project.network_range}</div>
            )}
            <div className="rp-cover-divider" />

            <table className="rp-cover-meta">
              <tbody>
                <tr><td>Report Date</td><td>{reportDate}</td></tr>
                <tr><td>Network Range</td><td><strong>{project?.network_range || '—'}</strong></td></tr>
                <tr><td>Hosts in Scope</td><td><strong>{hostData.length}</strong></td></tr>
                <tr><td>Hosts Scanned</td><td><strong>{scannedHosts.length}</strong></td></tr>
                <tr><td>Total Findings</td><td><strong>{allCVEs.length}</strong></td></tr>
                <tr><td>Open Ports</td><td><strong>{totalOpenPorts}</strong></td></tr>
                <tr>
                  <td>Overall Risk</td>
                  <td><span className="rp-risk-badge" style={{ background: riskColor }}>{riskLevel}</span></td>
                </tr>
                <tr><td>Classification</td><td><strong style={{ color: '#b71c1c' }}>Confidential</strong></td></tr>
                <tr><td>Version</td><td>1.0 — Draft</td></tr>
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
                ['3', 'Host Summaries'],
                ...hostData.map((hd, i) => [`3.${i + 1}`, `${hd.session.session_name} (${hd.session.target_host})`]),
                ['4', 'Consolidated Vulnerability Findings'],
                ['5', 'Post-Exploitation Findings'],
                ['6', 'Disclaimer'],
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
            A penetration test was conducted against the <strong>{project?.name}</strong> project,
            encompassing <strong>{hostData.length}</strong> target host{hostData.length !== 1 ? 's' : ''}{' '}
            {project?.network_range ? `within network range ${project.network_range}` : ''}.
            The assessment covered network service enumeration, automated vulnerability scanning,
            CVE cross-referencing against the National Vulnerability Database (NVD), and
            post-exploitation analysis where applicable.
          </p>

          {allCVEs.length > 0 ? (
            <p>
              Across all hosts, the assessment identified{' '}
              <strong>{allCVEs.length} CVE{allCVEs.length !== 1 ? 's' : ''}</strong>{' '}
              over <strong>{totalOpenPorts}</strong> open port{totalOpenPorts !== 1 ? 's' : ''}.
              The overall project risk posture is rated{' '}
              <span className="rp-inline-badge" style={{ background: riskColor }}>{riskLevel}</span>.
              {sevCounts['CRITICAL']
                ? ` ${sevCounts['CRITICAL']} critical-severity finding${sevCounts['CRITICAL'] > 1 ? 's require' : ' requires'} immediate remediation.`
                : sevCounts['HIGH']
                  ? ` ${sevCounts['HIGH']} high-severity finding${sevCounts['HIGH'] > 1 ? 's require' : ' requires'} priority attention.`
                  : ''}
            </p>
          ) : (
            <p className="rp-no-data">
              {scannedHosts.length > 0
                ? 'Vulnerability scans completed. No CVEs were identified across any host.'
                : 'No scan data available. Run Vulnerability Scan and CVE Analysis for each session.'}
            </p>
          )}

          {/* KPI boxes */}
          <div className="rp-kpi-row">
            <div className="rp-kpi" style={{ borderTopColor: '#333' }}>
              <div className="rp-kpi-num">{hostData.length}</div>
              <div className="rp-kpi-lbl">Hosts</div>
            </div>
            <div className="rp-kpi" style={{ borderTopColor: '#546e7a' }}>
              <div className="rp-kpi-num">{totalOpenPorts}</div>
              <div className="rp-kpi-lbl">Open Ports</div>
            </div>
            <div className="rp-kpi" style={{ borderTopColor: '#333' }}>
              <div className="rp-kpi-num">{allCVEs.length}</div>
              <div className="rp-kpi-lbl">Total CVEs</div>
            </div>
            {SEV_ORDER.filter(s => s !== 'NONE').map(sev => (
              <div key={sev} className="rp-kpi" style={{ borderTopColor: SEV_COLOR[sev] }}>
                <div className="rp-kpi-num" style={{ color: SEV_COLOR[sev] }}>{sevCounts[sev] || 0}</div>
                <div className="rp-kpi-lbl">{sev}</div>
              </div>
            ))}
            {hostsWithLoot > 0 && (
              <div className="rp-kpi" style={{ borderTopColor: '#7b1fa2' }}>
                <div className="rp-kpi-num" style={{ color: '#7b1fa2' }}>{hostsWithLoot}</div>
                <div className="rp-kpi-lbl">Hosts Compromised</div>
              </div>
            )}
          </div>

          {/* Charts */}
          {allCVEs.length > 0 && (
            <div className="rp-charts-row">
              <div className="rp-chart-box">
                <div className="rp-chart-title">Severity Distribution</div>
                <div className="rp-chart-body rp-donut-body">
                  <DonutChart segs={donutSegs} total={allCVEs.length} />
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
                <div className="rp-chart-title">
                  CVSS Score Ranking (top {Math.min(allCVEs.filter(f => (f.metrics?.baseScore ?? 0) > 0).length, 12)})
                </div>
                <div className="rp-chart-body">
                  <CVSSBars findings={allCVEs} />
                </div>
              </div>
            </div>
          )}

          {/* Finding summary table */}
          {allCVEs.length > 0 && (
            <>
              <h3 className="rp-sub-title">Finding Summary</h3>
              <table className="rp-table">
                <thead>
                  <tr><th>ID</th><th>CVE</th><th>Severity</th><th>CVSS</th><th>Affected Hosts</th><th>Description</th></tr>
                </thead>
                <tbody>
                  {allCVEs.map((item, i) => (
                    <tr key={item.cve}>
                      <td className="rp-mono rp-id-col">VULN-{String(i + 1).padStart(3, '0')}</td>
                      <td className="rp-mono">{item.cve}</td>
                      <td>
                        <span className="rp-inline-badge" style={{ background: SEV_COLOR[item.metrics?.severity || 'NONE'] || '#546e7a' }}>
                          {item.metrics?.severity || 'N/A'}
                        </span>
                      </td>
                      <td className="rp-score-col">{item.metrics?.baseScore?.toFixed(1) || '—'}</td>
                      <td className="rp-mono" style={{ fontSize: 11 }}>
                        {(item.targets || []).join(', ') || '—'}
                      </td>
                      <td className="rp-desc-col">
                        {item.metrics?.description
                          ? item.metrics.description.slice(0, 100) + (item.metrics.description.length > 100 ? '…' : '')
                          : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}

          <RiskMatrix findings={allCVEs} />
          <ToolsUsed hostData={hostData} />
        </section>

        {/* ═══════════════════ 2. SCOPE AND METHODOLOGY ═══════════════════ */}
        <section className="rp-section">
          <h2 className="rp-section-title">2. Scope and Methodology</h2>

          <table className="rp-meta-table">
            <tbody>
              <tr><td>Project</td><td><strong>{project?.name}</strong></td></tr>
              <tr><td>Network Range</td><td>{project?.network_range || 'N/A'}</td></tr>
              <tr><td>Hosts in Scope</td><td>{hostData.length}</td></tr>
              <tr><td>Assessment Date</td><td>{reportDate}</td></tr>
              <tr><td>Tooling</td><td>Bagaholdin, Metasploit Framework, nmap</td></tr>
            </tbody>
          </table>

          <h3 className="rp-sub-title" style={{ marginTop: 18 }}>Hosts in Scope</h3>
          <table className="rp-table">
            <thead>
              <tr><th>Session</th><th>Target Host</th><th>OS</th><th>Open Ports</th><th>CVEs</th></tr>
            </thead>
            <tbody>
              {hostData.map(hd => (
                <tr key={hd.session.id}>
                  <td>{hd.session.session_name}</td>
                  <td className="rp-mono">{hd.session.target_host}</td>
                  <td>{hd.osInfo ? `${hd.osInfo.name}${hd.osInfo.os_gen ? ' ' + hd.osInfo.os_gen : ''}` : '—'}</td>
                  <td>{hd.services.filter(s => s.state === 'open').length}</td>
                  <td>{hd.cveResults.length || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>

          <p style={{ marginTop: 18 }}>The assessment was conducted in the following phases:</p>
          <div className="rp-phases">
            {[
              ['Network Enumeration', 'Live host discovery using nmap ping sweep across the project network range.'],
              ['Vulnerability Scan', 'Full service and OS fingerprint scan (nmap -sV -O --osscan-guess --script=vuln,vulners) against each in-scope host.'],
              ['CVE Analysis', 'Identified CVEs cross-referenced against the NVD for CVSS scores and descriptions. Each CVE mapped to available Metasploit Framework modules.'],
              ['Exploit Research', 'For CVEs without Metasploit coverage, public proof-of-concept repositories on GitHub were identified.'],
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

        {/* ═══════════════════ 3. HOST SUMMARIES ═══════════════════ */}
        <section className="rp-section">
          <h2 className="rp-section-title">3. Host Summaries</h2>

          {hostData.map((hd, hi) => {
            const openPorts = hd.services.filter(s => s.state === 'open');
            const nseVulns  = hd.vulnOutput ? parseNSEVulns(hd.vulnOutput) : [];
            return (
              <div key={hd.session.id} className="prr-host-block">
                <div className="prr-host-header">
                  <span className="prr-host-num">3.{hi + 1}</span>
                  <span className="prr-host-name">{hd.session.session_name}</span>
                  <code className="prr-host-ip">{hd.session.target_host}</code>
                </div>

                {hd.osInfo && (
                  <div className="rp-os-card" style={{ marginBottom: 12 }}>
                    <div className="rp-os-header">
                      <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#1565c0" strokeWidth="2">
                        <rect x="2" y="3" width="20" height="14" rx="2" /><path d="M8 21h8M12 17v4"/>
                      </svg>
                      <span className="rp-os-label">Detected OS</span>
                    </div>
                    <div className="rp-os-name">
                      {hd.osInfo.name}{hd.osInfo.os_gen ? ` ${hd.osInfo.os_gen}` : ''}
                      {hd.osInfo.family && <span className="rp-os-family"> ({hd.osInfo.family})</span>}
                    </div>
                    {hd.osInfo.accuracy < 90 && (
                      <div className="rp-os-note">Detection confidence: {hd.osInfo.accuracy}%</div>
                    )}
                  </div>
                )}

                {openPorts.length > 0 ? (
                  <table className="rp-table rp-services-table">
                    <thead>
                      <tr><th>Port</th><th>Proto</th><th>State</th><th>Service</th><th>Product / Version</th></tr>
                    </thead>
                    <tbody>
                      {hd.services.map(svc => (
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
                ) : (
                  <p className="rp-no-data">No scan data for this host.</p>
                )}

                <div className="prr-host-stats">
                  <span><strong>{openPorts.length}</strong> open port{openPorts.length !== 1 ? 's' : ''}</span>
                  <span><strong>{hd.cveResults.length}</strong> CVE{hd.cveResults.length !== 1 ? 's' : ''}</span>
                  {nseVulns.length > 0 && <span><strong>{nseVulns.length}</strong> NSE flag{nseVulns.length !== 1 ? 's' : ''}</span>}
                  {hd.lootItems.length > 0 && <span><strong>{hd.lootItems.length}</strong> loot item{hd.lootItems.length !== 1 ? 's' : ''}</span>}
                </div>
              </div>
            );
          })}
        </section>

        {/* ═══════════════════ 4. CONSOLIDATED CVE FINDINGS ═══════════════════ */}
        <section className="rp-section">
          <h2 className="rp-section-title">4. Consolidated Vulnerability Findings</h2>

          {allCVEs.length === 0 ? (
            <p className="rp-no-data">No CVE findings across any host. Run CVE Analysis for each session.</p>
          ) : (
            allCVEs.map((item, idx) => {
              const fid   = `VULN-${String(idx + 1).padStart(3, '0')}`;
              const sev   = item.metrics?.severity || 'NONE';
              const score = item.metrics?.baseScore || 0;
              const col   = SEV_COLOR[sev] || '#546e7a';
              const bg    = SEV_BG[sev]   || '#f9f9f9';
              return (
                <div key={item.cve} className="rp-finding" style={{ borderLeftColor: col }}>
                  <div className="rp-fhdr">
                    <div className="rp-fhdr-left">
                      <span className="rp-fid">{fid}</span>
                      <span className="rp-fcve">{item.cve}</span>
                    </div>
                    <div className="rp-fhdr-right">
                      {sev !== 'NONE' && <span className="rp-sev-badge" style={{ background: col }}>{sev}</span>}
                      {score > 0 && <span className="rp-score-chip" style={{ color: col, borderColor: col }}>CVSS&nbsp;{score.toFixed(1)}</span>}
                    </div>
                  </div>

                  {score > 0 && (
                    <div className="rp-gauge">
                      <div className="rp-gauge-track">
                        <div className="rp-gauge-fill" style={{ width: `${score * 10}%`, background: col }} />
                      </div>
                      <span className="rp-gauge-val">{score.toFixed(1)} / 10.0</span>
                    </div>
                  )}

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
                              <span className="rp-exploit-note">Confirmed Metasploit Framework coverage:</span>
                              <ul className="rp-mod-list">
                                {item.modules.map(m => <li key={m}><code>{m}</code></li>)}
                              </ul>
                            </>
                          ) : (
                            <>
                              <span className="rp-exploit-note">Public PoC repositories found:</span>
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

          <RemediationRoadmap findings={allCVEs} />
        </section>

        {/* ═══════════════════ 5. POST-EXPLOITATION ═══════════════════ */}
        <section className="rp-section">
          <h2 className="rp-section-title">5. Post-Exploitation Findings</h2>

          {hostsWithLoot === 0 ? (
            <p className="rp-no-data">No post-exploitation data collected across any host.</p>
          ) : (
            <>
              <p>
                The following data was extracted during post-exploitation.
                All findings are sensitive and must be handled in accordance with applicable
                data handling and disclosure policies.
              </p>
              {hostData.filter(hd => hd.lootItems.length > 0).map(hd => (
                <div key={hd.session.id}>
                  <div className="prr-loot-host">
                    <code>{hd.session.target_host}</code>
                    <span>{hd.session.session_name}</span>
                  </div>
                  {Object.entries(
                    hd.lootItems.reduce((acc, it) => {
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
                </div>
              ))}
            </>
          )}
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
