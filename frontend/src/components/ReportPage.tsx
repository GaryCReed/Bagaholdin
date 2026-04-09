import { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import axios from 'axios';
import './ReportPage.css';

interface Session {
  id: number;
  session_name: string;
  target_host: string;
  is_running: boolean;
}

interface CVEMetrics {
  description: string;
  baseScore: number;
  severity: string;
  vector: string;
  cvssVersion: string;
}

interface GitHubRepo {
  full_name: string;
  description: string | null;
  stargazers_count: number;
  updated_at: string;
  html_url: string;
}

interface CVEResult {
  cve: string;
  modules: string[];
  targets?: string[];
  metrics?: CVEMetrics | null;
  githubRepos?: GitHubRepo[] | null;
}

interface LootField    { name: string; value: string }
interface LootItem     { type: string; source: string; timestamp: string; fields: LootField[] }

interface ServiceResult {
  port: number; protocol: string; state: string;
  name: string; product: string; version: string;
}

interface OSInfo { name: string; family: string; os_gen: string; accuracy: number }

interface VulnFinding {
  script:   string;
  title:    string;
  state:    string;
  cves:     string[];
  risk:     string;
  disclosed: string;
}

// Extract structured vulnerability findings from nmap vuln-script text output.
function parseVulnFindings(output: string): VulnFinding[] {
  const findings: VulnFinding[] = [];
  const lines = output.split('\n');
  let cur: VulnFinding | null = null;
  let inVuln = false;
  let titleSet = false;

  const flush = () => {
    if (cur && (cur.state.toUpperCase().includes('VULNERABLE') || cur.cves.length > 0)) {
      findings.push(cur);
    }
    cur = null; inVuln = false; titleSet = false;
  };

  for (const raw of lines) {
    // Strip nmap pipe prefix: "| " or "|_" or "|  "
    const stripped = raw.replace(/^\|[_ ]?/, '').trim();
    const lower = stripped.toLowerCase();

    // New script block: "| script-name: " at indent level 0
    const scriptMatch = raw.match(/^\|\s+([\w-]+):\s*$/);
    if (scriptMatch) {
      flush();
      cur = { script: scriptMatch[1], title: '', state: '', cves: [], risk: '', disclosed: '' };
      continue;
    }

    if (!cur) continue;

    if (lower === 'vulnerable:' || lower === 'likely vulnerable:') {
      cur.state = stripped.replace(':', '');
      inVuln = true; continue;
    }

    if (inVuln) {
      const stateMatch = stripped.match(/^State:\s+(.+)/i);
      if (stateMatch) { cur.state = stateMatch[1].trim(); continue; }

      const cveMatches = stripped.matchAll(/CVE-\d{4}-\d+/gi);
      for (const m of cveMatches) cur.cves.push(m[0].toUpperCase());

      const riskMatch = stripped.match(/^Risk factor:\s+(.+)/i);
      if (riskMatch) { cur.risk = riskMatch[1].trim(); continue; }

      const discMatch = stripped.match(/^Disclosure date:\s+(.+)/i);
      if (discMatch) { cur.disclosed = discMatch[1].trim(); continue; }

      // First substantive line after VULNERABLE: is the title
      if (!titleSet && stripped !== '' &&
          !stripped.match(/^(State|IDs|Risk|Disclosure|References|http|https):/i)) {
        cur.title = stripped;
        titleSet = true;
      }
    }
  }
  flush();

  // Deduplicate by script name
  const seen = new Set<string>();
  return findings.filter(f => { const k = f.script; if (seen.has(k)) return false; seen.add(k); return true; });
}

const LOOT_TYPE_LABEL: Record<string, string> = {
  system_info:          'System Information',
  current_user:         'Current User',
  privilege_escalation: 'Privilege Escalation',
  privileges:           'Privileges',
  is_admin:             'Admin Status',
  credential:           'Credentials',
  user_list:            'User List',
  user_account:         'User Accounts (/etc/passwd)',
  network_hosts:        'Network Hosts (ARP)',
  environment:          'Interesting Environment Variables',
  groups:               'Groups',
};

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'];

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: '#c62828',
  HIGH:     '#e64a19',
  MEDIUM:   '#f9a825',
  LOW:      '#1565c0',
  NONE:     '#555',
};

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
  const [loading,    setLoading]    = useState(true);

  useEffect(() => {
    axios.get(`/api/sessions/${sessionId}`)
      .then(res => setSession(res.data.session))
      .catch(() => {})
      .finally(() => setLoading(false));

    const savedVuln = localStorage.getItem(`session-${sessionId}-vuln`);
    if (savedVuln) setVulnOutput(savedVuln);

    const savedEnum = localStorage.getItem(`session-${sessionId}-enum`);
    if (savedEnum) {
      try { const { services: svcs } = JSON.parse(savedEnum); setServices(svcs || []); } catch {}
    }

    const savedOS = localStorage.getItem(`session-${sessionId}-os`);
    if (savedOS) {
      try { setOsInfo(JSON.parse(savedOS)); } catch {}
    }

    const savedCve = localStorage.getItem(`session-${sessionId}-cve`);
    if (savedCve) {
      try {
        const { results, target } = JSON.parse(savedCve);
        setCveResults(results || []);
        setCveTarget(target || '');
      } catch {}
    }

    const savedRemarks = localStorage.getItem(`session-${sessionId}-remarks`);
    if (savedRemarks) setRemarks(savedRemarks);

    axios.get(`/api/sessions/${sessionId}/loot`)
      .then(res => setLootItems(res.data.items || []))
      .catch(() => {});
  }, [sessionId]);

  const handleRemarks = (val: string) => {
    setRemarks(val);
    localStorage.setItem(`session-${sessionId}-remarks`, val);
  };

  // Severity counts + overall risk
  const sevCounts = cveResults.reduce((acc, r) => {
    const s = r.metrics?.severity || 'UNKNOWN';
    acc[s] = (acc[s] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const topSeverity = SEVERITY_ORDER.find(s => sevCounts[s]) || '';
  const overallRisk = topSeverity || (cveResults.length > 0 ? 'INFORMATIONAL' : 'N/A');

  const reportDate = new Date().toLocaleDateString('en-GB', {
    year: 'numeric', month: 'long', day: 'numeric',
  });

  const target = cveTarget || session?.target_host || 'Unknown';

  if (loading) return <div className="rp-loading">Loading report…</div>;

  return (
    <div className="rp-wrapper">

      {/* ── Toolbar (screen only) ── */}
      <div className="rp-toolbar no-print">
        <div className="rp-toolbar-left">
          <span className="rp-toolbar-title">Report Preview</span>
          <span className="rp-toolbar-hint">Fill in the Remarks section before printing.</span>
        </div>
        <button className="rp-btn-print" onClick={() => window.print()}>
          Print / Save as PDF
        </button>
      </div>

      {/* ── Report document ── */}
      <div className="rp-document">

        {/* Cover */}
        <div className="rp-cover">
          <div className="rp-cover-label">CONFIDENTIAL</div>
          <h1 className="rp-cover-title">Penetration Test Report</h1>
          <table className="rp-cover-table">
            <tbody>
              <tr>
                <td>Target Host</td>
                <td><strong>{session?.target_host || 'Unknown'}</strong></td>
              </tr>
              <tr>
                <td>Session Name</td>
                <td>{session?.session_name || `Session ${sessionId}`}</td>
              </tr>
              <tr>
                <td>Report Date</td>
                <td>{reportDate}</td>
              </tr>
              <tr>
                <td>Overall Risk</td>
                <td>
                  <span
                    className="rp-risk-badge"
                    style={{ background: SEVERITY_COLOR[overallRisk] || '#555' }}
                  >
                    {overallRisk}
                  </span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        {/* 1. Executive Summary */}
        <section className="rp-section">
          <h2 className="rp-section-title">1. Executive Summary</h2>
          <p>
            A penetration test was conducted against target host{' '}
            <strong>{target}</strong>.{' '}
            {cveResults.length > 0
              ? `The assessment identified ${cveResults.length} CVE${cveResults.length !== 1 ? 's' : ''} with an overall risk rating of ${overallRisk}.`
              : vulnOutput
                ? 'A vulnerability scan was completed. No CVEs were identified during analysis.'
                : 'No vulnerability scan data is currently available in this report.'}
          </p>

          {cveResults.length > 0 && (
            <table className="rp-table">
              <thead>
                <tr><th>Severity</th><th>Count</th></tr>
              </thead>
              <tbody>
                {Object.entries(sevCounts)
                  .sort((a, b) => {
                    const ai = SEVERITY_ORDER.indexOf(a[0]);
                    const bi = SEVERITY_ORDER.indexOf(b[0]);
                    return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
                  })
                  .map(([sev, count]) => (
                    <tr key={sev}>
                      <td>
                        <span
                          className="rp-sev-dot"
                          style={{ background: SEVERITY_COLOR[sev] || '#888' }}
                        />
                        {sev}
                      </td>
                      <td>{count}</td>
                    </tr>
                  ))}
              </tbody>
            </table>
          )}
        </section>

        {/* 2. Scope and Methodology */}
        <section className="rp-section">
          <h2 className="rp-section-title">2. Scope and Methodology</h2>
          <p><strong>Target:</strong> {session?.target_host || 'N/A'}</p>
          <p>The assessment was performed using Metasploit Web Interface and comprised the following phases:</p>
          <ol className="rp-list">
            <li>
              <strong>Vulnerability Scan</strong> — An nmap service and vulnerability scan
              (<code>nmap -v -sV --script=vuln</code>) was executed against the target to enumerate
              open services and identify known vulnerabilities.
            </li>
            <li>
              <strong>CVE Analysis</strong> — Identified CVEs were cross-referenced against the NVD
              database (CVSS v3.x/v2.0) and the Metasploit Framework module library.
            </li>
            <li>
              <strong>Exploit Research</strong> — For CVEs without Metasploit modules, publicly
              available exploit repositories on GitHub were identified and ranked by community activity.
            </li>
          </ol>
        </section>

        {/* 3. Findings */}
        <section className="rp-section">
          <h2 className="rp-section-title">3. Findings</h2>

          {cveResults.length === 0 ? (
            <p className="rp-no-data">
              No CVE findings available. Run CVE Analysis from the session view first.
            </p>
          ) : (
            cveResults.map((item, idx) => (
              <div key={item.cve} className="rp-finding">
                <div className="rp-finding-header">
                  <span className="rp-finding-num">{idx + 1}.</span>
                  <span className="rp-finding-cve">{item.cve}</span>
                  {item.metrics?.severity && (
                    <span
                      className="rp-finding-badge"
                      style={{ background: SEVERITY_COLOR[item.metrics.severity] || '#888' }}
                    >
                      {item.metrics.severity}
                      {item.metrics.baseScore > 0 ? ` ${item.metrics.baseScore.toFixed(1)}` : ''}
                      {item.metrics.cvssVersion ? ` (CVSSv${item.metrics.cvssVersion})` : ''}
                    </span>
                  )}
                </div>

                {item.targets && item.targets.length > 0 && (
                  <p className="rp-finding-targets">
                    <strong>Affected hosts:</strong>{' '}
                    {item.targets.map(t => <code key={t} className="rp-cve-tag">{t}</code>)}
                  </p>
                )}

                {item.metrics?.description && (
                  <p className="rp-finding-desc">{item.metrics.description}</p>
                )}

                {item.metrics?.vector && (
                  <p className="rp-finding-vector">
                    <strong>CVSS Vector:</strong> <code>{item.metrics.vector}</code>
                  </p>
                )}

                <div className="rp-finding-action">
                  <strong>Recommended Action:</strong>
                  {item.modules.length > 0 ? (
                    <>
                      <span> The following Metasploit modules are available for exploitation/validation:</span>
                      <ul className="rp-modules">
                        {item.modules.map(mod => (
                          <li key={mod}><code>{mod}</code></li>
                        ))}
                      </ul>
                    </>
                  ) : item.githubRepos && item.githubRepos.length > 0 ? (
                    <>
                      <span> No Metasploit module available. Public exploit repositories identified:</span>
                      <ul className="rp-modules">
                        {item.githubRepos.map(repo => (
                          <li key={repo.full_name}>
                            <a href={repo.html_url} target="_blank" rel="noopener noreferrer">
                              {repo.full_name}
                            </a>
                            {' '}(★{repo.stargazers_count.toLocaleString()})
                            {repo.description && ` — ${repo.description}`}
                          </li>
                        ))}
                      </ul>
                    </>
                  ) : (
                    <span> Apply vendor-supplied patches and review system hardening guidance for this vulnerability.</span>
                  )}
                </div>
              </div>
            ))
          )}
        </section>

        {/* 4. Scan Summary */}
        <section className="rp-section">
          <h2 className="rp-section-title">4. Scan Summary</h2>

          {!vulnOutput && services.length === 0 ? (
            <p className="rp-no-data">No vulnerability scan data available. Run a Vulnerability Scan from the session view first.</p>
          ) : (
            <>
              {/* OS detection */}
              {osInfo && (
                <div className="rp-scan-meta">
                  <strong>Detected OS:</strong>{' '}
                  {osInfo.name}
                  {osInfo.os_gen ? ` ${osInfo.os_gen}` : ''}
                  {osInfo.family ? ` (${osInfo.family})` : ''}
                  {osInfo.accuracy < 90 ? <span className="rp-scan-approx"> — approximate ({osInfo.accuracy}% confidence)</span> : null}
                </div>
              )}

              {/* Discovered services */}
              {services.length > 0 && (
                <>
                  <h3 className="rp-subsection-title">Discovered Services</h3>
                  <table className="rp-table">
                    <thead>
                      <tr>
                        <th>Port</th>
                        <th>Protocol</th>
                        <th>State</th>
                        <th>Service</th>
                        <th>Product / Version</th>
                      </tr>
                    </thead>
                    <tbody>
                      {services.map(svc => (
                        <tr key={`${svc.port}-${svc.protocol}`}>
                          <td><code>{svc.port}</code></td>
                          <td>{svc.protocol.toUpperCase()}</td>
                          <td className={svc.state === 'open' ? 'rp-state-open' : 'rp-state-filtered'}>
                            {svc.state}
                          </td>
                          <td>{svc.name}</td>
                          <td>{[svc.product, svc.version].filter(Boolean).join(' ') || '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </>
              )}

              {/* NSE vulnerability script findings */}
              {(() => {
                const findings = vulnOutput ? parseVulnFindings(vulnOutput) : [];
                if (findings.length === 0) return null;
                return (
                  <>
                    <h3 className="rp-subsection-title">NSE Vulnerability Script Findings</h3>
                    {findings.map(f => (
                      <div key={f.script} className="rp-vuln-finding">
                        <div className="rp-vuln-header">
                          <code className="rp-vuln-script">{f.script}</code>
                          {f.risk && (
                            <span className="rp-finding-badge"
                              style={{ background: SEVERITY_COLOR[f.risk.toUpperCase()] || '#555' }}>
                              {f.risk.toUpperCase()}
                            </span>
                          )}
                          <span className={`rp-vuln-state ${f.state.toUpperCase().includes('VULNERABLE') ? 'rp-state-vuln' : 'rp-state-likely'}`}>
                            {f.state}
                          </span>
                        </div>
                        {f.title && <p className="rp-vuln-title">{f.title}</p>}
                        {f.cves.length > 0 && (
                          <p className="rp-vuln-cves">
                            <strong>CVEs:</strong>{' '}
                            {f.cves.map(c => (
                              <code key={c} className="rp-cve-tag">{c}</code>
                            ))}
                          </p>
                        )}
                        {f.disclosed && <p className="rp-vuln-meta">Disclosed: {f.disclosed}</p>}
                      </div>
                    ))}
                  </>
                );
              })()}
            </>
          )}
        </section>

        {/* 5. Loot */}
        <section className="rp-section">
          <h2 className="rp-section-title">5. Loot</h2>
          {lootItems.length === 0 ? (
            <p className="rp-no-data">No loot collected. Run post-exploitation commands to populate this section.</p>
          ) : (
            Object.entries(
              lootItems.reduce((acc, item) => {
                const key = item.type;
                if (!acc[key]) acc[key] = [];
                acc[key].push(item);
                return acc;
              }, {} as Record<string, LootItem[]>)
            ).map(([type, items]) => (
              <div key={type} className="rp-loot-group">
                <h3 className="rp-loot-group-title">
                  {LOOT_TYPE_LABEL[type] || type}
                </h3>
                {items.map((item, i) => (
                  <table key={i} className="rp-table rp-loot-table">
                    <thead>
                      <tr>
                        <th colSpan={2} className="rp-loot-source">
                          Source: <code>{item.source}</code>
                          <span className="rp-loot-ts"> — {new Date(item.timestamp).toLocaleString()}</span>
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {item.fields.map(f => (
                        <tr key={f.name}>
                          <td className="rp-loot-key">{f.name}</td>
                          <td className="rp-loot-val"><pre className="rp-loot-pre">{f.value}</pre></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ))}
              </div>
            ))
          )}
        </section>

        {/* 6. Remarks (editable on screen, rendered text on print) */}
        <section className="rp-section rp-remarks-section">
          <h2 className="rp-section-title">6. Remarks</h2>
          <p className="no-print rp-remarks-hint">
            Enter additional observations, recommendations, or conclusions below.
            This text will appear in the printed report.
          </p>
          <textarea
            className="rp-remarks-input no-print"
            value={remarks}
            onChange={e => handleRemarks(e.target.value)}
            placeholder="Enter remarks, observations, or conclusions here…"
            rows={10}
          />
          <div className="print-only rp-remarks-text">
            {remarks || <em>No remarks entered.</em>}
          </div>
        </section>

      </div>
    </div>
  );
}
