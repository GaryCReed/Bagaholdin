import { useState, useEffect, useRef } from 'react';
import { useParams, Link } from 'react-router-dom';
import axios from 'axios';
import Console from './Console';
import './SessionDetail.css';

interface SessionDetailProps {
  onLogout: () => void;
}

interface Session {
  id: number;
  session_name: string;
  target_host: string;
  is_running: boolean;
  project_id?: number;
}

interface CVEMetrics {
  description: string;
  baseScore: number;
  severity: string;   // CRITICAL | HIGH | MEDIUM | LOW | NONE
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
  metricsLoading?: boolean;
  githubRepos?: GitHubRepo[] | null;
  githubLoading?: boolean;
  githubError?: string;
}

interface OSInfo {
  name: string;
  family: string;   // "Linux" | "Windows" | ""
  os_gen: string;
  accuracy: number;
}

interface ShellEntry { cmd: string; output: string; error?: string }

interface MsfSession {
  id: string;
  type: string;
  info: string;
  connection: string;
}

interface ServiceResult {
  port: number;
  protocol: string;
  state: string;
  name: string;
  product: string;
  version: string;
  modules: string[];
}

const ACTIONS = [
  { id: 1, label: '1. Vulnerability Scan' },
  { id: 2, label: '2. Enumeration' },
  { id: 3, label: '3. CVE Analysis' },
  { id: 4, label: '4. Shells' },
  { id: 5, label: '5. Post Exploitation' },
  { id: 6, label: '6. Reporting' },
];

// ── Quick command buttons ──
// sessionType: 'meterpreter' | 'shell' | 'any'
// platform:    'any' | 'linux' | 'windows'
interface PostExCmd { label: string; cmd: string }
interface PostExGroup {
  label: string;
  sessionType: 'meterpreter' | 'shell' | 'any';
  platform: 'any' | 'linux' | 'windows';
  commands: PostExCmd[];
}

const POST_EX_QUICK: PostExGroup[] = [
  // ── Meterpreter / any OS ──
  {
    label: 'System', sessionType: 'meterpreter', platform: 'any',
    commands: [
      { label: 'sysinfo',      cmd: 'sysinfo' },
      { label: 'getuid',       cmd: 'getuid' },
      { label: 'getpid',       cmd: 'getpid' },
      { label: 'ps',           cmd: 'ps' },
      { label: 'env',          cmd: 'env' },
    ],
  },
  {
    label: 'Privileges', sessionType: 'meterpreter', platform: 'any',
    commands: [
      { label: 'getsystem',    cmd: 'getsystem' },
      { label: 'getprivs',     cmd: 'getprivs' },
      { label: 'is_admin',     cmd: 'is_admin' },
    ],
  },
  {
    label: 'Network', sessionType: 'meterpreter', platform: 'any',
    commands: [
      { label: 'ipconfig',     cmd: 'ipconfig' },
      { label: 'arp',          cmd: 'arp' },
      { label: 'route',        cmd: 'route' },
      { label: 'netstat',      cmd: 'netstat' },
      { label: 'portfwd list', cmd: 'portfwd list' },
    ],
  },
  {
    label: 'Files', sessionType: 'meterpreter', platform: 'any',
    commands: [
      { label: 'pwd',          cmd: 'pwd' },
      { label: 'ls',           cmd: 'ls' },
      { label: 'search',       cmd: 'search -f *.txt' },
    ],
  },
  // ── Meterpreter / Linux ──
  {
    label: 'Linux Info', sessionType: 'meterpreter', platform: 'linux',
    commands: [
      { label: 'uname -a',     cmd: 'shell uname -a' },
      { label: 'id',           cmd: 'shell id' },
      { label: 'cat /etc/passwd', cmd: 'shell cat /etc/passwd' },
      { label: 'crontab -l',   cmd: 'shell crontab -l' },
    ],
  },
  {
    label: 'Linux Creds', sessionType: 'meterpreter', platform: 'linux',
    commands: [
      { label: 'hashdump',     cmd: 'run post/linux/gather/hashdump' },
      { label: 'mimipenguin',  cmd: 'run post/linux/gather/mimipenguin' },
      { label: 'ssh keys',     cmd: 'run post/linux/gather/ssh_creds' },
      { label: 'user history', cmd: 'run post/linux/gather/enum_users_history' },
    ],
  },
  // ── Meterpreter / Windows ──
  {
    label: 'Windows Info', sessionType: 'meterpreter', platform: 'windows',
    commands: [
      { label: 'shell ver',    cmd: 'shell ver' },
      { label: 'shell whoami /all', cmd: 'shell whoami /all' },
      { label: 'shell net user', cmd: 'shell net user' },
      { label: 'shell ipconfig /all', cmd: 'shell ipconfig /all' },
    ],
  },
  {
    label: 'Windows Creds', sessionType: 'meterpreter', platform: 'windows',
    commands: [
      { label: 'hashdump',     cmd: 'hashdump' },
      { label: 'lsa_secrets',  cmd: 'run post/windows/gather/lsa_secrets' },
      { label: 'cached creds', cmd: 'run post/windows/gather/cachedump' },
      { label: 'enum tokens',  cmd: 'run post/windows/gather/enum_tokens' },
    ],
  },
  // ── Shell / any OS ──
  {
    label: 'System', sessionType: 'shell', platform: 'any',
    commands: [
      { label: 'id',           cmd: 'id' },
      { label: 'whoami',       cmd: 'whoami' },
      { label: 'uname -a',     cmd: 'uname -a' },
      { label: 'hostname',     cmd: 'hostname' },
    ],
  },
  {
    label: 'Network', sessionType: 'shell', platform: 'any',
    commands: [
      { label: 'ifconfig',     cmd: 'ifconfig 2>/dev/null || ipconfig' },
      { label: 'netstat -an',  cmd: 'netstat -an' },
      { label: 'ss -tlnp',     cmd: 'ss -tlnp' },
    ],
  },
  // ── Shell / Linux ──
  {
    label: 'Linux Enum', sessionType: 'shell', platform: 'linux',
    commands: [
      { label: 'cat /etc/passwd', cmd: 'cat /etc/passwd' },
      { label: 'cat /etc/shadow', cmd: 'cat /etc/shadow' },
      { label: 'sudo -l',      cmd: 'sudo -l -n 2>&1' },
      { label: 'find suid',    cmd: 'find / -perm -4000 -type f 2>/dev/null' },
      { label: 'crontab -l',   cmd: 'crontab -l' },
      { label: 'env',          cmd: 'env' },
    ],
  },
  // ── Shell / Windows ──
  {
    label: 'Windows Enum', sessionType: 'shell', platform: 'windows',
    commands: [
      { label: 'systeminfo',   cmd: 'systeminfo' },
      { label: 'whoami /all',  cmd: 'whoami /all' },
      { label: 'net users',    cmd: 'net user' },
      { label: 'net localgroup admins', cmd: 'net localgroup administrators' },
      { label: 'tasklist',     cmd: 'tasklist' },
    ],
  },
];

// ── Recommended MSF modules ──
interface PostExModule {
  module: string;
  label: string;
  description: string;
  category: 'Gather' | 'Persist' | 'Escalate' | 'Exfil' | 'Pivot';
  sessionType: 'meterpreter' | 'shell' | 'any';
  platform: 'any' | 'linux' | 'windows';
}

const POST_EX_MODULES: PostExModule[] = [
  // ── Multi / any ──
  { module: 'post/multi/recon/local_exploit_suggester', label: 'Local Exploit Suggester',
    description: 'Suggests local privilege escalation exploits for the current session',
    category: 'Escalate', sessionType: 'meterpreter', platform: 'any' },
  { module: 'post/multi/gather/env',                   label: 'Gather Environment',
    description: 'Enumerates environment variables from the target',
    category: 'Gather', sessionType: 'meterpreter', platform: 'any' },
  { module: 'post/multi/gather/docker_creds',          label: 'Docker Credentials',
    description: 'Retrieves Docker credentials and config from the target',
    category: 'Gather', sessionType: 'meterpreter', platform: 'any' },
  { module: 'post/multi/manage/shell_to_meterpreter',  label: 'Shell → Meterpreter',
    description: 'Upgrades a plain shell session to a Meterpreter session',
    category: 'Pivot', sessionType: 'shell', platform: 'any' },
  { module: 'post/multi/manage/autoroute',             label: 'Autoroute',
    description: 'Adds routes to subnets reachable via this session for pivoting',
    category: 'Pivot', sessionType: 'meterpreter', platform: 'any' },
  // ── Linux / Gather ──
  { module: 'post/linux/gather/enum_system',           label: 'Enum System',
    description: 'Gathers detailed system information: OS, kernel, users, cron, services',
    category: 'Gather', sessionType: 'meterpreter', platform: 'linux' },
  { module: 'post/linux/gather/enum_configs',          label: 'Enum Configs',
    description: 'Reads common config files (apache, nginx, SSH, etc.)',
    category: 'Gather', sessionType: 'meterpreter', platform: 'linux' },
  { module: 'post/linux/gather/enum_network',          label: 'Enum Network',
    description: 'Enumerates network interfaces, routes, and listening services',
    category: 'Gather', sessionType: 'meterpreter', platform: 'linux' },
  { module: 'post/linux/gather/enum_protections',      label: 'Enum Protections',
    description: 'Checks for security tools (AV, HIDS, SELinux, AppArmor)',
    category: 'Gather', sessionType: 'meterpreter', platform: 'linux' },
  { module: 'post/linux/gather/enum_users_history',    label: 'User History',
    description: 'Dumps bash/zsh history and SSH keys from all user home directories',
    category: 'Gather', sessionType: 'meterpreter', platform: 'linux' },
  { module: 'post/linux/gather/hashdump',              label: 'Hash Dump',
    description: 'Dumps /etc/shadow password hashes (requires root)',
    category: 'Exfil', sessionType: 'meterpreter', platform: 'linux' },
  { module: 'post/linux/gather/mimipenguin',           label: 'Mimipenguin',
    description: 'Dumps cleartext credentials from memory (gnome-keyring, lightdm, vsftpd)',
    category: 'Exfil', sessionType: 'meterpreter', platform: 'linux' },
  { module: 'post/linux/gather/openvpn_credentials',   label: 'OpenVPN Creds',
    description: 'Extracts OpenVPN configuration and credentials',
    category: 'Exfil', sessionType: 'meterpreter', platform: 'linux' },
  // ── Linux / Persist ──
  { module: 'post/linux/manage/sshkey_persistence',    label: 'SSH Key Persistence',
    description: 'Adds attacker SSH public key to authorized_keys for backdoor access',
    category: 'Persist', sessionType: 'meterpreter', platform: 'linux' },
  { module: 'post/linux/manage/cron_persistence',      label: 'Cron Persistence',
    description: 'Installs a cron job that calls back to the attacker on schedule',
    category: 'Persist', sessionType: 'meterpreter', platform: 'linux' },
  // ── Windows / Gather ──
  { module: 'post/windows/gather/enum_applications',   label: 'Enum Applications',
    description: 'Lists installed applications from the Windows registry',
    category: 'Gather', sessionType: 'meterpreter', platform: 'windows' },
  { module: 'post/windows/gather/enum_patches',        label: 'Enum Patches',
    description: 'Lists installed Windows hotfixes and KB patches',
    category: 'Gather', sessionType: 'meterpreter', platform: 'windows' },
  { module: 'post/windows/gather/enum_shares',         label: 'Enum Shares',
    description: 'Enumerates SMB shares accessible from the target',
    category: 'Gather', sessionType: 'meterpreter', platform: 'windows' },
  { module: 'post/windows/gather/enum_domain',         label: 'Enum Domain',
    description: 'Enumerates Active Directory domain information',
    category: 'Gather', sessionType: 'meterpreter', platform: 'windows' },
  { module: 'post/windows/gather/enum_domain_users',   label: 'Domain Users',
    description: 'Lists all domain user accounts via LDAP',
    category: 'Gather', sessionType: 'meterpreter', platform: 'windows' },
  { module: 'post/windows/gather/bloodhound',          label: 'BloodHound',
    description: 'Collects Active Directory data for BloodHound analysis',
    category: 'Gather', sessionType: 'meterpreter', platform: 'windows' },
  // ── Windows / Exfil (creds) ──
  { module: 'post/windows/gather/lsa_secrets',         label: 'LSA Secrets',
    description: 'Extracts LSA secrets including cached domain credentials (requires SYSTEM)',
    category: 'Exfil', sessionType: 'meterpreter', platform: 'windows' },
  { module: 'post/windows/gather/cachedump',           label: 'Cached Creds',
    description: 'Dumps cached domain credentials from the registry',
    category: 'Exfil', sessionType: 'meterpreter', platform: 'windows' },
  { module: 'post/windows/gather/credentials/credential_collector',
    label: 'Credential Collector',
    description: 'Collects stored credentials from browsers, FTP clients, and more',
    category: 'Exfil', sessionType: 'meterpreter', platform: 'windows' },
  { module: 'post/windows/gather/enum_tokens',         label: 'Enum Tokens',
    description: 'Lists available impersonation tokens for privilege escalation',
    category: 'Escalate', sessionType: 'meterpreter', platform: 'windows' },
  // ── Windows / Persist ──
  { module: 'post/windows/manage/persistence',         label: 'Registry Persistence',
    description: 'Installs a persistent payload via the Windows registry run key',
    category: 'Persist', sessionType: 'meterpreter', platform: 'windows' },
  { module: 'post/windows/manage/enable_rdp',          label: 'Enable RDP',
    description: 'Enables Remote Desktop Protocol on the target machine',
    category: 'Persist', sessionType: 'meterpreter', platform: 'windows' },
  { module: 'post/windows/manage/add_user',            label: 'Add User',
    description: 'Creates a new local user account on the target',
    category: 'Persist', sessionType: 'meterpreter', platform: 'windows' },
  // ── Windows / Escalate ──
  { module: 'post/windows/escalate/getsystem',         label: 'Get SYSTEM',
    description: 'Attempts to escalate to SYSTEM privileges using named pipe impersonation',
    category: 'Escalate', sessionType: 'meterpreter', platform: 'windows' },
];

const CATEGORY_ORDER = ['Gather', 'Escalate', 'Exfil', 'Persist', 'Pivot'] as const;
const CATEGORY_COLOR: Record<string, string> = {
  Gather:   '#4fc1ff',
  Escalate: '#e5c07b',
  Exfil:    '#e06c75',
  Persist:  '#c678dd',
  Pivot:    '#56b6c2',
};

// Parse MSF "sessions -l" text output into structured sessions.
function parseMsfSessions(text: string): MsfSession[] {
  const sessions: MsfSession[] = [];
  const lines = text.split('\n');
  let pastHeader = false;
  for (const line of lines) {
    if (!pastHeader) {
      if (/^[\s-]+$/.test(line) && line.includes('--')) pastHeader = true;
      continue;
    }
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('msf')) break;
    // Columns: Id  Name  Type  Information  Connection
    const m = trimmed.match(/^(\d+)\s+\S*\s+((?:meterpreter|shell)\s+\S+)\s{2,}(.*?)\s{2,}(\S+\s*->\s*\S+(?:\s+\(\S+\))?)?$/);
    if (m) {
      sessions.push({ id: m[1], type: m[2].trim(), info: m[3].trim(), connection: m[4]?.trim() || '' });
    }
  }
  return sessions;
}

// Fetch CVE summary from NVD public API (CORS-enabled, no key required).
async function fetchNVDMetrics(cveID: string): Promise<CVEMetrics | null> {
  try {
    const res = await fetch(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveID)}`
    );
    if (!res.ok) return null;
    const data = await res.json();
    const vuln = data.vulnerabilities?.[0]?.cve;
    if (!vuln) return null;
    const description: string = vuln.descriptions?.find((d: any) => d.lang === 'en')?.value ?? '';
    const m31 = vuln.metrics?.cvssMetricV31?.[0];
    const m30 = vuln.metrics?.cvssMetricV30?.[0];
    const m2  = vuln.metrics?.cvssMetricV2?.[0];
    if (m31 || m30) {
      const m = (m31 || m30)!;
      return { description, baseScore: m.cvssData.baseScore, severity: m.cvssData.baseSeverity,
               vector: m.cvssData.vectorString, cvssVersion: m31 ? '3.1' : '3.0' };
    }
    if (m2) {
      return { description, baseScore: m2.cvssData.baseScore, severity: m2.baseSeverity,
               vector: m2.cvssData.vectorString, cvssVersion: '2.0' };
    }
    return description ? { description, baseScore: 0, severity: '', vector: '', cvssVersion: '' } : null;
  } catch { return null; }
}

// Fetch top exploit repos for a CVE from the GitHub search API.
async function fetchGitHubRepos(cveID: string): Promise<{ repos: GitHubRepo[] | null; error?: string }> {
  try {
    const q = encodeURIComponent(`${cveID} exploit`);
    const res = await fetch(
      `https://api.github.com/search/repositories?q=${q}&sort=stars&order=desc&per_page=5`,
      { headers: { Accept: 'application/vnd.github+json' } }
    );
    if (res.status === 403 || res.status === 429)
      return { repos: null, error: 'GitHub rate limit reached — try again in a minute' };
    if (!res.ok) return { repos: null, error: `GitHub search failed (${res.status})` };
    const data = await res.json();
    const cutoff = new Date();
    cutoff.setFullYear(cutoff.getFullYear() - 5);
    const filtered: GitHubRepo[] = (data.items || [])
      .filter((r: GitHubRepo) => new Date(r.updated_at) >= cutoff)
      .slice(0, 3);
    return { repos: filtered };
  } catch { return { repos: null, error: 'GitHub search unavailable' }; }
}

const sleep = (ms: number) => new Promise<void>(r => setTimeout(r, ms));
const NVD_DELAY_MS = 7000;

export default function SessionDetail({ onLogout }: SessionDetailProps) {
  const { id } = useParams<{ id: string }>();
  const sessionId = parseInt(id || '0', 10);

  const [session, setSession]           = useState<Session | null>(null);
  const [activeAction, setActiveAction] = useState<number | null>(null);
  const [localIfaces, setLocalIfaces]   = useState<{ name: string; cidr: string; ip: string }[]>([]);

  // Vuln scan state
  const [vulnOutput, setVulnOutput]   = useState('');
  const [vulnLoading, setVulnLoading] = useState(false);
  const [vulnError, setVulnError]     = useState('');
  const vulnOutputRef = useRef<HTMLPreElement>(null);
  const vulnPollRef   = useRef<ReturnType<typeof setInterval> | null>(null);

  // CVE analysis state
  const [cveResults, setCveResults]   = useState<CVEResult[]>([]);
  const [cveLoading, setCveLoading]   = useState(false);
  const [cveError, setCveError]       = useState('');
  const [cveTarget, setCveTarget]     = useState('');
  const [cveAnalysed, setCveAnalysed] = useState(false);
  const [copied, setCopied]           = useState<string | null>(null);
  const cveRunIdRef = useRef(0);

  // OS detection state
  const [osInfo, setOsInfo] = useState<OSInfo | null>(null);

  // Enumeration state
  const [enumResults, setEnumResults] = useState<ServiceResult[]>([]);
  const [enumLoading, setEnumLoading] = useState(false);
  const [enumError, setEnumError]     = useState('');
  const [enumTarget, setEnumTarget]   = useState('');
  const enumLoadingRef  = useRef(false); // synchronous guard
  const runModuleRef    = useRef(false); // synchronous guard for handleRunModule

  // MSF sessions (Shells tab) state
  const [msfSessions, setMsfSessions]               = useState<MsfSession[]>([]);
  const [msfSessionsLoading, setMsfSessionsLoading] = useState(false);
  const msfLoadingRef = useRef(false); // synchronous guard against double-fire
  const [upgradedSessions, setUpgradedSessions]     = useState<Set<string>>(new Set());
  const upgradingRef = useRef<Set<string>>(new Set());
  // Tracks which MSF session is currently entered interactively (sessions -i <id>)
  // isMeterpreter distinguishes confirmation behaviour: shell sessions prompt "Background session N? [y/N]"
  const interactedSessionRef = useRef<{ id: string; isMeterpreter: boolean } | null>(null);


  // Post exploitation state
  const [postHistory, setPostHistory] = useState<ShellEntry[]>([]);
  const [postLoading, setPostLoading] = useState(false);
  const [postRunning, setPostRunning] = useState('');
  const postRunningRef = useRef(false); // ref-based guard against double-fire

  // Enumeration — which service's module list is expanded (one at a time)
  const [expandedEnumKey, setExpandedEnumKey] = useState<string | null>(null);

  useEffect(() => {
    if (!sessionId) return;
    axios.get(`/api/sessions/${sessionId}`)
      .then(res => setSession(res.data.session))
      .catch(() => {});
    axios.get('/api/network')
      .then(res => setLocalIfaces(res.data.interfaces || []))
      .catch(() => {});
  }, [sessionId]);

  // On mount: check if a scan is already running server-side and resume polling if so.
  // Also clean up the poll interval on unmount.
  useEffect(() => {
    if (!sessionId) return;
    axios.get(`/api/sessions/${sessionId}/vuln-scan`).then(res => {
      if (res.data.status === 'running') {
        setVulnLoading(true);
        startVulnPoll();
      } else if (res.data.status === 'done' && !localStorage.getItem(`session-${sessionId}-vuln`)) {
        applyVulnResult(res.data);
      }
    }).catch(() => {});
    return () => stopVulnPoll();
  }, [sessionId]); // eslint-disable-line react-hooks/exhaustive-deps

  // Restore persisted data from localStorage on mount
  useEffect(() => {
    if (!sessionId) return;

    const savedVuln = localStorage.getItem(`session-${sessionId}-vuln`);
    if (savedVuln) setVulnOutput(savedVuln);

    const savedCve = localStorage.getItem(`session-${sessionId}-cve`);
    if (savedCve) {
      try {
        const { results, target, analysed } = JSON.parse(savedCve);
        const restored: CVEResult[] = (results || []).map((r: CVEResult) => ({
          ...r, metricsLoading: false, githubLoading: false,
        }));
        setCveResults(restored);
        setCveTarget(target || '');
        setCveAnalysed(analysed || false);
      } catch { /* ignore corrupt cache */ }
    }

    const savedEnum = localStorage.getItem(`session-${sessionId}-enum`);
    if (savedEnum) {
      try {
        const { services, target } = JSON.parse(savedEnum);
        setEnumResults(services || []);
        setEnumTarget(target || '');
      } catch { /* ignore corrupt cache */ }
    }

    const savedOS = localStorage.getItem(`session-${sessionId}-os`);
    if (savedOS) {
      try { setOsInfo(JSON.parse(savedOS)); } catch {}
    }

    const savedShells = localStorage.getItem(`session-${sessionId}-msf-sessions`);
    if (savedShells) {
      try { setMsfSessions(JSON.parse(savedShells)); } catch {}
    }
  }, [sessionId]);

  // Persist vuln output
  useEffect(() => {
    if (vulnOutput && sessionId)
      localStorage.setItem(`session-${sessionId}-vuln`, vulnOutput);
  }, [vulnOutput, sessionId]);

  // Persist enumeration results
  useEffect(() => {
    if (sessionId && enumResults.length > 0)
      localStorage.setItem(`session-${sessionId}-enum`, JSON.stringify({ services: enumResults, target: enumTarget }));
  }, [enumResults, enumTarget, sessionId]);

  // Persist MSF sessions list
  useEffect(() => {
    if (sessionId && msfSessions.length > 0)
      localStorage.setItem(`session-${sessionId}-msf-sessions`, JSON.stringify(msfSessions));
  }, [msfSessions, sessionId]);

  // Persist CVE state when settled
  useEffect(() => {
    if (!sessionId || cveLoading) return;
    if (cveResults.some(r => r.metricsLoading || r.githubLoading)) return;
    if (cveResults.length > 0 || cveAnalysed) {
      localStorage.setItem(`session-${sessionId}-cve`, JSON.stringify({
        results: cveResults, target: cveTarget, analysed: cveAnalysed,
      }));
    }
  }, [cveResults, cveTarget, cveAnalysed, cveLoading, sessionId]);

  // Abort CVE NVD fetches when leaving CVE panel
  useEffect(() => {
    if (activeAction !== 3) cveRunIdRef.current++;
  }, [activeAction]);

  useEffect(() => {
    if (vulnOutputRef.current)
      vulnOutputRef.current.scrollTop = vulnOutputRef.current.scrollHeight;
  }, [vulnOutput]);

  // Auto-run CVE analysis when first opening the CVE panel if scan data exists but analysis not yet done
  useEffect(() => {
    if (activeAction === 3 && !cveAnalysed && !cveLoading && cveResults.length === 0 && vulnOutput)
      handleCVEAnalysis();
  }, [activeAction]); // eslint-disable-line react-hooks/exhaustive-deps

  // Always refresh MSF sessions when opening the Shells tab
  useEffect(() => {
    if (activeAction === 4) loadMsfSessions();
  }, [activeAction]); // eslint-disable-line react-hooks/exhaustive-deps


  // Apply completed scan results (shared by poll and resume-on-mount paths).
  const applyVulnResult = (data: any) => {
    setVulnOutput(data.output || '(no output)');
    if (data.os_info) {
      setOsInfo(data.os_info);
      localStorage.setItem(`session-${sessionId}-os`, JSON.stringify(data.os_info));
    }
    if (data.services && data.services.length > 0) {
      setEnumResults(data.services);
      setEnumTarget(data.target || '');
    }
  };

  const stopVulnPoll = () => {
    if (vulnPollRef.current !== null) {
      clearInterval(vulnPollRef.current);
      vulnPollRef.current = null;
    }
  };

  const startVulnPoll = () => {
    stopVulnPoll();
    vulnPollRef.current = setInterval(async () => {
      try {
        const res = await axios.get(`/api/sessions/${sessionId}/vuln-scan`);
        if (res.data.status === 'done') {
          stopVulnPoll();
          applyVulnResult(res.data);
          setVulnLoading(false);
        } else if (res.data.status === 'error') {
          stopVulnPoll();
          setVulnError(res.data.error || 'Scan failed');
          setVulnLoading(false);
        }
        // 'running' → keep polling
      } catch {
        // network blip — keep polling
      }
    }, 3000);
  };

  const handleVulnScan = async () => {
    setVulnLoading(true);
    setVulnError('');
    setVulnOutput('');
    localStorage.removeItem(`session-${sessionId}-vuln`);
    try {
      const res = await axios.post(`/api/sessions/${sessionId}/vuln-scan`, {});
      if (res.data.status === 'started' || res.data.status === 'running') {
        startVulnPoll();
      }
    } catch (err: any) {
      setVulnError(err.response?.data?.error || err.message || 'Scan failed');
      setVulnLoading(false);
    }
  };

  const handleCVEAnalysis = async () => {
    const runId = ++cveRunIdRef.current;
    setCveLoading(true);
    setCveError('');
    setCveResults([]);
    setCveAnalysed(false);

    try {
      const res = await axios.post(
        `/api/sessions/${sessionId}/cve-analysis`, {},
        { timeout: 3 * 60 * 1000 }
      );
      if (runId !== cveRunIdRef.current) return;
      setCveTarget(res.data.target || '');

      const initial: CVEResult[] = (res.data.cves || []).map((r: CVEResult) => ({
        ...r, metricsLoading: true, metrics: null,
        githubRepos: undefined, githubLoading: false, githubError: undefined,
      }));
      setCveResults(initial);
      setCveLoading(false);
      if (initial.length === 0) { setCveAnalysed(true); return; }

      for (let i = 0; i < initial.length; i++) {
        if (runId !== cveRunIdRef.current) {
          setCveResults(prev => prev.map(r => r.metricsLoading ? { ...r, metricsLoading: false } : r));
          break;
        }
        const metrics = await fetchNVDMetrics(initial[i].cve);
        if (runId !== cveRunIdRef.current) {
          setCveResults(prev => prev.map(r => r.metricsLoading ? { ...r, metricsLoading: false } : r));
          break;
        }
        setCveResults(prev => {
          const next = [...prev];
          next[i] = { ...next[i], metrics, metricsLoading: false };
          return next;
        });

        if (initial[i].modules.length === 0 && runId === cveRunIdRef.current) {
          setCveResults(prev => { const n = [...prev]; n[i] = { ...n[i], githubLoading: true }; return n; });
          const { repos, error } = await fetchGitHubRepos(initial[i].cve);
          if (runId === cveRunIdRef.current) {
            setCveResults(prev => {
              const n = [...prev];
              n[i] = { ...n[i], githubRepos: repos, githubLoading: false, githubError: error };
              return n;
            });
          }
        }

        if (i < initial.length - 1 && runId === cveRunIdRef.current)
          await sleep(NVD_DELAY_MS);
      }
      if (runId === cveRunIdRef.current) setCveAnalysed(true);
    } catch (err: any) {
      if (runId !== cveRunIdRef.current) return;
      setCveError(err.response?.data?.error || err.message || 'Analysis failed');
      setCveLoading(false);
    }
  };

  const handleEnumerate = async () => {
    if (enumLoadingRef.current) return;
    enumLoadingRef.current = true;
    setEnumLoading(true);
    setEnumError('');
    try {
      const res = await axios.post(
        `/api/sessions/${sessionId}/enumerate`,
        { os_family: osInfo?.family || '' },
        { timeout: 2 * 60 * 1000 }
      );
      setEnumResults(res.data.services || []);
      setEnumTarget(res.data.target || '');
    } catch (err: any) {
      setEnumError(err.response?.data?.error || err.message || 'Enumeration failed');
    } finally {
      enumLoadingRef.current = false;
      setEnumLoading(false);
    }
  };

  const sendShellCmd = async (cmd: string) => {
    try {
      await axios.post(`/api/sessions/${sessionId}/shell`, { command: cmd }, { timeout: 15 * 1000 });
    } catch { /* best-effort */ }
  };

  // Ensure msfconsole is back at the msf> prompt before sending msf-level commands.
  // Shell sessions show "Background session N? [y/N]" and need a 'y' reply.
  // Meterpreter sessions background silently.
  const ensureMsfPrompt = async () => {
    if (interactedSessionRef.current === null) return;
    const isMeterpreter = interactedSessionRef.current.isMeterpreter;
    interactedSessionRef.current = null;
    await sendShellCmd('background');
    if (!isMeterpreter) {
      // Confirm the shell's "Background session N? [y/N]" prompt
      await sendShellCmd('y');
    }
  };

  const loadMsfSessions = async () => {
    if (msfLoadingRef.current) return;
    msfLoadingRef.current = true;
    setMsfSessionsLoading(true);
    try {
      // Return to msf> prompt before running 'sessions -l'
      await ensureMsfPrompt();
      const res = await axios.get(`/api/sessions/${sessionId}/msf-sessions`);
      const parsed = parseMsfSessions(res.data.output || '');
      setMsfSessions(prev => parsed.length > 0 ? parsed : prev);
    } catch { /* ignore */ } finally {
      msfLoadingRef.current = false;
      setMsfSessionsLoading(false);
    }
  };

  const handlePostExRun = async (cmd: string, label: string) => {
    if (postRunningRef.current) return;
    postRunningRef.current = true;
    setPostLoading(true);
    setPostRunning(label);
    try {
      // If not currently in an interactive session, enter the active one first.
      if (interactedSessionRef.current === null && activeMsfSession !== null) {
        const isMeter = activeMsfSession.type.startsWith('meterpreter');
        await sendShellCmd(`sessions -i ${activeMsfSession.id}`);
        interactedSessionRef.current = { id: activeMsfSession.id, isMeterpreter: isMeter };
      }
      const res = await axios.post(
        `/api/sessions/${sessionId}/shell`,
        { command: cmd },
        { timeout: 15 * 1000 }
      );
      const output = res.data.output || '(no output)';
      setPostHistory(prev => [...prev, { cmd: label, output }]);
      // Best-effort loot extraction
      axios.post(`/api/sessions/${sessionId}/loot`, { cmd, output }).catch(() => {});
    } catch (err: any) {
      setPostHistory(prev => [...prev, { cmd: label, output: '', error: err.response?.data?.error || err.message }]);
    } finally {
      postRunningRef.current = false;
      setPostLoading(false);
      setPostRunning('');
    }
  };

  const handleCopyModule = (moduleName: string) => {
    navigator.clipboard.writeText(`use ${moduleName}`).then(() => {
      setCopied(moduleName);
      setTimeout(() => setCopied(null), 1500);
    });
  };

  const handleRunModule = async (moduleName: string) => {
    if (runModuleRef.current) return;
    runModuleRef.current = true;
    try {
      const netRes = await axios.get('/api/network');
      const networks: string[] = netRes.data.networks || [];
      const lhost = networks.length > 0 ? networks[0].split('/')[0] : '';
      const cmds = [
        `use ${moduleName}`,
        lhost ? `set LHOST ${lhost}` : '',
        session?.target_host ? `set RHOSTS ${session.target_host}` : '',
        'set VERBOSE true',
        'options',
      ].filter(Boolean);
      for (const c of cmds) await sendShellCmd(c);
    } catch { /* best-effort */ }
    finally { runModuleRef.current = false; }
  };

  // Derived OS values used across panels
  const osFamily = (osInfo?.family || '').toLowerCase() as 'linux' | 'windows' | '';
  const osBadge = osInfo
    ? `${osInfo.family || osInfo.name}${osInfo.os_gen ? ` ${osInfo.os_gen}` : ''}${osInfo.accuracy < 90 ? ' ~' : ''}`
    : null;

  // Determine active session type from the most recently opened MSF session
  const activeMsfSession = msfSessions.length > 0 ? msfSessions[msfSessions.length - 1] : null;
  const activeSessionType: 'meterpreter' | 'shell' | 'any' = activeMsfSession
    ? (activeMsfSession.type.startsWith('meterpreter') ? 'meterpreter' : 'shell')
    : 'any';

  // Filter quick command groups by session type and OS
  const visibleQuickGroups = POST_EX_QUICK.filter(g => {
    const typeMatch = activeSessionType === 'any' || g.sessionType === 'any' || g.sessionType === activeSessionType;
    const osMatch   = osFamily === '' || g.platform === 'any' || g.platform === osFamily;
    return typeMatch && osMatch;
  });

  // Filter and group recommended modules
  const visibleModules = POST_EX_MODULES.filter(m => {
    const typeMatch = activeSessionType === 'any' || m.sessionType === 'any' || m.sessionType === activeSessionType;
    const osMatch   = osFamily === '' || m.platform === 'any' || m.platform === osFamily;
    return typeMatch && osMatch;
  });
  const modulesByCategory = CATEGORY_ORDER.reduce((acc, cat) => {
    const mods = visibleModules.filter(m => m.category === cat);
    if (mods.length > 0) acc.push({ category: cat, modules: mods });
    return acc;
  }, [] as { category: string; modules: PostExModule[] }[]);

  return (
    <div className="session-detail">
      <header className="sd-header">
        <div className="sd-header-left">
          <Link to={session?.project_id ? `/project/${session.project_id}` : '/'} className="sd-back">← Overview</Link>
          {session ? (
            <div className="sd-title">
              <span className={`status-dot ${session.is_running ? 'running' : 'idle'}`} />
              <span className="sd-name">{session.session_name}</span>
              <span className="sd-host">{session.target_host}</span>
            </div>
          ) : (
            <span className="sd-loading">Loading session…</span>
          )}
        </div>
        <div className="sd-header-right">
          {localIfaces.length > 0 && (
            <div className="header-ifaces">
              {localIfaces.map(iface => (
                <span key={iface.cidr} className="header-iface-tag">
                  <span className="header-iface-name">{iface.name}</span>
                  {iface.ip}
                </span>
              ))}
            </div>
          )}
          <button className="logout-btn" onClick={onLogout}>Logout</button>
        </div>
      </header>

      <div className="sd-body">
        <aside className="sd-sidebar">
          <h2>Actions</h2>
          <nav className="action-nav">
            {ACTIONS.map(action => (
              <button
                key={action.id}
                className={`action-item${activeAction === action.id ? ' active' : ''}`}
                onClick={() => {
                  if (action.id === 6) {
                    window.open(`/report/${sessionId}`, '_blank');
                  } else {
                    setActiveAction(activeAction === action.id ? null : action.id);
                  }
                }}
              >
                {action.label}
              </button>
            ))}
          </nav>
        </aside>

        <main className="sd-main">
          <div className="sd-console-wrap">
            {sessionId
              ? <Console sessionId={sessionId} onSessionOpened={loadMsfSessions} />
              : <div className="sd-no-session">Invalid session ID</div>
            }
          </div>

          {/* ── Vuln scan panel ── */}
          {activeAction === 1 && (
            <div className="action-panel">
              <div className="action-panel-header">
                <span className="action-panel-title">
                  Vulnerability Scan
                  {session && <span className="action-panel-target"> — {session.target_host}</span>}
                  {osBadge && <span className="os-badge">{osBadge}</span>}
                </span>
                <button className="btn-run-scan" onClick={handleVulnScan} disabled={vulnLoading}>
                  {vulnLoading ? <><span className="btn-spinner" /> Scanning…</> : 'Run Scan'}
                </button>
              </div>
              <pre className="action-panel-output" ref={vulnOutputRef}>
                {vulnError
                  ? <span className="output-error">{vulnError}</span>
                  : !vulnOutput && !vulnLoading
                    ? <span className="output-hint">
                        Click Run Scan to start{'\n'}nmap -v -sV -O --osscan-guess --script=vuln,vulners -oX &lt;ip&gt;.xml {session?.target_host}
                      </span>
                    : vulnLoading && !vulnOutput
                      ? <span className="output-hint">Running… this may take several minutes.</span>
                      : vulnOutput
                }
              </pre>
            </div>
          )}

          {/* ── Enumeration panel ── */}
          {activeAction === 2 && (
            <div className="action-panel">
              <div className="action-panel-header">
                <span className="action-panel-title">
                  Enumeration
                  {enumTarget && <span className="action-panel-target"> — {enumTarget}</span>}
                  {osBadge && <span className="os-badge">{osBadge}</span>}
                </span>
                <button className="btn-run-scan" onClick={handleEnumerate} disabled={enumLoading}>
                  {enumLoading ? <><span className="btn-spinner" /> Enumerating…</> : 'Enumerate'}
                </button>
              </div>

              {/* OS filter context bar */}
              <div className="enum-os-context">
                {osInfo ? (
                  <span className="enum-os-filter-active">
                    Modules filtered for: <strong>{osInfo.family || osInfo.name}{osInfo.os_gen ? ` ${osInfo.os_gen}` : ''}</strong>
                    {osInfo.accuracy < 90 && <span className="enum-os-approx"> (approximate)</span>}
                  </span>
                ) : (
                  <span className="enum-os-filter-none">
                    OS not detected — showing modules for all platforms. Run a Vulnerability Scan to enable OS filtering.
                  </span>
                )}
              </div>

              {enumError && <div className="output-error" style={{ padding: '8px 0' }}>{enumError}</div>}

              {!enumError && !enumLoading && enumResults.length === 0 && (
                <p className="output-hint">
                  Enumeration is populated automatically after a Vulnerability Scan.{'\n'}
                  Click Enumerate to refresh or run standalone.
                </p>
              )}
              {enumLoading && (
                <p className="output-hint">Searching Metasploit module tree for matching services…</p>
              )}

              {enumResults.length > 0 && (
                <div className="enum-list">
                  {enumResults.map(svc => {
                    const key = `${svc.port}/${svc.protocol}`;
                    const isOpen = expandedEnumKey === key;
                    const hasModules = svc.modules.length > 0;
                    return (
                      <div key={key} className="enum-service">
                        <div
                          className={`enum-service-header${hasModules ? ' enum-service-clickable' : ''}`}
                          onClick={() => {
                            if (!hasModules) return;
                            setExpandedEnumKey(isOpen ? null : key);
                          }}
                        >
                          <span className={`enum-expand-icon${!hasModules ? ' enum-expand-hidden' : ''}`}>
                            {isOpen ? '▼' : '▶'}
                          </span>
                          <code className="enum-port">{svc.port}/{svc.protocol}</code>
                          {svc.state === 'filtered' && <span className="enum-filtered">filtered</span>}
                          <span className="enum-service-name">{svc.product || svc.name}</span>
                          {svc.version && <span className="enum-version">{svc.version}</span>}
                          <span className={`enum-module-count ${!hasModules ? 'cve-no-module' : ''}`}>
                            {hasModules
                              ? `${svc.modules.length} module${svc.modules.length !== 1 ? 's' : ''}`
                              : 'no modules'}
                          </span>
                        </div>
                        {hasModules && isOpen && (
                          <ul className="module-list">
                            {svc.modules.map(mod => {
                              const modOS = mod.includes('/windows/') ? 'windows'
                                : mod.includes('/linux/') || mod.includes('/unix/') ? 'linux'
                                : mod.includes('/multi/') ? 'multi'
                                : mod.startsWith('auxiliary/') ? 'scanner'
                                : null;
                              return (
                              <li key={mod} className="module-item">
                                <div className="module-item-left">
                                  {modOS && (
                                    <span className={`enum-mod-os-pill enum-mod-os-${modOS}`}>
                                      {modOS}
                                    </span>
                                  )}
                                  <span className="module-name">{mod}</span>
                                </div>
                                <div className="module-actions">
                                  <button type="button" className="btn-copy-module"
                                    title="Copy 'use <module>' to clipboard"
                                    onClick={e => { e.stopPropagation(); handleCopyModule(mod); }}>
                                    {copied === mod ? '✓ Copied' : 'Copy use'}
                                  </button>
                                  <button type="button" className="btn-run-module"
                                    title="Send to console and set options"
                                    onClick={e => { e.stopPropagation(); handleRunModule(mod); }}>
                                    Run →
                                  </button>
                                </div>
                              </li>
                              );
                            })}
                          </ul>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {/* ── CVE analysis panel ── */}
          {activeAction === 3 && (
            <div className="action-panel">
              <div className="action-panel-header">
                <span className="action-panel-title">
                  CVE Analysis
                  {cveTarget && <span className="action-panel-target"> — {cveTarget}</span>}
                  {osBadge && <span className="os-badge">{osBadge}</span>}
                </span>
                <button className="btn-run-scan" onClick={handleCVEAnalysis} disabled={cveLoading}>
                  {cveLoading ? <><span className="btn-spinner" /> Analysing…</> : 'Analyse'}
                </button>
              </div>

              <div className="cve-body">
                {cveError && <div className="output-error cve-error">{cveError}</div>}

                {!cveError && !cveLoading && cveResults.length === 0 && !cveAnalysed && (
                  <p className="output-hint">
                    {vulnOutput
                      ? 'Analysing scan results…'
                      : 'Run a Vulnerability Scan first, then open this panel.'}
                  </p>
                )}
                {!cveError && !cveLoading && cveResults.length === 0 && cveAnalysed && (
                  <p className="output-hint cve-no-results">No CVE's Found</p>
                )}
                {cveLoading && (
                  <p className="output-hint">Parsing scan results and searching Metasploit module tree…</p>
                )}

                {cveResults.length > 0 && (
                  <div className="cve-list">
                    {cveResults.map(item => (
                      <div key={item.cve} className="cve-item">
                        <div className="cve-id-row">
                          <span className="cve-id-text">{item.cve}</span>
                          {item.metricsLoading
                            ? <span className="cve-metrics-loading"><span className="btn-spinner" /> fetching NVD…</span>
                            : item.metrics?.severity
                              ? <span className={`cve-severity cve-severity-${item.metrics.severity.toLowerCase()}`}>
                                  {item.metrics.severity}{item.metrics.baseScore > 0 ? ` ${item.metrics.baseScore.toFixed(1)}` : ''}
                                  {item.metrics.cvssVersion && <span className="cve-cvss-ver"> CVSSv{item.metrics.cvssVersion}</span>}
                                </span>
                              : null
                          }
                          <span className={`cve-module-count ${item.modules.length === 0 ? 'cve-no-module' : ''}`}>
                            {item.modules.length > 0
                              ? `${item.modules.length} module${item.modules.length !== 1 ? 's' : ''}`
                              : 'no modules'}
                          </span>
                        </div>

                        {item.targets && item.targets.length > 1 && (
                          <div className="cve-targets">
                            {item.targets.map(t => (
                              <span key={t} className="cve-target-tag">{t}</span>
                            ))}
                          </div>
                        )}

                        {!item.metricsLoading && item.metrics && (
                          <div className="cve-summary">
                            {item.metrics.description && <p className="cve-description">{item.metrics.description}</p>}
                            {item.metrics.vector && <code className="cve-vector">{item.metrics.vector}</code>}
                          </div>
                        )}

                        {item.modules.length > 0 && (
                          <ul className="module-list">
                            {item.modules.map(mod => (
                              <li key={mod} className="module-item">
                                <span className="module-name">{mod}</span>
                                <div className="module-actions">
                                  <button className="btn-copy-module" title="Copy 'use <module>' to clipboard"
                                    onClick={() => handleCopyModule(mod)}>
                                    {copied === mod ? '✓ Copied' : 'Copy use'}
                                  </button>
                                  <button className="btn-run-module" title="Send to console and set options"
                                    onClick={() => handleRunModule(mod)}>
                                    Run →
                                  </button>
                                </div>
                              </li>
                            ))}
                          </ul>
                        )}

                        {item.modules.length === 0 && !item.metricsLoading && (
                          <div className="github-section">
                            <div className="github-section-header">
                              <span className="github-section-title">GitHub Exploit Repos</span>
                              {item.githubLoading && (
                                <span className="cve-metrics-loading"><span className="btn-spinner" /> searching…</span>
                              )}
                            </div>
                            {item.githubError && <p className="github-error">{item.githubError}</p>}
                            {!item.githubLoading && !item.githubError && item.githubRepos !== undefined && (
                              item.githubRepos && item.githubRepos.length > 0 ? (
                                <ul className="github-repo-list">
                                  {item.githubRepos.map(repo => (
                                    <li key={repo.full_name} className="github-repo-item">
                                      <div className="github-repo-top">
                                        <a className="github-repo-name" href={repo.html_url}
                                          target="_blank" rel="noopener noreferrer">
                                          {repo.full_name}
                                        </a>
                                        <span className="github-repo-stars">★ {repo.stargazers_count.toLocaleString()}</span>
                                      </div>
                                      {repo.description && <p className="github-repo-desc">{repo.description}</p>}
                                      <span className="github-repo-updated">
                                        updated {new Date(repo.updated_at).toLocaleDateString()}
                                      </span>
                                    </li>
                                  ))}
                                </ul>
                              ) : (
                                <p className="github-no-results">No public exploit repos found for this CVE.</p>
                              )
                            )}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ── Shells panel ── */}
          {activeAction === 4 && (
            <div className="action-panel">
              <div className="action-panel-header">
                <span className="action-panel-title">
                  Shells
                  {session && <span className="action-panel-target"> — {session.target_host}</span>}
                  {osBadge && <span className="os-badge">{osBadge}</span>}
                </span>
                <div className="shells-header-actions">
                  <button className="btn-background-session"
                    onClick={async () => {
                      await ensureMsfPrompt();
                      loadMsfSessions();
                    }}
                    title="Background the currently active session (returns to msf prompt)">
                    ⏸ Background
                  </button>
                  <button className="btn-run-scan" onClick={loadMsfSessions} disabled={msfSessionsLoading}>
                    {msfSessionsLoading ? <><span className="btn-spinner" /> Refreshing…</> : 'Refresh'}
                  </button>
                </div>
              </div>
              <div className="msf-sessions-body">
                {msfSessionsLoading && msfSessions.length === 0 && (
                  <p className="output-hint">Loading sessions…</p>
                )}
                {!msfSessionsLoading && msfSessions.length === 0 && (
                  <p className="output-hint">
                    No active MSF sessions.{'\n'}
                    Run a module from Enumeration or CVE Analysis to create a session.{'\n'}
                    The Console tab must be open first.
                  </p>
                )}
                {msfSessions.length > 0 && (
                  <div className="msf-session-list">
                    {msfSessions.map(s => {
                      const isMeterpreter = s.type.startsWith('meterpreter');
                      const arch = s.type.replace(/^(meterpreter|shell)\s*/, '');
                      return (
                        <div key={s.id} className="msf-session-card">
                          <div className="msf-session-header">
                            <span className="msf-session-id">Session {s.id}</span>
                            <span className={`msf-session-type-badge ${isMeterpreter ? 'badge-meterpreter' : 'badge-shell'}`}>
                              {isMeterpreter ? 'Meterpreter' : 'Shell'}
                            </span>
                            {arch && <span className="msf-session-arch">{arch}</span>}
                          </div>
                          {s.info       && <div className="msf-session-info">{s.info}</div>}
                          {s.connection && <div className="msf-session-conn">{s.connection}</div>}
                          <div className="msf-session-actions">
                            <button className={isMeterpreter ? 'btn-interact-meterpreter' : 'btn-run-scan'}
                              onClick={() => {
                                interactedSessionRef.current = { id: s.id, isMeterpreter };
                                sendShellCmd(`sessions -i ${s.id}`);
                              }}>
                              Interact
                            </button>
                            {!isMeterpreter && (
                              <button className="btn-upgrade-session"
                                disabled={upgradedSessions.has(s.id)}
                                onClick={async () => {
                                  if (upgradingRef.current.has(s.id)) return;
                                  upgradingRef.current.add(s.id);
                                  setUpgradedSessions(prev => new Set(prev).add(s.id));
                                  // Must be at msf> prompt — background any active interactive session first
                                  await ensureMsfPrompt();
                                  await sendShellCmd('use post/multi/manage/shell_to_meterpreter');
                                  await sendShellCmd(`set SESSION ${s.id}`);
                                  await sendShellCmd('set DB_ALL_PASS true');
                                  await sendShellCmd('set DB_ALL_CREDS true');
                                  await sendShellCmd('set DB_ALL_USERS true');
                                  await sendShellCmd('set CreateSession true');
                                  await sendShellCmd('run');
                                }}
                                title="Upgrade shell to Meterpreter">
                                ↑ Upgrade to Meterpreter
                              </button>
                            )}
                            <button className="btn-kill-session"
                              onClick={async () => {
                                await ensureMsfPrompt();
                                await sendShellCmd(`sessions -k ${s.id}`);
                                loadMsfSessions();
                              }}
                              title="Kill this session">
                              ✕ Kill
                            </button>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ── Post Exploitation panel ── */}
          {activeAction === 5 && (
            <div className="action-panel">
              <div className="action-panel-header">
                <span className="action-panel-title">
                  Post Exploitation
                  {session && <span className="action-panel-target"> — {session.target_host}</span>}
                  {osBadge && <span className="os-badge">{osBadge}</span>}
                </span>
                {postLoading && <span className="cve-metrics-loading"><span className="btn-spinner" /> {postRunning}…</span>}
              </div>

              <div className="post-ex-body">

                {/* ── Context bar ── */}
                <div className="post-ex-context">
                  <div className="post-ex-context-row">
                    <span className="post-ex-context-label">Session type:</span>
                    {activeMsfSession ? (
                      <span className={`msf-session-type-badge ${activeSessionType === 'meterpreter' ? 'badge-meterpreter' : 'badge-shell'}`}>
                        {activeSessionType === 'meterpreter' ? 'Meterpreter' : 'Shell'}
                      </span>
                    ) : (
                      <span className="post-ex-no-session">No active MSF session — open Shells tab and create a session first</span>
                    )}
                    {activeMsfSession && (
                      <span className="post-ex-session-info">{activeMsfSession.info}</span>
                    )}
                  </div>
                </div>

                {/* ── Quick command buttons ── */}
                <div className="post-ex-section-title">Quick Commands</div>
                {visibleQuickGroups.length === 0 ? (
                  <p className="output-hint">No quick commands for this session / OS combination.</p>
                ) : (
                  <div className="post-ex-quick-groups">
                    {visibleQuickGroups.map((group, gi) => (
                      <div key={`${group.label}-${gi}`} className="post-ex-quick-group">
                        <div className="post-ex-quick-label">
                          {group.label}
                          {group.sessionType !== 'any' && (
                            <span className={`post-ex-type-pill ${group.sessionType === 'meterpreter' ? 'pill-meterpreter' : 'pill-shell'}`}>
                              {group.sessionType}
                            </span>
                          )}
                          {group.platform !== 'any' && (
                            <span className="post-ex-os-pill">{group.platform}</span>
                          )}
                        </div>
                        <div className="post-ex-quick-buttons">
                          {group.commands.map(c => (
                            <button key={c.cmd} type="button" className="btn-post-quick"
                              onClick={e => { e.stopPropagation(); handlePostExRun(c.cmd, c.label); }}
                              disabled={postLoading} title={c.cmd}>
                              {c.label}
                            </button>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                {/* ── Recommended modules ── */}
                <div className="post-ex-section-title">Recommended Modules</div>
                {modulesByCategory.length === 0 ? (
                  <p className="output-hint">No modules for this session / OS combination.</p>
                ) : (
                  <div className="post-ex-modules-list">
                    {modulesByCategory.map(({ category, modules }) => (
                      <div key={category} className="post-ex-module-category">
                        <div className="post-ex-module-cat-header"
                          style={{ borderLeftColor: CATEGORY_COLOR[category] }}>
                          <span className="post-ex-module-cat-name"
                            style={{ color: CATEGORY_COLOR[category] }}>
                            {category}
                          </span>
                        </div>
                        {modules.map(m => (
                          <div key={m.module} className="post-ex-module-item">
                            <div className="post-ex-module-top">
                              <code className="post-ex-module-name">{m.module}</code>
                              <div className="post-ex-module-actions">
                                <button className="btn-copy-module"
                                  title="Copy 'use <module>' to clipboard"
                                  onClick={() => handleCopyModule(m.module)}>
                                  {copied === m.module ? '✓' : 'Copy'}
                                </button>
                                <button className="btn-run-module"
                                  title="Send to console and set options"
                                  onClick={() => handleRunModule(m.module)}>
                                  Run →
                                </button>
                              </div>
                            </div>
                            <p className="post-ex-module-desc">{m.description}</p>
                          </div>
                        ))}
                      </div>
                    ))}
                  </div>
                )}

                {/* ── Output ── */}
                {postHistory.length > 0 && (
                  <div className="post-ex-output">
                    <div className="post-ex-section-title">Output</div>
                    {postHistory.map((entry, i) => (
                      <div key={i} className="shell-entry">
                        <div className="shell-cmd">&gt; {entry.cmd}</div>
                        {entry.error
                          ? <div className="output-error shell-result">{entry.error}</div>
                          : <pre className="shell-result">{entry.output}</pre>}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

        </main>
      </div>
    </div>
  );
}
