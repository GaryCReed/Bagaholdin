import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { useParams } from 'react-router-dom';
import axios from 'axios';
import './TopographyPage.css';

// ── Types ──────────────────────────────────────────────────────────────────

interface Project    { id: number; name: string; network_range: string }
interface ProjHost   { ip: string; hostname?: string; online: boolean }
interface SessionRef { id: number; session_name: string; target_host: string }
interface CVEMetrics { baseScore: number; severity: string }
interface CVEResult  { cve: string; modules: string[]; metrics?: CVEMetrics | null }
interface Service    { port: number; protocol: string; state: string; name: string }
interface OSInfo     { name: string; family: string; os_gen: string; accuracy: number }

interface HostNode {
  ip: string;
  hostname?: string;
  online: boolean;
  sessionId?: number;
  sessionName?: string;
  services: Service[];
  osInfo: OSInfo | null;
  cveResults: CVEResult[];
  worstSev: string;
}

interface Pos { x: number; y: number }

// ── Helpers ────────────────────────────────────────────────────────────────

const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const SEV_COLOR: Record<string, string> = {
  CRITICAL: '#c62828', HIGH: '#e64a19', MEDIUM: '#f9a825', LOW: '#1565c0',
};

function worstSev(cves: CVEResult[]): string {
  for (const s of SEV_ORDER) {
    if (cves.some(r => r.metrics?.severity === s)) return s;
  }
  return 'NONE';
}

function nodeColor(node: HostNode): string {
  if (!node.online && !node.sessionId) return '#546e7a';
  if (node.cveResults.length === 0) return node.sessionId ? '#2e7d32' : '#37474f';
  return SEV_COLOR[node.worstSev] || '#546e7a';
}

function gatewayIP(range: string): string {
  const [base] = range.split('/');
  const parts = base.split('.');
  if (parts.length === 4) { parts[3] = '1'; return parts.join('.'); }
  return '';
}

// ── Layout constants ────────────────────────────────────────────────────────

const NW = 176;
const NH = 118;
const CG = 28;
const RG = 80;
const GW = 200;
const GH = 84;
const PAD_TOP  = 36;
const HOST_Y   = PAD_TOP + GH + 108;
const MIN_W    = 600;
const SIDE_PAD = 60;

// ── Component ──────────────────────────────────────────────────────────────

export default function TopographyPage() {
  const { id } = useParams<{ id: string }>();
  const projectId = parseInt(id || '0', 10);

  const [project, setProject] = useState<Project | null>(null);
  const [nodes,   setNodes]   = useState<HostNode[]>([]);
  const [pending, setPending] = useState(1);
  const [loadErr, setLoadErr] = useState('');

  // Drag state
  const [dragPos, setDragPos] = useState<Map<string, Pos>>(new Map());
  const dragRef = useRef<{
    ip: string; startMX: number; startMY: number; startNX: number; startNY: number;
  } | null>(null);
  const [dragging, setDragging] = useState<string | null>(null);

  // ── Data loading ────────────────────────────────────────────────────────────

  const fetchSessionData = useCallback(async (s: SessionRef) => {
    const [scanR, cveR] = await Promise.allSettled([
      axios.get(`/api/sessions/${s.id}/vuln-scan`),
      axios.get(`/api/sessions/${s.id}/cve-results`),
    ]);
    const services: Service[] = scanR.status === 'fulfilled' && scanR.value.data.status === 'done'
      ? scanR.value.data.services || [] : [];
    const osInfo: OSInfo | null = scanR.status === 'fulfilled' && scanR.value.data.status === 'done'
      ? scanR.value.data.os_info || null : null;

    let cveResults: CVEResult[] = [];
    if (cveR.status === 'fulfilled' && cveR.value.data.results?.length > 0) {
      cveResults = cveR.value.data.results;
    } else {
      try {
        const ls = localStorage.getItem(`session-${s.id}-cve`);
        if (ls) { const { results } = JSON.parse(ls); if (results?.length > 0) cveResults = results; }
      } catch { /* ignore */ }
    }
    return { services, osInfo, cveResults };
  }, []);

  useEffect(() => {
    if (!projectId) return;
    Promise.all([
      axios.get(`/api/projects/${projectId}`),
      axios.get(`/api/projects/${projectId}/hosts`),
      axios.get(`/api/projects/${projectId}/sessions`),
    ]).then(async ([projR, hostsR, sessR]) => {
      setProject(projR.data.project);
      const phosts: ProjHost[]     = hostsR.data.hosts    || [];
      const sessions: SessionRef[] = sessR.data.sessions  || [];

      const sessionByIP = new Map<string, SessionRef>(sessions.map(s => [s.target_host, s]));

      const gwIP = projR.data.project?.network_range
        ? gatewayIP(projR.data.project.network_range) : '';

      const seen   = new Set(phosts.map(h => h.ip));
      const merged = phosts.filter(h => h.ip !== gwIP) as ProjHost[];
      for (const s of sessions) {
        if (!seen.has(s.target_host) && s.target_host !== gwIP)
          merged.push({ ip: s.target_host, online: true });
      }

      if (merged.length === 0) { setNodes([]); setPending(0); return; }
      setPending(sessions.length || 1);

      const nodeMap = new Map<string, HostNode>();
      for (const h of merged) {
        const sess = sessionByIP.get(h.ip);
        nodeMap.set(h.ip, {
          ip: h.ip, hostname: h.hostname, online: h.online,
          sessionId: sess?.id, sessionName: sess?.session_name,
          services: [], osInfo: null, cveResults: [], worstSev: 'NONE',
        });
      }

      await Promise.all(sessions.map(async s => {
        const data = await fetchSessionData(s);
        const node = nodeMap.get(s.target_host);
        if (node) {
          node.services   = data.services;
          node.osInfo     = data.osInfo;
          node.cveResults = data.cveResults;
          node.worstSev   = worstSev(data.cveResults);
        }
        setPending(p => Math.max(0, p - 1));
      }));

      const sevIdx = (n: HostNode) => { const i = SEV_ORDER.indexOf(n.worstSev); return i < 0 ? 99 : i; };
      const sorted = [...nodeMap.values()].sort((a, b) => {
        const sd = sevIdx(a) - sevIdx(b); if (sd !== 0) return sd;
        if (a.online !== b.online) return a.online ? -1 : 1;
        return a.ip.localeCompare(b.ip, undefined, { numeric: true });
      });

      setNodes(sorted);
      setDragPos(new Map()); // reset overrides when nodes reload
      setPending(0);
    }).catch(err => {
      setLoadErr(err.response?.data?.error || err.message || 'Failed to load topology');
      setPending(0);
    });
  }, [projectId, fetchSessionData]);

  // ── Drag handlers ──────────────────────────────────────────────────────────

  // Register global move/up handlers once — they read/write dragRef which is always current.
  useEffect(() => {
    const onMove = (e: MouseEvent) => {
      if (!dragRef.current) return;
      const { ip, startMX, startMY, startNX, startNY } = dragRef.current;
      setDragPos(prev => {
        const next = new Map(prev);
        next.set(ip, { x: startNX + e.clientX - startMX, y: startNY + e.clientY - startMY });
        return next;
      });
    };
    const onUp = () => {
      dragRef.current = null;
      setDragging(null);
    };
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
    return () => {
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
    };
  }, []);

  const handleNodeMouseDown = (e: React.MouseEvent, ip: string, curPos: Pos) => {
    e.preventDefault();
    dragRef.current = { ip, startMX: e.clientX, startMY: e.clientY, startNX: curPos.x, startNY: curPos.y };
    setDragging(ip);
  };

  // ── Layout ────────────────────────────────────────────────────────────────

  const layout = useMemo(() => {
    const n    = nodes.length;
    const cols = n <= 3 ? n : Math.min(6, Math.ceil(Math.sqrt(n * 1.6)));
    const rows = Math.ceil(Math.max(1, n) / Math.max(1, cols));
    const gridW = cols * NW + Math.max(0, cols - 1) * CG;
    const totalW = Math.max(MIN_W, gridW + SIDE_PAD * 2);
    const cx = totalW / 2;
    const gwX = cx - GW / 2;
    const gwCY = PAD_TOP + GH / 2;
    const hostStartX = cx - gridW / 2;
    const baseH = HOST_Y + rows * NH + Math.max(0, rows - 1) * RG + 60;

    const initPos = new Map<string, Pos>(nodes.map((node, i) => {
      const col = i % cols;
      const row = Math.floor(i / cols);
      return [node.ip, {
        x: hostStartX + col * (NW + CG),
        y: HOST_Y + row * (NH + RG),
      }];
    }));

    return { cols, rows, gridW, totalW, baseH, cx, gwX, gwCY, hostStartX, initPos };
  }, [nodes]);

  // Effective position per node: drag override first, then initial grid position
  const effPos = useMemo<Map<string, Pos>>(() => {
    return new Map(nodes.map(n => [
      n.ip,
      dragPos.get(n.ip) ?? layout.initPos.get(n.ip) ?? { x: 0, y: 0 },
    ]));
  }, [nodes, dragPos, layout.initPos]);

  // Canvas dimensions: grow to contain any dragged nodes
  const canvasW = useMemo(() => {
    let w = layout.totalW;
    for (const p of effPos.values()) w = Math.max(w, p.x + NW + SIDE_PAD);
    return w;
  }, [effPos, layout.totalW]);

  const canvasH = useMemo(() => {
    let h = layout.baseH;
    for (const p of effPos.values()) h = Math.max(h, p.y + NH + 60);
    return h;
  }, [effPos, layout.baseH]);

  // ── Guards ─────────────────────────────────────────────────────────────────

  if (pending > 0 && nodes.length === 0) {
    return <div className="topo-loading">Building network topology…</div>;
  }
  if (loadErr) return <div className="topo-loading topo-err">{loadErr}</div>;

  const gw = project?.network_range ? gatewayIP(project.network_range) : '';
  const { cx, gwX, gwCY, totalW } = layout;

  return (
    <div className="topo-wrapper" style={{ userSelect: dragging ? 'none' : undefined }}>

      {/* ── Toolbar ── */}
      <div className="topo-toolbar no-print">
        <div className="topo-toolbar-left">
          <span className="topo-brand">Bagaholdin</span>
          <span className="topo-sep">|</span>
          <span className="topo-title">Network Topology — {project?.name}</span>
          {pending > 0 && <span className="topo-loading-hint">Loading {pending} host{pending !== 1 ? 's' : ''}…</span>}
        </div>
        <div className="topo-legend">
          {[
            ['Critical', '#c62828'], ['High', '#e64a19'], ['Medium', '#f9a825'],
            ['Low', '#1565c0'], ['Clean', '#2e7d32'], ['Offline', '#546e7a'],
          ].map(([label, color]) => (
            <span key={label} className="topo-legend-item">
              <span className="topo-legend-dot" style={{ background: color }} />
              {label}
            </span>
          ))}
        </div>
        <button className="topo-btn-print" onClick={() => window.print()}>
          Print / Save as PDF
        </button>
      </div>

      {/* ── Canvas ── */}
      <div className="topo-scroll">
        <div className="topo-canvas" style={{ width: canvasW, minHeight: canvasH, position: 'relative' }}>

          {/* ── SVG connector lines — always on top of gateway, below nodes ── */}
          <svg
            width={canvasW}
            height={canvasH}
            style={{ position: 'absolute', top: 0, left: 0, pointerEvents: 'none' }}
          >
            {nodes.map(node => {
              const pos = effPos.get(node.ip)!;
              const col = nodeColor(node);
              const nodeCX = pos.x + NW / 2;
              const nodeTY = pos.y;
              const midY  = (gwCY + GH / 2 + nodeTY) / 2;
              return (
                <path
                  key={node.ip}
                  d={`M ${cx} ${gwCY + GH / 2} C ${cx} ${midY}, ${nodeCX} ${midY}, ${nodeCX} ${nodeTY}`}
                  fill="none"
                  stroke={col}
                  strokeWidth={node.sessionId ? 2 : 1.5}
                  strokeDasharray={node.sessionId ? undefined : '6 5'}
                  opacity={0.5}
                />
              );
            })}
          </svg>

          {/* ── Gateway node ── */}
          <div className="topo-node topo-gw" style={{ left: gwX, top: PAD_TOP, width: GW, height: GH }}>
            <div className="topo-gw-eyebrow">Gateway / Router</div>
            <div className="topo-gw-ip">{gw || '—'}</div>
            {project?.network_range && (
              <div className="topo-gw-range">{project.network_range}</div>
            )}
          </div>

          {/* ── Host nodes ── */}
          {nodes.map(node => {
            const pos  = effPos.get(node.ip)!;
            const col  = nodeColor(node);
            const open = node.services.filter(s => s.state === 'open');
            const sev  = node.worstSev !== 'NONE' ? node.worstSev : null;
            const isDragging = dragging === node.ip;
            return (
              <div
                key={node.ip}
                className={[
                  'topo-node', 'topo-host',
                  node.sessionId   ? 'topo-active'  : '',
                  !node.online && !node.sessionId ? 'topo-offline' : '',
                  isDragging       ? 'topo-dragging' : '',
                ].join(' ').trim()}
                style={{
                  left: pos.x, top: pos.y, width: NW, height: NH,
                  cursor: isDragging ? 'grabbing' : 'grab',
                  zIndex: isDragging ? 100 : 1,
                }}
                onMouseDown={e => handleNodeMouseDown(e, node.ip, pos)}
              >
                <div className="topo-host-bar" style={{ background: col }} />
                <div className="topo-host-body">
                  <div className="topo-host-ip">{node.ip}</div>
                  {node.hostname   && <div className="topo-host-hostname">{node.hostname}</div>}
                  {node.sessionName && <div className="topo-host-session">{node.sessionName}</div>}
                  {node.osInfo && (
                    <div className="topo-host-os">
                      {node.osInfo.name}{node.osInfo.os_gen ? ` ${node.osInfo.os_gen}` : ''}
                    </div>
                  )}
                  <div className="topo-host-footer">
                    {open.length > 0 && (
                      <span className="topo-badge topo-port-badge" style={{ color: col, borderColor: col }}>
                        {open.length}p
                      </span>
                    )}
                    {sev && (
                      <span className="topo-badge topo-sev-badge" style={{ background: col }}>
                        {node.cveResults.length} CVE
                      </span>
                    )}
                    {!node.sessionId && !node.online && (
                      <span className="topo-badge topo-offline-badge">offline</span>
                    )}
                  </div>
                </div>
              </div>
            );
          })}

          {nodes.length === 0 && (
            <div className="topo-empty" style={{ top: HOST_Y, left: 0, width: totalW }}>
              No hosts discovered yet. Run a Network Scan on the project.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
