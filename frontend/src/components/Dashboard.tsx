import { useState, useEffect } from 'react';
import axios from 'axios';
import { Link } from 'react-router-dom';
import './Dashboard.css';

interface DashboardProps {
  onLogout: () => void;
  project: { id: number; name: string; network_range: string };
}

interface Session {
  id: number;
  session_name: string;
  target_host: string;
  is_running: boolean;
}

interface ScanHost {
  id: number;
  ip: string;
  hostname?: string;
  online: boolean;
  last_seen: string;
  first_seen: string;
}

interface LocalIface { name: string; cidr: string; ip: string }

interface ServicePort {
  port: number;
  protocol: string; // 'tcp' | 'udp'
  state: string;    // 'open' | 'filtered'
  name: string;
}

function getSessionPorts(sessionId: number): ServicePort[] {
  try {
    const raw = localStorage.getItem(`session-${sessionId}-enum`);
    if (!raw) return [];
    const data = JSON.parse(raw);
    return (data.services as ServicePort[]) || [];
  } catch {
    return [];
  }
}

export default function Dashboard({ onLogout, project }: DashboardProps) {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [showNewForm, setShowNewForm] = useState(false);
  const [sessionName, setSessionName] = useState('');
  const [targetHost, setTargetHost] = useState('');
  const [createError, setCreateError] = useState('');
  const [localIfaces, setLocalIfaces] = useState<LocalIface[]>([]);

  const [scanHosts, setScanHosts] = useState<ScanHost[]>([]);
  const [scanCidr, setScanCidr] = useState('');
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState('');
  const [addingHost, setAddingHost] = useState<string | null>(null);
  const [selectedHosts, setSelectedHosts] = useState<Set<string>>(new Set());
  const [addingMultiple, setAddingMultiple] = useState(false);


  useEffect(() => {
    loadSessions();
    loadHosts();
    axios.get('/api/network')
      .then(res => setLocalIfaces(res.data.interfaces || []))
      .catch(() => {});
  }, [project.id]);

  const loadSessions = async () => {
    try {
      const res = await axios.get(`/api/projects/${project.id}/sessions`);
      setSessions(res.data.sessions || []);
    } catch {
      // silently ignore
    }
  };

  const loadHosts = async () => {
    try {
      const res = await axios.get(`/api/projects/${project.id}/hosts`);
      setScanHosts(res.data.hosts || []);
    } catch {
      // silently ignore
    }
  };

  const handleCreateSession = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreateError('');
    try {
      await axios.post(`/api/projects/${project.id}/sessions`, {
        session_name: sessionName,
        target_host: targetHost,
      });
      setSessionName('');
      setTargetHost('');
      setShowNewForm(false);
      loadSessions();
    } catch (err: any) {
      setCreateError(err.response?.data?.error || err.message || 'Failed to create session');
    }
  };

  const clearSessionLocalStorage = (id: number) => {
    const keys = ['vuln', 'cve', 'enum', 'os', 'msf-sessions', 'remarks'];
    keys.forEach(k => localStorage.removeItem(`session-${id}-${k}`));
  };

  const handleDeleteSession = async (id: number) => {
    try {
      await axios.delete(`/api/sessions/${id}`);
      clearSessionLocalStorage(id);
      loadSessions();
    } catch {
      // silently ignore
    }
  };

  const handleScan = async () => {
    setScanError('');
    setScanning(true);
    try {
      const res = await axios.post(`/api/projects/${project.id}/scan`, {});
      setScanHosts(res.data.hosts || []);
      setScanCidr(res.data.cidr || '');
    } catch (err: any) {
      setScanError(err.response?.data?.error || err.message || 'Scan failed');
    } finally {
      setScanning(false);
    }
  };

  const handleAddHost = async (host: ScanHost) => {
    if (!host.online) return;
    // Prevent duplicate — check if this IP is already a session in this project
    if (sessions.some(s => s.target_host === host.ip)) return;
    setAddingHost(host.ip);
    try {
      const name = host.hostname || host.ip;
      await axios.post(`/api/projects/${project.id}/sessions`, {
        session_name: name,
        target_host: host.ip,
      });
      loadSessions();
    } catch {
      // silently ignore
    } finally {
      setAddingHost(null);
    }
  };

  const onlineHosts = scanHosts.filter(h => h.online);

  const handleToggleHost = (ip: string) => {
    setSelectedHosts(prev => {
      const next = new Set(prev);
      if (next.has(ip)) next.delete(ip);
      else next.add(ip);
      return next;
    });
  };

  const handleSelectAll = () => {
    if (selectedHosts.size === onlineHosts.length) {
      setSelectedHosts(new Set());
    } else {
      setSelectedHosts(new Set(onlineHosts.map(h => h.ip)));
    }
  };

  const handleAddSelected = async () => {
    if (selectedHosts.size === 0 || addingMultiple) return;
    setAddingMultiple(true);
    const existingIPs = new Set(sessions.map(s => s.target_host));
    await Promise.all(
      onlineHosts
        .filter(h => selectedHosts.has(h.ip) && !existingIPs.has(h.ip))
        .map(h =>
          axios.post(`/api/projects/${project.id}/sessions`, {
            session_name: h.hostname || h.ip,
            target_host: h.ip,
          }).catch(() => {})
        )
    );
    setSelectedHosts(new Set());
    setAddingMultiple(false);
    loadSessions();
  };

  // Use project's network_range if set, otherwise fall back to the first detected local network
  const effectiveRange = project.network_range || localIfaces[0]?.cidr || '';

  return (
    <div className="dashboard">
      <header className="dashboard-header">
        <div className="dashboard-header-left">
          <Link to="/" className="btn-back">← Projects</Link>
          <h1>{project.name}</h1>
          {effectiveRange && (
            <span className="project-range">{effectiveRange}</span>
          )}
        </div>
        <div className="dashboard-header-right">
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
          <button onClick={onLogout} className="logout-btn">Logout</button>
        </div>
      </header>

      <div className="dashboard-body">
        {/* ── Network scanner panel ── */}
        <section className="scanner-panel">
          <div className="panel-heading">
            <h2>Network Scanner</h2>
            <button className="btn-primary" onClick={handleScan} disabled={scanning}>
              {scanning ? 'Scanning...' : 'Scan Network'}
            </button>
          </div>

          {(scanCidr || effectiveRange) && (
            <div className="scan-cidr">
              {scanCidr ? `Last scan: ${scanCidr}` : `Network: ${effectiveRange}`}
            </div>
          )}
          {scanError && <div className="form-error">{scanError}</div>}

          {scanning && (
            <div className="scan-status">
              <span className="scan-spinner" /> Running nmap ping sweep…
            </div>
          )}

          {!scanning && scanHosts.length === 0 && !scanError && (
            <p className="empty-hint">Click Scan Network to discover live hosts.</p>
          )}

          {scanHosts.length > 0 && (
            <>
              {onlineHosts.length > 0 && (
                <div className="host-select-toolbar">
                  <label className="host-select-all">
                    <input
                      type="checkbox"
                      checked={selectedHosts.size === onlineHosts.length}
                      ref={el => {
                        if (el) el.indeterminate =
                          selectedHosts.size > 0 && selectedHosts.size < onlineHosts.length;
                      }}
                      onChange={handleSelectAll}
                    />
                    Select All ({onlineHosts.length})
                  </label>
                  {selectedHosts.size > 0 && (
                    <button
                      className="btn-add-selected"
                      onClick={handleAddSelected}
                      disabled={addingMultiple}
                    >
                      {addingMultiple
                        ? 'Adding…'
                        : `+ Add Selected (${selectedHosts.size})`}
                    </button>
                  )}
                </div>
              )}
              <div className="host-list">
                {scanHosts.map((h) => (
                  <div key={h.ip} className={`host-item${h.online ? '' : ' host-offline'}`}>
                    <label className="host-checkbox">
                      <input
                        type="checkbox"
                        disabled={!h.online}
                        checked={selectedHosts.has(h.ip)}
                        onChange={() => handleToggleHost(h.ip)}
                      />
                    </label>
                    <div className="host-item-info">
                      <div className="host-ip-row">
                        <span className={`host-status-dot ${h.online ? 'online' : 'offline'}`} />
                        <span className="host-ip">{h.ip}</span>
                      </div>
                      {h.hostname && <span className="host-name">{h.hostname}</span>}
                      {!h.online && (
                        <span className="host-last-seen">last seen {h.last_seen}</span>
                      )}
                    </div>
                    <button
                      className="btn-add-host"
                      disabled={!h.online || addingHost === h.ip || sessions.some(s => s.target_host === h.ip)}
                      onClick={() => handleAddHost(h)}
                      title={sessions.some(s => s.target_host === h.ip) ? 'Already added' : h.online ? 'Add as session' : 'Host is offline'}
                    >
                      {addingHost === h.ip ? '…' : sessions.some(s => s.target_host === h.ip) ? '✓ Added' : '+ Add'}
                    </button>
                  </div>
                ))}
              </div>
            </>
          )}
        </section>

        {/* ── Sessions panel ── */}
        <section className="sessions-panel">
          <div className="panel-heading">
            <h2>Sessions</h2>
            <button className="btn-primary" onClick={() => setShowNewForm(!showNewForm)}>
              + New Session
            </button>
          </div>

          {showNewForm && (
            <form onSubmit={handleCreateSession} className="new-session-form">
              <input
                type="text"
                placeholder="Session name"
                value={sessionName}
                onChange={(e) => setSessionName(e.target.value)}
                required
              />
              <input
                type="text"
                placeholder="Target host"
                value={targetHost}
                onChange={(e) => setTargetHost(e.target.value)}
                required
              />
              {createError && <div className="form-error">{createError}</div>}
              <div className="form-actions">
                <button type="submit" className="btn-primary">Create</button>
                <button type="button" className="btn-ghost" onClick={() => setShowNewForm(false)}>
                  Cancel
                </button>
              </div>
            </form>
          )}

          {sessions.length === 0 ? (
            <p className="empty-hint">No sessions yet. Create one or scan the network.</p>
          ) : (
            <div className="session-cards">
              {sessions.map((s) => {
                const ports = getSessionPorts(s.id);
                return (
                <div key={s.id} className="session-card">
                  <Link to={`/session/${s.id}`} className="session-card-body">
                    <div className="session-card-name">
                      <span className={`status-dot ${s.is_running ? 'running' : 'idle'}`} />
                      {s.session_name}
                    </div>
                    <div className="session-card-host">{s.target_host}</div>
                    {ports.length > 0 && (
                      <div className="session-card-ports">
                        {ports.map(p => (
                          <span
                            key={`${p.port}-${p.protocol}`}
                            className={`port-tag port-${p.state}${p.protocol === 'udp' ? ' port-udp' : ''}`}
                            title={`${p.port}/${p.protocol} ${p.state}${p.name ? ` (${p.name})` : ''}`}
                          >
                            {p.port}{p.protocol === 'udp' ? '/udp' : ''}
                          </span>
                        ))}
                      </div>
                    )}
                  </Link>
                  <div className="session-card-actions">
                    <Link to={`/session/${s.id}`} className="btn-open">
                      Open →
                    </Link>
                    <button
                      className="btn-kill"
                      title="Delete session"
                      onClick={() => handleDeleteSession(s.id)}
                    >
                      ✕
                    </button>
                  </div>
                </div>
              ); })}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
