import { useState, useEffect } from 'react';
import axios from 'axios';
import { useNavigate, Link } from 'react-router-dom';
import './ProjectsPage.css';
import {
  HandshakeUploadPanel,
  HashcatPanel,
  BruteforcePanel,
  SqlmapPanel,
  FeroxPanel,
} from './SessionDetail';
import HandshakeCapturePanel from './HandshakeCapturePanel';

// Fixed virtual session ID for project-page password attacks (not tied to a real session)
const ATTACKS_VIRTUAL_SESSION = 99999;

interface ProjectsPageProps {
  onLogout: () => void;
}

interface Project {
  id: number;
  name: string;
  network_range: string;
  created_at: string;
}

export default function ProjectsPage({ onLogout }: ProjectsPageProps) {
  const navigate = useNavigate();
  const [projects, setProjects] = useState<Project[]>([]);
  const [showForm, setShowForm] = useState(false);
  const [projName, setProjName] = useState('');
  const [networkRange, setNetworkRange] = useState('');
  const [createError, setCreateError] = useState('');
  const [localInterfaces, setLocalInterfaces] = useState<{ name: string; cidr: string; ip: string }[]>([]);
  const [activeAttack, setActiveAttack] = useState<number>(9);

  useEffect(() => {
    loadProjects();
    axios.get('/api/network')
      .then(res => setLocalInterfaces(res.data.interfaces || []))
      .catch(() => {});
  }, []);

  const loadProjects = async () => {
    try {
      const res = await axios.get('/api/projects');
      setProjects(res.data.projects || []);
    } catch {
      // silently ignore
    }
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreateError('');
    try {
      const res = await axios.post('/api/projects', {
        name: projName,
        network_range: networkRange,
      });
      setProjName('');
      setNetworkRange('');
      setShowForm(false);
      navigate(`/project/${res.data.project.id}`);
    } catch (err: any) {
      setCreateError(err.response?.data?.error || err.message || 'Failed to create project');
    }
  };

  const clearSessionLocalStorage = (sessionId: number) => {
    const keys = ['vuln', 'cve', 'enum', 'os', 'msf-sessions', 'remarks'];
    keys.forEach(k => localStorage.removeItem(`session-${sessionId}-${k}`));
  };

  const handleDelete = async (id: number) => {
    try {
      const res = await axios.delete(`/api/projects/${id}`);
      // Clear localStorage for every session that belonged to this project.
      const deletedIds: number[] = res.data?.deleted_session_ids || [];
      deletedIds.forEach(clearSessionLocalStorage);
      loadProjects();
    } catch {
      // silently ignore
    }
  };

  return (
    <div className="projects-page">
      <header className="projects-header">
        <div className="projects-header-left">
          <h1>MSF Web Interface</h1>
          {localInterfaces.length > 0 && (
            <div className="projects-network-info">
              {localInterfaces.map(iface => (
                <span key={iface.cidr} className="projects-network-cidr">
                  <span className="projects-iface-name">{iface.name}</span>
                  {iface.ip}
                </span>
              ))}
            </div>
          )}
        </div>
        <button className="logout-btn" onClick={onLogout}>Logout</button>
      </header>

      <div className="projects-body">
        <div className="projects-main-row">
        <div className="projects-panel">
          <div className="panel-heading">
            <h2>Projects</h2>
            <button className="btn-primary" onClick={() => setShowForm(!showForm)}>
              + New Project
            </button>
          </div>

          {showForm && (
            <form onSubmit={handleCreate} className="new-project-form">
              <input
                type="text"
                placeholder="Project name (e.g. Lab Network)"
                value={projName}
                onChange={(e) => setProjName(e.target.value)}
                required
                autoFocus
              />
              <input
                type="text"
                placeholder="Network range (e.g. 192.168.1.0/24) — optional"
                value={networkRange}
                onChange={(e) => setNetworkRange(e.target.value)}
              />
              {createError && <div className="form-error">{createError}</div>}
              <div className="form-actions">
                <button type="submit" className="btn-primary">Create</button>
                <button type="button" className="btn-ghost" onClick={() => setShowForm(false)}>Cancel</button>
              </div>
            </form>
          )}

          {projects.length === 0 ? (
            <p className="empty-hint">No projects yet. Create one to get started.</p>
          ) : (
            <div className="project-cards">
              {projects.map((p) => (
                <div key={p.id} className="project-card">
                  <Link to={`/project/${p.id}`} className="project-card-body">
                    <div className="project-card-name">{p.name}</div>
                    {p.network_range && (
                      <div className="project-card-range">{p.network_range}</div>
                    )}
                  </Link>
                  <div className="project-card-actions">
                    <Link to={`/project/${p.id}`} className="btn-open">
                      Open →
                    </Link>
                    <button
                      className="btn-kill"
                      title="Delete project"
                      onClick={() => handleDelete(p.id)}
                    >
                      ✕
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
        </div>{/* end projects-main-row */}

        {/* ── Password Attacks ── */}
        <div className="attacks-panel">
          <div className="attacks-panel-heading">
            <h2>Password Attacks</h2>
          </div>
          <div className="attacks-tabs">
            {[
              { id: 9,  label: "Handshake Capture" },
              { id: 10, label: "Wifi Handshakes" },
              { id: 11, label: "Hashcat" },
              { id: 12, label: "Bruteforce" },
              { id: 13, label: "SqlMap" },
              { id: 14, label: "FeroxBuster" },
            ].map(t => (
              <button
                key={t.id}
                className={`attacks-tab${activeAttack === t.id ? ' active' : ''}`}
                onClick={() => setActiveAttack(t.id)}
              >
                {t.label}
              </button>
            ))}
          </div>
          <div className="attacks-content">
            {activeAttack === 9  && <HandshakeCapturePanel sessionId={ATTACKS_VIRTUAL_SESSION} />}
            {activeAttack === 10 && <HandshakeUploadPanel />}
            {activeAttack === 11 && <HashcatPanel sessionId={ATTACKS_VIRTUAL_SESSION} />}
            {activeAttack === 12 && <BruteforcePanel sessionId={ATTACKS_VIRTUAL_SESSION} />}
            {activeAttack === 13 && <SqlmapPanel sessionId={ATTACKS_VIRTUAL_SESSION} />}
            {activeAttack === 14 && <FeroxPanel sessionId={ATTACKS_VIRTUAL_SESSION} />}
          </div>
        </div>
      </div>
    </div>
  );
}
