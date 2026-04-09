import { useState } from 'react';
import axios from 'axios';
import './SessionList.css';

interface Session {
  id: number;
  session_name: string;
  target_host: string;
  created_at: string;
  is_running: boolean;
}

interface SessionListProps {
  sessions: Session[];
  activeSession: number | null;
  onSelectSession: (id: number) => void;
  onCreateSession: () => void;
  onDeleteSession: (id: number) => void;
}

export default function SessionList({
  sessions,
  activeSession,
  onSelectSession,
  onCreateSession,
  onDeleteSession,
}: SessionListProps) {
  const [showNewSession, setShowNewSession] = useState(false);
  const [sessionName, setSessionName] = useState('');
  const [targetHost, setTargetHost] = useState('');
  const [createError, setCreateError] = useState('');

  const handleCreateSession = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreateError('');
    try {
      await axios.post('/api/sessions', { session_name: sessionName, target_host: targetHost });
      setSessionName('');
      setTargetHost('');
      setShowNewSession(false);
      onCreateSession();
    } catch (err: any) {
      setCreateError(err.response?.data?.error || err.message || 'Failed to create session');
    }
  };

  return (
    <div className="session-list">
      <h2>Sessions</h2>
      
      <button className="new-session-btn" onClick={() => setShowNewSession(!showNewSession)}>
        + New Session
      </button>

      {showNewSession && (
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
          {createError && <div className="session-create-error">{createError}</div>}
          <button type="submit">Create</button>
        </form>
      )}

      <div className="sessions">
        {sessions.map((session) => (
          <div
            key={session.id}
            className={`session-item ${activeSession === session.id ? 'active' : ''}`}
            onClick={() => onSelectSession(session.id)}
          >
            <div className="session-info">
              <div className="session-name">
                <span
                  className={`session-status-dot ${session.is_running ? 'running' : 'idle'}`}
                  title={session.is_running ? 'Console active' : 'No active console'}
                />
                {session.session_name}
              </div>
              <div className="session-host">{session.target_host}</div>
            </div>
            <button
              className="session-kill-btn"
              title="Kill session"
              onClick={(e) => {
                e.stopPropagation();
                onDeleteSession(session.id);
              }}
            >
              ✕
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
