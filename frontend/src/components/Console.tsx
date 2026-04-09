import { useEffect, useRef, useState, useCallback } from 'react';
import { ansiToHtml } from '../ansi';
import './Console.css';

const MAX_RECONNECT_ATTEMPTS = 5;

interface ConsoleProps {
  sessionId: number;
  onSessionOpened?: () => void;
}

export default function Console({ sessionId, onSessionOpened }: ConsoleProps) {
  const [messages, setMessages] = useState<string[]>([]);
  const [command, setCommand] = useState('');
  const [connected, setConnected] = useState(false);
  const [reconnectAttempt, setReconnectAttempt] = useState(0);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const reconnectAttemptRef = useRef(0);
  const historyRef = useRef<string[]>([]);
  const historyIndexRef = useRef(-1);
  const sendingRef = useRef(false);

  const connectWebSocket = useCallback(() => {
    try {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';

      // Silence and close any previous WebSocket so its onclose/onmessage
      // handlers don't fire after we've moved on (fixes StrictMode double-mount).
      if (wsRef.current) {
        const old = wsRef.current;
        old.onopen = null;
        old.onmessage = null;
        old.onerror = null;
        old.onclose = null;
        if (old.readyState === WebSocket.OPEN || old.readyState === WebSocket.CONNECTING) {
          old.close();
        }
      }

      // Cookie is sent automatically by the browser on the WebSocket upgrade request
      const ws = new WebSocket(
        `${protocol}//${window.location.host}/api/ws?session=${sessionId}`
      );
      // Store immediately so the guards below can compare against wsRef.current.
      wsRef.current = ws;

      ws.onopen = () => {
        if (wsRef.current !== ws) return; // superseded
        setConnected(true);
        reconnectAttemptRef.current = 0;
        setReconnectAttempt(0);
        setMessages((prev) => [...prev, '[*] Connected to metasploit console']);
      };

      ws.onmessage = (event) => {
        if (wsRef.current !== ws) return; // superseded
        try {
          const data = JSON.parse(event.data);
          if (data.type === 'output' && data.output) {
            setMessages((prev) => [...prev, data.output]);
          } else if (data.type === 'welcome' && data.output) {
            setMessages((prev) => [...prev, data.output]);
          } else if (data.type === 'error' && data.output) {
            setMessages((prev) => [...prev, `[ERROR] ${data.output}`]);
            if (data.status === 'session_not_found') {
              // The app session no longer exists — reconnecting will never recover.
              reconnectAttemptRef.current = MAX_RECONNECT_ATTEMPTS;
            }
          } else if (data.type === 'status' && data.output) {
            setMessages((prev) => [...prev, `[STATUS] ${data.output}`]);
          } else if (data.type === 'session_opened') {
            onSessionOpened?.();
          }
        } catch {
          setMessages((prev) => [...prev, event.data]);
        }
      };

      ws.onerror = () => {
        if (wsRef.current !== ws) return; // superseded
        setConnected(false);
      };

      ws.onclose = () => {
        if (wsRef.current !== ws) return; // superseded — don't trigger reconnect
        setConnected(false);
        const attempt = reconnectAttemptRef.current;
        if (attempt < MAX_RECONNECT_ATTEMPTS) {
          const delay = Math.min(1000 * Math.pow(2, attempt), 30000);
          reconnectAttemptRef.current = attempt + 1;
          setReconnectAttempt(attempt + 1);
          setMessages((prev) => [
            ...prev,
            `[!] Disconnected. Reconnecting in ${delay / 1000}s (attempt ${attempt + 1}/${MAX_RECONNECT_ATTEMPTS})...`,
          ]);
          reconnectTimerRef.current = setTimeout(connectWebSocket, delay);
        } else {
          setMessages((prev) => [
            ...prev,
            '[!] Connection lost. Max reconnect attempts reached. Click Reconnect to try again.',
          ]);
        }
      };
    } catch (err) {
      setConnected(false);
      setMessages((prev) => [...prev, '[!] Failed to connect to console']);
    }
  }, [sessionId]);

  const handleManualReconnect = () => {
    reconnectAttemptRef.current = 0;
    setReconnectAttempt(0);
    connectWebSocket();
  };

  useEffect(() => {
    reconnectAttemptRef.current = 0;
    setReconnectAttempt(0);
    setMessages([]);
    connectWebSocket();
    return () => {
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      if (wsRef.current) wsRef.current.close();
    };
  }, [sessionId, connectWebSocket]);

  const handleSendCommand = (e: React.FormEvent) => {
    e.preventDefault();
    if (!command.trim() || !connected || !wsRef.current || sendingRef.current) return;
    sendingRef.current = true;

    historyRef.current = [command, ...historyRef.current.slice(0, 99)];
    historyIndexRef.current = -1;

    setMessages((prev) => [...prev, `msf> ${command}`]);
    try {
      wsRef.current.send(JSON.stringify({ command, session_id: sessionId }));
    } catch (err) {
      setMessages((prev) => [...prev, '[!] Failed to send command']);
    }
    setCommand('');
    requestAnimationFrame(() => { sendingRef.current = false; });
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      const next = historyIndexRef.current + 1;
      if (next < historyRef.current.length) {
        historyIndexRef.current = next;
        setCommand(historyRef.current[next]);
      }
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      const next = historyIndexRef.current - 1;
      if (next < 0) {
        historyIndexRef.current = -1;
        setCommand('');
      } else {
        historyIndexRef.current = next;
        setCommand(historyRef.current[next]);
      }
    }
  };

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  return (
    <div className="console">
      <div className="console-header">
        <h3>MSF Console - Session {sessionId}</h3>
        <div className="console-header-right">
          <div className={`status-indicator ${connected ? 'connected' : 'disconnected'}`}>
            <span className="status-dot"></span>
            {connected ? 'Connected' : 'Disconnected'}
          </div>
          {!connected && reconnectAttempt >= MAX_RECONNECT_ATTEMPTS && (
            <button className="reconnect-btn" onClick={handleManualReconnect}>
              Reconnect
            </button>
          )}
        </div>
      </div>

      <div className="console-output">
        {messages.length === 0 ? (
          <div className="console-welcome">
            <p>[*] Metasploit Framework v6 Console</p>
            <p>[*] Waiting for commands...</p>
          </div>
        ) : (
          messages.map((msg, idx) => (
            <div
              key={idx}
              className="console-line"
              dangerouslySetInnerHTML={{ __html: ansiToHtml(msg) }}
            />
          ))
        )}
        <div ref={messagesEndRef} />
      </div>

      <form onSubmit={handleSendCommand} className="console-input-form">
        <span className="console-prompt">msf&gt;</span>
        <input
          type="text"
          value={command}
          onChange={(e) => setCommand(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Type your command..."
          disabled={!connected}
          autoFocus
          className="console-input"
        />
        <button type="submit" disabled={!connected} className="console-send-btn">
          Send
        </button>
      </form>
    </div>
  );
}
