import { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import './HandshakeCapturePanel.css';

interface WifiAP {
  bssid: string;
  essid: string;
  channel: number;
  power: number;
  privacy: string;
  cipher: string;
  auth: string;
  beacons: number;
  clients: number;
  client_macs: string[];
}

type SortKey = 'essid' | 'bssid' | 'channel' | 'power' | 'privacy' | 'clients';

interface HandshakeCapturePanelProps {
  sessionId: number;
}

export default function HandshakeCapturePanel({ sessionId }: HandshakeCapturePanelProps) {
  // Interface & monitor mode
  const [ifaces, setIfaces] = useState<string[]>([]);
  const [selectedIface, setSelectedIface] = useState('');
  const [monitorIface, setMonitorIface] = useState('');
  const [monitorBusy, setMonitorBusy] = useState(false);
  const [monitorOutput, setMonitorOutput] = useState('');
  const [monitorError, setMonitorError] = useState('');

  // Scan
  const [band, setBand] = useState('');
  const [scanRunning, setScanRunning] = useState(false);
  const [scanSecondsLeft, setScanSecondsLeft] = useState<number | null>(null);
  const [aps, setAps] = useState<WifiAP[]>([]);
  const [sortKey, setSortKey] = useState<SortKey>('power');
  const [sortDesc, setSortDesc] = useState(true);
  const scanPollRef    = useRef<ReturnType<typeof setInterval> | null>(null);
  const scanAutoStop   = useRef<ReturnType<typeof setTimeout>  | null>(null);
  const scanCountdown  = useRef<ReturnType<typeof setInterval> | null>(null);

  const [scanOutput, setScanOutput] = useState<string[]>([]);
  const scanOutputRef = useRef<HTMLDivElement>(null);

  // Capture
  const [selectedBSSIDs, setSelectedBSSIDs] = useState<Set<string>>(new Set());
  const [deauthCount, setDeauthCount] = useState(10);
  const [deauthRepeat, setDeauthRepeat] = useState(true);
  const [captureRunning, setCaptureRunning] = useState(false);
  const [captureOutput, setCaptureOutput] = useState<string[]>([]);
  const [handshakes, setHandshakes] = useState<string[]>([]);
  const capturePollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const outputRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    loadInterfaces();
    return () => {
      if (scanPollRef.current)   clearInterval(scanPollRef.current);
      if (scanAutoStop.current)  clearTimeout(scanAutoStop.current);
      if (scanCountdown.current) clearInterval(scanCountdown.current);
      if (capturePollRef.current) clearInterval(capturePollRef.current);
    };
  }, []);

  useEffect(() => {
    if (scanOutputRef.current) scanOutputRef.current.scrollTop = scanOutputRef.current.scrollHeight;
  }, [scanOutput]);

  useEffect(() => {
    if (outputRef.current) outputRef.current.scrollTop = outputRef.current.scrollHeight;
  }, [captureOutput]);

  const loadInterfaces = async () => {
    try {
      const res = await axios.get('/api/wifi/interfaces');
      const list: string[] = res.data.interfaces || [];
      setIfaces(list);
      if (!selectedIface && list.length > 0) setSelectedIface(list[0]);
    } catch {}
  };

  const handleEnableMonitor = async () => {
    if (!selectedIface) return;
    setMonitorBusy(true);
    setMonitorError('');
    setMonitorOutput('');
    try {
      const res = await axios.post('/api/wifi/monitor', { interface: selectedIface });
      setMonitorIface(res.data.monitor_iface || selectedIface + 'mon');
      setMonitorOutput(res.data.output || '');
    } catch (err: any) {
      setMonitorError(err.response?.data?.error || err.message || 'Failed to enable monitor mode');
      setMonitorOutput(err.response?.data?.output || '');
    } finally {
      setMonitorBusy(false);
    }
  };

  const handleDisableMonitor = async () => {
    if (!monitorIface) return;
    setMonitorBusy(true);
    setMonitorError('');
    try {
      const res = await axios.delete('/api/wifi/monitor', { data: { monitor_iface: monitorIface } });
      setMonitorIface('');
      setMonitorOutput(res.data.output || '');
      if (scanRunning) doStopScan();
    } catch (err: any) {
      setMonitorError(err.response?.data?.error || err.message || 'Failed to disable monitor mode');
    } finally {
      setMonitorBusy(false);
    }
  };

  const handleEnableManaged = async () => {
    if (!selectedIface) return;
    setMonitorBusy(true);
    setMonitorError('');
    try {
      const iface = monitorIface || selectedIface;
      await axios.post('/api/wifi/managed', { interface: iface });
      setMonitorIface('');
      setMonitorOutput('Managed mode restored.');
      if (scanRunning) doStopScan();
    } catch (err: any) {
      setMonitorError(err.response?.data?.error || err.message || 'Failed to restore managed mode');
    } finally {
      setMonitorBusy(false);
    }
  };

  const clearScanTimers = () => {
    if (scanPollRef.current)   { clearInterval(scanPollRef.current);  scanPollRef.current   = null; }
    if (scanAutoStop.current)  { clearTimeout(scanAutoStop.current);  scanAutoStop.current  = null; }
    if (scanCountdown.current) { clearInterval(scanCountdown.current); scanCountdown.current = null; }
  };

  // Manage countdown + auto-stop via effect so we never capture a stale closure
  useEffect(() => {
    if (!scanRunning) {
      setScanSecondsLeft(null);
      if (scanAutoStop.current)  { clearTimeout(scanAutoStop.current);  scanAutoStop.current  = null; }
      if (scanCountdown.current) { clearInterval(scanCountdown.current); scanCountdown.current = null; }
      return;
    }
    setScanSecondsLeft(60);
    scanCountdown.current = setInterval(() => {
      setScanSecondsLeft(s => (s !== null && s > 1 ? s - 1 : null));
    }, 1000);
    scanAutoStop.current = setTimeout(() => {
      if (scanPollRef.current) { clearInterval(scanPollRef.current); scanPollRef.current = null; }
      setScanRunning(false);
      axios.delete(`/api/sessions/${sessionId}/wifi/scan`).catch(() => {});
    }, 60_000);
    return () => {
      if (scanAutoStop.current)  { clearTimeout(scanAutoStop.current);  scanAutoStop.current  = null; }
      if (scanCountdown.current) { clearInterval(scanCountdown.current); scanCountdown.current = null; }
    };
  }, [scanRunning, sessionId]);

  const doStopScan = () => {
    // Update UI immediately — don't wait for the network call
    if (scanPollRef.current) { clearInterval(scanPollRef.current); scanPollRef.current = null; }
    setScanRunning(false);
    axios.delete(`/api/sessions/${sessionId}/wifi/scan`).catch(() => {});
  };

  const startScan = async () => {
    if (!monitorIface) return;
    setMonitorError('');
    try {
      await axios.post(`/api/sessions/${sessionId}/wifi/scan`, { monitor_iface: monitorIface, band });
      setAps([]);
      setScanOutput([]);
      if (scanPollRef.current) clearInterval(scanPollRef.current);
      scanPollRef.current = setInterval(pollScan, 2000);
      setScanRunning(true); // triggers the useEffect above
    } catch (err: any) {
      setMonitorError(err.response?.data?.error || err.message || 'Failed to start scan');
    }
  };

  const pollScan = async () => {
    try {
      const res = await axios.get(`/api/sessions/${sessionId}/wifi/scan`);
      setAps(res.data.aps || []);
      setScanOutput(res.data.output || []);
      if (res.data.status === 'done') {
        setScanRunning(false);
        setScanSecondsLeft(null);
        clearScanTimers();
      }
    } catch {}
  };

  const startCapture = async () => {
    if (!monitorIface || selectedBSSIDs.size === 0) return;
    const targets = aps
      .filter(ap => selectedBSSIDs.has(ap.bssid))
      .map(ap => ({ bssid: ap.bssid, essid: ap.essid, channel: ap.channel, client_macs: ap.client_macs || [] }));
    setMonitorError('');
    try {
      await axios.post(`/api/sessions/${sessionId}/wifi/capture`, {
        monitor_iface: monitorIface,
        targets,
        deauth_count: deauthCount,
        deauth_repeat: deauthRepeat,
      });
      setCaptureRunning(true);
      setCaptureOutput([]);
      setHandshakes([]);
      if (capturePollRef.current) clearInterval(capturePollRef.current);
      capturePollRef.current = setInterval(pollCapture, 2000);
    } catch (err: any) {
      setMonitorError(err.response?.data?.error || err.message || 'Failed to start capture');
    }
  };

  const stopCapture = () => {
    // Update UI immediately — don't wait for the network call
    setCaptureRunning(false);
    if (capturePollRef.current) { clearInterval(capturePollRef.current); capturePollRef.current = null; }
    axios.delete(`/api/sessions/${sessionId}/wifi/capture`).catch(() => {});
  };

  const pollCapture = async () => {
    try {
      const res = await axios.get(`/api/sessions/${sessionId}/wifi/capture`);
      setCaptureOutput(res.data.output || []);
      setHandshakes(res.data.handshakes || []);
      if (res.data.status === 'done') {
        setCaptureRunning(false);
        if (capturePollRef.current) { clearInterval(capturePollRef.current); capturePollRef.current = null; }
      }
    } catch {}
  };

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) setSortDesc(d => !d);
    else { setSortKey(key); setSortDesc(key === 'power'); }
  };

  const sortedAps = [...aps].sort((a, b) => {
    const av = a[sortKey], bv = b[sortKey];
    if (typeof av === 'number' && typeof bv === 'number')
      return sortDesc ? bv - av : av - bv;
    return sortDesc
      ? String(bv).localeCompare(String(av))
      : String(av).localeCompare(String(bv));
  });

  const toggleSelectAP = (bssid: string) => {
    setSelectedBSSIDs(prev => {
      const next = new Set(prev);
      if (next.has(bssid)) next.delete(bssid);
      else next.add(bssid);
      return next;
    });
  };

  const handleSelectAll = () => {
    if (selectedBSSIDs.size === aps.length) setSelectedBSSIDs(new Set());
    else setSelectedBSSIDs(new Set(aps.map(ap => ap.bssid)));
  };

  const sortArrow = (key: SortKey) =>
    sortKey === key ? (sortDesc ? ' ▼' : ' ▲') : '';

  return (
    <div className="hcp-panel">

      {/* ── 1. Interface & Monitor Mode ── */}
      <div className="hcp-section">
        <div className="hcp-section-title">Interface &amp; Monitor Mode</div>
        <div className="hcp-row">
          <label className="hcp-label">Interface</label>
          <select
            className="hcp-select"
            value={selectedIface}
            onChange={e => setSelectedIface(e.target.value)}
            disabled={!!monitorIface || monitorBusy}
          >
            {ifaces.length === 0 && <option value="">No wireless interfaces found</option>}
            {ifaces.map(i => <option key={i} value={i}>{i}</option>)}
          </select>
          <button className="hcp-btn-refresh" onClick={loadInterfaces} title="Refresh">↺</button>
        </div>

        <div className="hcp-row hcp-monitor-btns">
          {!monitorIface ? (
            <button
              className="btn-run-attack"
              onClick={handleEnableMonitor}
              disabled={monitorBusy || !selectedIface}
            >
              {monitorBusy ? 'Enabling…' : '▶ Enable Monitor Mode'}
            </button>
          ) : (
            <>
              <span className="hcp-monitor-active">⬤ {monitorIface}</span>
              <button className="btn-stop-attack" onClick={handleDisableMonitor} disabled={monitorBusy}>
                {monitorBusy ? 'Stopping…' : '■ Disable Monitor Mode'}
              </button>
              <button className="hcp-btn-managed" onClick={handleEnableManaged} disabled={monitorBusy}>
                Restore Managed Mode
              </button>
            </>
          )}
        </div>

        {monitorError && <div className="hcp-error">{monitorError}</div>}
        {monitorOutput && <pre className="hcp-mono-out">{monitorOutput}</pre>}
      </div>

      {/* ── 2. AP Scanner ── */}
      <div className="hcp-section">
        <div className="hcp-section-title">AP Scanner (airodump-ng)</div>
        <div className="hcp-row">
          <label className="hcp-label">Band</label>
          <select
            className="hcp-select hcp-select-sm"
            value={band}
            onChange={e => setBand(e.target.value)}
            disabled={scanRunning}
          >
            <option value="">All bands</option>
            <option value="a">5 GHz (a)</option>
            <option value="bg">2.4 GHz (bg)</option>
            <option value="abg">Both (abg)</option>
          </select>
          {!scanRunning ? (
            <button className="btn-run-attack" onClick={startScan} disabled={!monitorIface}>
              ▶ Start Scan
            </button>
          ) : (
            <button className="btn-stop-attack" onClick={doStopScan}>■ Stop Scan</button>
          )}
          {scanRunning && scanSecondsLeft !== null && (
            <span className="hcp-countdown">auto-stop in {scanSecondsLeft}s</span>
          )}
          {!monitorIface && <span className="hcp-hint">Enable monitor mode first.</span>}
        </div>

        {scanRunning && aps.length === 0 && (
          <div className="hcp-hint hcp-scanning">
            <span className="hcp-spinner" /> Scanning… initial results take ~10 s
          </div>
        )}

        {scanOutput.length > 0 && (
          <div className="hcp-out-wrap">
            <div className="hcp-out-title">Scan output</div>
            <div className="hcp-out hcp-out-sm" ref={scanOutputRef}>
              {scanOutput.map((line, i) => (
                <div key={i} className={
                  `hcp-line${
                    line.startsWith('[diag]') ? ' hcp-line-diag' :
                    line.includes('error') || line.includes('Error') || line.includes('failed') ? ' hcp-line-error' :
                    line.startsWith('[*]') || line.startsWith('[+]') ? ' hcp-line-info' : ''
                  }`
                }>{line}</div>
              ))}
            </div>
          </div>
        )}

        {aps.length > 0 && (
          <div className="hcp-ap-wrap">
            <table className="hcp-ap-table">
              <thead>
                <tr>
                  <th>
                    <input
                      type="checkbox"
                      checked={selectedBSSIDs.size === aps.length && aps.length > 0}
                      ref={el => {
                        if (el) el.indeterminate =
                          selectedBSSIDs.size > 0 && selectedBSSIDs.size < aps.length;
                      }}
                      onChange={handleSelectAll}
                    />
                  </th>
                  {(['essid', 'bssid', 'channel', 'power', 'privacy', 'clients'] as SortKey[]).map(k => (
                    <th key={k} className="hcp-sort-th" onClick={() => toggleSort(k)}>
                      {k.toUpperCase()}{sortArrow(k)}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {sortedAps.map(ap => (
                  <tr
                    key={ap.bssid}
                    className={selectedBSSIDs.has(ap.bssid) ? 'hcp-selected' : ''}
                    onClick={() => toggleSelectAP(ap.bssid)}
                  >
                    <td>
                      <input
                        type="checkbox"
                        checked={selectedBSSIDs.has(ap.bssid)}
                        onChange={() => toggleSelectAP(ap.bssid)}
                        onClick={e => e.stopPropagation()}
                      />
                    </td>
                    <td className="hcp-td-essid">{ap.essid || '<hidden>'}</td>
                    <td className="hcp-td-bssid">{ap.bssid}</td>
                    <td>{ap.channel}</td>
                    <td className={
                      ap.power >= -60 ? 'hcp-pwr-strong' :
                      ap.power >= -75 ? 'hcp-pwr-med' : 'hcp-pwr-weak'
                    }>
                      {ap.power} dBm
                    </td>
                    <td>{ap.privacy}</td>
                    <td>{ap.clients}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ── 3. Capture ── */}
      <div className="hcp-section">
        <div className="hcp-section-title">Handshake Capture</div>

        <div className="hcp-row">
          <label className="hcp-label">Deauth count</label>
          <input
            type="number"
            className="hcp-num"
            value={deauthCount}
            min={1}
            max={100}
            onChange={e => setDeauthCount(Number(e.target.value))}
          />
          <label className="hcp-check">
            <input
              type="checkbox"
              checked={deauthRepeat}
              onChange={e => setDeauthRepeat(e.target.checked)}
            />
            Repeat every 15 s
          </label>
        </div>

        <div className="hcp-row">
          {!captureRunning ? (
            <button
              className="btn-run-attack"
              onClick={startCapture}
              disabled={!monitorIface || selectedBSSIDs.size === 0}
            >
              ▶ Capture ({selectedBSSIDs.size} target{selectedBSSIDs.size !== 1 ? 's' : ''})
            </button>
          ) : (
            <button className="btn-stop-attack" onClick={stopCapture}>■ Stop Capture</button>
          )}
          {monitorIface && selectedBSSIDs.size === 0 && !captureRunning && (
            <span className="hcp-hint">Select targets from the AP table above.</span>
          )}
          {!monitorIface && !captureRunning && (
            <span className="hcp-hint">Enable monitor mode and scan first.</span>
          )}
        </div>

        {handshakes.length > 0 && (
          <div className="hcp-hs-found">
            <div className="hcp-hs-title">Handshakes Captured</div>
            {handshakes.map((h, i) => (
              <div key={i} className="hcp-hs-entry">
                <span className="hcp-hs-check">✔</span>
                <span className="hcp-hs-text">{h}</span>
              </div>
            ))}
          </div>
        )}

        {captureOutput.length > 0 && (
          <div className="hcp-out-wrap">
            <div className="hcp-out-title">Capture Output</div>
            <div className="hcp-out" ref={outputRef}>
              {captureOutput.map((line, i) => (
                <div key={i} className={
                  `hcp-line${
                    line.startsWith('[+]') ? ' hcp-line-found' :
                    line.startsWith('[!]') ? ' hcp-line-error' :
                    line.startsWith('[*]') ? ' hcp-line-info' : ''
                  }`
                }>
                  {line}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
