import { useState, useEffect, useCallback, useRef } from 'react';
import {
  Shield, Scan, History, LayoutDashboard, Activity, Info,
  CheckCircle2, AlertTriangle, XCircle, Wifi, WifiOff,
  Search, MessageSquare, Zap, Eye, Lock,
  ChevronRight, RefreshCw, Brain, QrCode, Upload, Image as ImageIcon,
  Globe, FileText, ShieldAlert, TrendingUp, Camera, Square
} from 'lucide-react';
import jsQR from 'jsqr';
import {
  checkHealth, analyzeUrl, analyzeMessage, analyzeQR, analyzeScreenshot, getHistory, getStatistics,
  type AnalysisResult, type HistoryItem, type Statistics
} from './services/api';
import ThreatExplanation from './components/ThreatExplanation';
import './index.css';

type Tab = 'dashboard' | 'scanner' | 'history' | 'about';

const EXAMPLE_URLS = [
  'http://suspicious-site.tk/login',
  'https://www.google.com',
  'http://paypal-secure.xyz',
];

export default function App() {
  const [tab, setTab] = useState<Tab>('scanner');
  const [connected, setConnected] = useState<boolean | null>(null);
  const [mlStatus, setMlStatus] = useState({ url: false, message: false });

  // Scanner state
  const [scanMode, setScanMode] = useState<'url' | 'message' | 'qr' | 'screenshot'>('url');
  const [urlInput, setUrlInput] = useState('');
  const [messageInput, setMessageInput] = useState('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [filePreview, setFilePreview] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [scanError, setScanError] = useState('');
  const fileInputRef = useRef<HTMLInputElement>(null);
  const videoRef = useRef<HTMLVideoElement>(null);
  const cameraStreamRef = useRef<MediaStream | null>(null);
  const cameraScanInFlightRef = useRef(false);
  const [cameraActive, setCameraActive] = useState(false);

  // Dashboard state
  const [stats, setStats] = useState<Statistics | null>(null);

  // History state
  const [history, setHistory] = useState<HistoryItem[]>([]);

  // Health check
  useEffect(() => {
    checkHealth()
      .then((data) => {
        setConnected(true);
        setMlStatus({
          url: data.ml_models.url_model_loaded,
          message: data.ml_models.message_model_loaded,
        });
      })
      .catch(() => setConnected(false));
  }, []);

  useEffect(() => () => {
    cameraStreamRef.current?.getTracks().forEach((track) => track.stop());
  }, []);

  useEffect(() => {
    if (cameraActive && videoRef.current && cameraStreamRef.current) {
      videoRef.current.srcObject = cameraStreamRef.current;
    }
  }, [cameraActive]);

  // Load data when switching tabs
  const loadDashboard = useCallback(() => {
    getStatistics().then(setStats).catch(console.error);
  }, []);

  const loadHistory = useCallback(() => {
    getHistory().then((data) => setHistory(data.history)).catch(console.error);
  }, []);

  useEffect(() => {
    if (tab === 'dashboard') loadDashboard();
    if (tab === 'history') loadHistory();
  }, [tab, loadDashboard, loadHistory]);

  const handleFileChange = (file: File | null) => {
    if (!file) return;
      if (!['image/png', 'image/jpeg', 'image/webp'].includes(file.type)) {
        setScanError('Please select a PNG, JPG, JPEG, or WEBP image.');
      return;
    }
    if (file.size > 10 * 1024 * 1024) {
      setScanError('Please choose an image smaller than 10 MB.');
      return;
    }
    setSelectedFile(file);
    setScanError('');
    const reader = new FileReader();
    reader.onload = () => setFilePreview(reader.result as string);
    reader.readAsDataURL(file);
  };

  const handleDrop = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    handleFileChange(event.dataTransfer.files?.[0] || null);
  };

  useEffect(() => {
    const handlePaste = (event: ClipboardEvent) => {
      if (scanMode !== 'qr') return;
      const image = Array.from(event.clipboardData?.items || []).find((item) => item.type.startsWith('image/'));
      if (image) handleFileChange(image.getAsFile());
    };
    window.addEventListener('paste', handlePaste);
    return () => window.removeEventListener('paste', handlePaste);
  }, [scanMode]);

  const stopCamera = () => {
    cameraStreamRef.current?.getTracks().forEach((track) => track.stop());
    cameraStreamRef.current = null;
    cameraScanInFlightRef.current = false;
    setCameraActive(false);
  };

  const startCamera = async () => {
    setScanError('');
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
      cameraStreamRef.current = stream;
      cameraScanInFlightRef.current = false;
      setCameraActive(true);
    } catch {
      setScanError('Camera access was unavailable. You can still upload or paste an image.');
    }
  };

  useEffect(() => {
    if (!cameraActive || scanMode !== 'qr' || !videoRef.current) return;
    const timer = window.setInterval(async () => {
      if (cameraScanInFlightRef.current || scanning || !videoRef.current || videoRef.current.readyState < 2) return;
      try {
        const video = videoRef.current;
        const canvas = document.createElement('canvas');
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        const context = canvas.getContext('2d');
        if (!context) return;
        context.drawImage(video, 0, 0, canvas.width, canvas.height);
        const frame = context.getImageData(0, 0, canvas.width, canvas.height);
        const code = jsQR(frame.data, frame.width, frame.height, { inversionAttempts: 'attemptBoth' });
        if (!code?.data) return;
        cameraScanInFlightRef.current = true;
        captureCameraFrame(true);
      } catch {
        // Camera decoding support is optional; the capture button remains available.
      }
    }, 500);
    return () => window.clearInterval(timer);
  }, [cameraActive, scanMode, scanning]);

  const submitFile = async (file: File, mode: 'qr' | 'screenshot') => {
    setScanError('');
    setResult(null);
    setScanning(true);
    try {
      const response = mode === 'qr' ? await analyzeQR(file) : await analyzeScreenshot(file);
      setResult(response);
    } catch (err: unknown) {
      const response = err && typeof err === 'object' && 'response' in err
        ? (err as { response?: { status?: number; data?: { detail?: unknown } } }).response
        : undefined;
      const detail = response?.data?.detail;
      setScanError(detail
        ? typeof detail === 'string' ? detail : JSON.stringify(detail)
        : `Image analysis failed (${response?.status ?? 'network error'})`);
    } finally {
      setScanning(false);
    }
  };

  const captureCameraFrame = (autoAnalyze = false) => {
    const video = videoRef.current;
    if (!video || !video.videoWidth) return;
    const canvas = document.createElement('canvas');
    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    canvas.getContext('2d')?.drawImage(video, 0, 0);
    canvas.toBlob(async (blob) => {
      if (blob) {
        const file = new File([blob], 'camera-capture.jpg', { type: 'image/jpeg' });
        if (autoAnalyze) await submitFile(file, 'qr');
        else handleFileChange(file);
      }
      stopCamera();
    }, 'image/jpeg', 0.92);
  };

  const resetScanner = () => {
    stopCamera();
    setResult(null);
    setSelectedFile(null);
    setFilePreview(null);
    setScanError('');
  };

  // Scan handler
  const handleScan = async () => {
    setScanError('');
    setResult(null);

    if (scanMode === 'url' && !urlInput.trim()) {
      setScanError('Please enter a URL to analyze.');
      return;
    }
    if (scanMode === 'message' && !messageInput.trim()) {
      setScanError('Please enter a message to analyze.');
      return;
    }
    if ((scanMode === 'qr' || scanMode === 'screenshot') && !selectedFile) {
      setScanError(`Please select an image file for ${scanMode === 'qr' ? 'QR Code' : 'Screenshot'} analysis.`);
      return;
    }

    setScanning(true);
    try {
      let res: AnalysisResult;
      if (scanMode === 'url') {
        res = await analyzeUrl(urlInput.trim());
      } else if (scanMode === 'message') {
        res = await analyzeMessage(messageInput.trim());
      } else if (scanMode === 'qr') {
        res = await analyzeQR(selectedFile!);
      } else {
        res = await analyzeScreenshot(selectedFile!);
      }
      setResult(res);
    } catch (err: unknown) {
      let msg = 'Analysis failed';
      if (err && typeof err === 'object' && 'response' in err) {
        const response = (err as { response?: { status?: number; data?: { detail?: string | { stage?: string; error?: string } } } }).response;
        const detail = response?.data?.detail;
        if (typeof detail === 'object' && detail?.stage && detail.error) {
          msg = `${detail.stage.toUpperCase()}: ${detail.error}`;
        } else if (typeof detail === 'string') {
          msg = detail;
        } else if (response?.status === 413) {
          msg = 'The image is too large to scan.';
        } else {
          msg = 'The server could not analyze this input.';
        }
      }
      setScanError(msg);
    } finally {
      setScanning(false);
    }
  };

  const classColor = (c: string) => {
    switch (c) {
      case 'SAFE': return '#10b981';
      case 'SUSPICIOUS': return '#f59e0b';
      case 'PHISHING': return '#ef4444';
      default: return '#94a3b8';
    }
  };

  const classLabel = (c: string) => {
    switch (c) {
      case 'SAFE': return 'Safe';
      case 'SUSPICIOUS': return 'Suspicious';
      case 'PHISHING': return 'Phishing Detected';
      default: return c;
    }
  };

  const classIcon = (c: string) => {
    switch (c) {
      case 'SAFE': return <CheckCircle2 size={32} color="#10b981" />;
      case 'SUSPICIOUS': return <AlertTriangle size={32} color="#f59e0b" />;
      case 'PHISHING': return <XCircle size={32} color="#ef4444" />;
      default: return <Shield size={32} />;
    }
  };

  const classBg = (c: string) => {
    switch (c) {
      case 'SAFE': return 'rgba(16, 185, 129, 0.08)';
      case 'SUSPICIOUS': return 'rgba(245, 158, 11, 0.08)';
      case 'PHISHING': return 'rgba(239, 68, 68, 0.08)';
      default: return 'rgba(148, 163, 184, 0.08)';
    }
  };

  const navItems: { id: Tab; label: string; icon: typeof Shield }[] = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'scanner', label: 'Scanner', icon: Scan },
    { id: 'history', label: 'History', icon: History },
    { id: 'about', label: 'About', icon: Info },
  ];

  return (
    <div style={{ display: 'flex', height: '100vh', background: 'var(--bg-primary)' }}>
      {/* ===== SIDEBAR ===== */}
      <aside style={{
        width: 'var(--sidebar-width)',
        minWidth: 270,
        flexShrink: 0,
        display: 'flex',
        flexDirection: 'column',
        background: 'var(--bg-sidebar)',
        borderRight: '1px solid var(--border-color)',
      }}>
        {/* Logo */}
        <div style={{ padding: '24px 20px', borderBottom: '1px solid var(--border-subtle)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <div style={{
              width: 44, height: 44, borderRadius: 14,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              background: 'var(--gradient-blue)',
              boxShadow: '0 4px 16px rgba(59, 130, 246, 0.3)',
            }}>
              <Shield size={24} color="white" />
            </div>
            <div>
              <h1 style={{ fontSize: 18, fontWeight: 800, color: 'white', letterSpacing: '-0.02em' }}>
                PhishGuard AI
              </h1>
              <p style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2, lineHeight: 1.3 }}>
                AI-Powered Phishing<br />Detection System
              </p>
            </div>
          </div>
        </div>

        {/* Navigation */}
        <nav style={{ flex: 1, padding: '16px 12px', display: 'flex', flexDirection: 'column', gap: 4 }}>
          {navItems.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              id={`nav-${id}`}
              onClick={() => setTab(id)}
              style={{
                display: 'flex', alignItems: 'center', gap: 12,
                padding: '12px 16px', borderRadius: 12, border: 'none',
                cursor: 'pointer', width: '100%', textAlign: 'left',
                fontSize: 14, fontWeight: tab === id ? 600 : 500,
                background: tab === id ? 'rgba(59, 130, 246, 0.12)' : 'transparent',
                color: tab === id ? 'var(--accent-blue)' : 'var(--text-secondary)',
                borderLeft: tab === id ? '3px solid var(--accent-blue)' : '3px solid transparent',
                transition: 'all 0.2s ease',
              }}
            >
              <Icon size={18} />
              {label}
              {tab === id && <ChevronRight size={14} style={{ marginLeft: 'auto', opacity: 0.6 }} />}
            </button>
          ))}
        </nav>

        {/* Status */}
        <div style={{ padding: '16px 20px', borderTop: '1px solid var(--border-subtle)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, marginBottom: 10 }}>
            <div style={{
              width: 8, height: 8, borderRadius: '50%',
              background: connected ? 'var(--accent-green)' : connected === false ? 'var(--accent-red)' : 'var(--accent-yellow)',
              boxShadow: connected ? '0 0 8px rgba(16, 185, 129, 0.5)' : 'none',
            }} />
            <span style={{ color: connected ? 'var(--accent-green)' : connected === false ? 'var(--accent-red)' : 'var(--text-muted)' }}>
              {connected ? 'Backend Connected' : connected === false ? 'Disconnected' : 'Connecting...'}
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12 }}>
            <div style={{
              width: 8, height: 8, borderRadius: '50%',
              background: mlStatus.url && mlStatus.message ? 'var(--accent-green)' : 'var(--accent-yellow)',
              boxShadow: mlStatus.url && mlStatus.message ? '0 0 8px rgba(16, 185, 129, 0.5)' : 'none',
            }} />
            <span style={{ color: 'var(--text-muted)' }}>
              ML Models: {mlStatus.url && mlStatus.message ? 'Loaded' : 'Partial'}
            </span>
          </div>
        </div>
      </aside>

      {/* ===== MAIN AREA ===== */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        {/* Header */}
        <header style={{
          height: 'var(--header-height)', minHeight: 64,
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '0 32px',
          background: 'var(--bg-secondary)',
          borderBottom: '1px solid var(--border-color)',
        }}>
          <div>
            <h2 style={{ fontSize: 20, fontWeight: 700, color: 'white', letterSpacing: '-0.01em' }}>
              {tab === 'dashboard' && 'Dashboard'}
              {tab === 'scanner' && 'Phishing Scanner'}
              {tab === 'history' && 'Scan History'}
              {tab === 'about' && 'About'}
            </h2>
            <p style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
              {tab === 'scanner' && 'Analyze URLs and messages for potential threats using AI'}
              {tab === 'dashboard' && 'Overview of your scanning activity and threat landscape'}
              {tab === 'history' && 'Review your previous scans and their results'}
              {tab === 'about' && 'Learn more about PhishGuard AI'}
            </p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            {connected && (
              <div style={{
                display: 'flex', alignItems: 'center', gap: 6,
                padding: '6px 14px', borderRadius: 20,
                background: 'rgba(16, 185, 129, 0.1)',
                border: '1px solid rgba(16, 185, 129, 0.2)',
                fontSize: 12, fontWeight: 500, color: 'var(--accent-green)',
              }}>
                <Wifi size={13} />
                Backend Connected
              </div>
            )}
            {connected === false && (
              <div style={{
                display: 'flex', alignItems: 'center', gap: 6,
                padding: '6px 14px', borderRadius: 20,
                background: 'rgba(239, 68, 68, 0.1)',
                border: '1px solid rgba(239, 68, 68, 0.2)',
                fontSize: 12, fontWeight: 500, color: 'var(--accent-red)',
              }}>
                <WifiOff size={13} />
                Disconnected
              </div>
            )}
          </div>
        </header>

        {/* Content */}
        <main style={{ flex: 1, overflow: 'auto', padding: '24px 32px 32px' }}>

          {/* ===== DASHBOARD ===== */}
          {tab === 'dashboard' && (
            <div className="animate-fade-in">
              {stats ? (
                <>
                  {/* Stats Cards */}
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 24 }}>
                    <StatCard label="Total Scans" value={stats.total_scans} color="#3b82f6" icon={<Scan size={20} />} gradient="linear-gradient(135deg, rgba(59,130,246,0.12), rgba(6,182,212,0.08))" />
                    <StatCard label="Phishing" value={stats.phishing_count} color="#ef4444" icon={<XCircle size={20} />} gradient="linear-gradient(135deg, rgba(239,68,68,0.12), rgba(249,115,22,0.08))" />
                    <StatCard label="Suspicious" value={stats.suspicious_count} color="#f59e0b" icon={<AlertTriangle size={20} />} gradient="linear-gradient(135deg, rgba(245,158,11,0.12), rgba(249,115,22,0.08))" />
                    <StatCard label="Safe" value={stats.safe_count} color="#10b981" icon={<CheckCircle2 size={20} />} gradient="linear-gradient(135deg, rgba(16,185,129,0.12), rgba(6,182,212,0.08))" />
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
                    {/* Risk Distribution */}
                    <div className="glass-card" style={{ padding: 24 }}>
                      <h3 style={{ fontSize: 16, fontWeight: 700, color: 'white', marginBottom: 20 }}>
                        Risk Distribution
                      </h3>
                      {stats.total_scans === 0 ? (
                        <p style={{ color: 'var(--text-muted)' }}>No scans yet. Use the Scanner to analyze URLs or messages.</p>
                      ) : (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                          <DistributionBar label="Safe" count={stats.safe_count} total={stats.total_scans} color="#10b981" />
                          <DistributionBar label="Suspicious" count={stats.suspicious_count} total={stats.total_scans} color="#f59e0b" />
                          <DistributionBar label="Phishing" count={stats.phishing_count} total={stats.total_scans} color="#ef4444" />
                          <div style={{ paddingTop: 16, borderTop: '1px solid var(--border-subtle)', marginTop: 4 }}>
                            <p style={{ fontSize: 13, color: 'var(--text-secondary)' }}>
                              Average Risk Score: <span style={{ fontWeight: 700, color: 'white' }}>{stats.average_risk_score}%</span>
                            </p>
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Recent Scans */}
                    <div className="glass-card" style={{ padding: 24 }}>
                      <h3 style={{ fontSize: 16, fontWeight: 700, color: 'white', marginBottom: 20 }}>
                        Recent Scans
                      </h3>
                      {stats.recent_scans.length === 0 ? (
                        <p style={{ color: 'var(--text-muted)' }}>No recent scans.</p>
                      ) : (
                        <div style={{ display: 'flex', alignItems: 'flex-end', gap: 6, height: 140 }}>
                          {stats.recent_scans.slice().reverse().map((scan, i) => (
                            <div key={i} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6 }}>
                              <div style={{
                                width: '100%', borderRadius: '6px 6px 0 0',
                                height: `${Math.max(8, scan.risk_score * 1.2)}%`,
                                background: classColor(scan.classification),
                                opacity: 0.75,
                                minHeight: 6,
                                transition: 'all 0.3s ease',
                              }} />
                              <span style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 600 }}>{scan.risk_score}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                </>
              ) : (
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 300 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, color: 'var(--text-muted)' }}>
                    <Activity size={18} className="animate-spin" style={{ animationDuration: '2s' }} />
                    Loading statistics...
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ===== SCANNER ===== */}
          {tab === 'scanner' && (
            <div className="animate-fade-in">
              {/* Mode Toggle */}
              <div style={{ display: 'flex', gap: 8, marginBottom: 24, flexWrap: 'wrap' }}>
                <button
                  id="scan-mode-url"
                  onClick={() => { setScanMode('url'); setResult(null); setScanError(''); setSelectedFile(null); setFilePreview(null); }}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 8,
                    padding: '10px 22px', borderRadius: 12, border: 'none', cursor: 'pointer',
                    fontSize: 14, fontWeight: 600,
                    background: scanMode === 'url' ? 'var(--gradient-blue)' : 'var(--bg-card)',
                    color: scanMode === 'url' ? 'white' : 'var(--text-secondary)',
                    boxShadow: scanMode === 'url' ? '0 4px 16px rgba(59,130,246,0.3)' : 'none',
                    ...(scanMode !== 'url' ? { border: '1px solid var(--border-color)' } : {}),
                  }}
                >
                  <Globe size={16} />
                  URL Scanner
                </button>
                <button
                  id="scan-mode-message"
                  onClick={() => { setScanMode('message'); setResult(null); setScanError(''); setSelectedFile(null); setFilePreview(null); }}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 8,
                    padding: '10px 22px', borderRadius: 12, border: 'none', cursor: 'pointer',
                    fontSize: 14, fontWeight: 600,
                    background: scanMode === 'message' ? 'var(--gradient-blue)' : 'var(--bg-card)',
                    color: scanMode === 'message' ? 'white' : 'var(--text-secondary)',
                    boxShadow: scanMode === 'message' ? '0 4px 16px rgba(59,130,246,0.3)' : 'none',
                    ...(scanMode !== 'message' ? { border: '1px solid var(--border-color)' } : {}),
                  }}
                >
                  <MessageSquare size={16} />
                  Message Scanner
                </button>
                <button
                  id="scan-mode-qr"
                  onClick={() => { setScanMode('qr'); setResult(null); setScanError(''); setSelectedFile(null); setFilePreview(null); }}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 8,
                    padding: '10px 22px', borderRadius: 12, border: 'none', cursor: 'pointer',
                    fontSize: 14, fontWeight: 600,
                    background: scanMode === 'qr' ? 'var(--gradient-blue)' : 'var(--bg-card)',
                    color: scanMode === 'qr' ? 'white' : 'var(--text-secondary)',
                    boxShadow: scanMode === 'qr' ? '0 4px 16px rgba(59,130,246,0.3)' : 'none',
                    ...(scanMode !== 'qr' ? { border: '1px solid var(--border-color)' } : {}),
                  }}
                >
                  <QrCode size={16} />
                  QR Scanner
                </button>
                <button
                  id="scan-mode-screenshot"
                  onClick={() => { setScanMode('screenshot'); setResult(null); setScanError(''); setSelectedFile(null); setFilePreview(null); }}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 8,
                    padding: '10px 22px', borderRadius: 12, border: 'none', cursor: 'pointer',
                    fontSize: 14, fontWeight: 600,
                    background: scanMode === 'screenshot' ? 'var(--gradient-blue)' : 'var(--bg-card)',
                    color: scanMode === 'screenshot' ? 'white' : 'var(--text-secondary)',
                    boxShadow: scanMode === 'screenshot' ? '0 4px 16px rgba(59,130,246,0.3)' : 'none',
                    ...(scanMode !== 'screenshot' ? { border: '1px solid var(--border-color)' } : {}),
                  }}
                >
                  <ImageIcon size={16} />
                  Screenshot Scanner
                </button>
              </div>

              {/* Input Card */}
              <div className="glass-card" style={{ padding: 28, marginBottom: 24 }}>
                {scanMode === 'url' ? (
                  <div>
                    <label style={{ display: 'block', fontSize: 14, fontWeight: 600, color: 'white', marginBottom: 10 }}>
                      <Search size={14} style={{ display: 'inline', marginRight: 6, verticalAlign: -2 }} />
                      Enter URL to analyze
                    </label>
                    <input
                      id="url-input"
                      type="text"
                      value={urlInput}
                      onChange={(e) => setUrlInput(e.target.value)}
                      onKeyDown={(e) => e.key === 'Enter' && handleScan()}
                      placeholder="https://example.com/suspicious-page"
                      style={{
                        width: '100%', padding: '14px 18px', borderRadius: 12, fontSize: 14,
                        background: 'var(--bg-primary)', border: '1px solid var(--border-color)',
                        color: 'var(--text-primary)', outline: 'none',
                      }}
                    />
                    {/* Example URL chips */}
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: 14 }}>
                      <span style={{ fontSize: 12, color: 'var(--text-muted)', lineHeight: '28px' }}>Try:</span>
                      {EXAMPLE_URLS.map((url) => (
                        <button
                          key={url}
                          onClick={() => setUrlInput(url)}
                          style={{
                            padding: '4px 14px', borderRadius: 8, border: '1px solid var(--border-color)',
                            background: 'var(--bg-primary)', color: 'var(--accent-cyan)',
                            fontSize: 12, cursor: 'pointer', fontFamily: 'monospace',
                          }}
                        >
                          {url}
                        </button>
                      ))}
                    </div>
                  </div>
                ) : scanMode === 'message' ? (
                  <div>
                    <label style={{ display: 'block', fontSize: 14, fontWeight: 600, color: 'white', marginBottom: 10 }}>
                      <FileText size={14} style={{ display: 'inline', marginRight: 6, verticalAlign: -2 }} />
                      Enter message or email to analyze
                    </label>
                    <textarea
                      id="message-input"
                      value={messageInput}
                      onChange={(e) => setMessageInput(e.target.value)}
                      placeholder="Paste the suspicious email or message content here..."
                      rows={6}
                      style={{
                        width: '100%', padding: '14px 18px', borderRadius: 12, fontSize: 14,
                        background: 'var(--bg-primary)', border: '1px solid var(--border-color)',
                        color: 'var(--text-primary)', outline: 'none', resize: 'vertical',
                        fontFamily: "'Inter', sans-serif",
                      }}
                    />
                  </div>
                ) : (
                  <div>
                    <label style={{ display: 'block', fontSize: 14, fontWeight: 600, color: 'white', marginBottom: 10 }}>
                      {scanMode === 'qr' ? <QrCode size={14} style={{ display: 'inline', marginRight: 6, verticalAlign: -2 }} /> : <ImageIcon size={14} style={{ display: 'inline', marginRight: 6, verticalAlign: -2 }} />}
                      Upload {scanMode === 'qr' ? 'QR Code Image' : 'Screenshot Image'} to analyze
                    </label>

                    <input
                      ref={fileInputRef}
                      type="file"
                      accept="image/*"
                      onChange={(e) => handleFileChange(e.target.files?.[0] || null)}
                      style={{ display: 'none' }}
                    />

                    {scanMode === 'qr' && (
                      <div style={{ display: 'flex', gap: 10, marginBottom: 14 }}>
                        {!cameraActive ? (
                          <button type="button" onClick={startCamera} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '9px 14px', borderRadius: 10, border: '1px solid var(--border-color)', background: 'var(--bg-primary)', color: 'var(--text-primary)', cursor: 'pointer' }}>
                            <Camera size={15} /> Start camera
                          </button>
                        ) : (
                          <>
                            <button type="button" onClick={() => captureCameraFrame()} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '9px 14px', borderRadius: 10, border: 'none', background: 'var(--gradient-blue)', color: 'white', cursor: 'pointer' }}>
                              <Camera size={15} /> Capture frame
                            </button>
                            <button type="button" onClick={stopCamera} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '9px 14px', borderRadius: 10, border: '1px solid var(--border-color)', background: 'var(--bg-primary)', color: 'var(--text-secondary)', cursor: 'pointer' }}>
                              <Square size={14} /> Stop
                            </button>
                          </>
                        )}
                      </div>
                    )}

                    {cameraActive && (
                      <video ref={videoRef} autoPlay playsInline style={{ width: '100%', maxHeight: 260, objectFit: 'cover', borderRadius: 12, marginBottom: 14, border: '1px solid var(--border-color)' }} />
                    )}

                    <div
                      onClick={() => fileInputRef.current?.click()}
                      onDragOver={(event) => event.preventDefault()}
                      onDrop={handleDrop}
                      style={{
                        border: '2px dashed var(--border-color)',
                        borderRadius: 14,
                        padding: '36px 20px',
                        textAlign: 'center',
                        cursor: 'pointer',
                        background: 'var(--bg-primary)',
                        transition: 'border-color 0.2s ease',
                      }}
                    >
                      {filePreview ? (
                        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12 }}>
                          <img
                            src={filePreview}
                            alt="Uploaded preview"
                            style={{ maxHeight: 180, borderRadius: 10, border: '1px solid var(--border-color)' }}
                          />
                          <span style={{ fontSize: 13, color: 'var(--accent-blue)', fontWeight: 600 }}>
                            {selectedFile?.name} ({((selectedFile?.size || 0) / 1024).toFixed(1)} KB) — Click to change file
                          </span>
                        </div>
                      ) : (
                        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 10 }}>
                          <Upload size={32} color="var(--accent-blue)" />
                          <p style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
                            Click or drag and drop to upload {scanMode === 'qr' ? 'a QR Code image' : 'a screenshot'}
                          </p>
                          <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: 0 }}>
                            Supports PNG, JPG, JPEG, WEBP (Max 10MB). You can also paste an image.
                          </p>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {scanError && (
                  <div style={{
                    marginTop: 14, padding: '10px 16px', borderRadius: 10, fontSize: 13,
                    background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.25)',
                    color: 'var(--accent-red)',
                  }}>
                    {scanError}
                  </div>
                )}

                <button
                  id="analyze-button"
                  onClick={handleScan}
                  disabled={scanning}
                  style={{
                    marginTop: 18, padding: '12px 28px', borderRadius: 12, border: 'none',
                    fontSize: 14, fontWeight: 700, color: 'white', cursor: scanning ? 'not-allowed' : 'pointer',
                    background: scanning ? 'var(--bg-card)' : 'var(--gradient-blue)',
                    opacity: scanning ? 0.6 : 1,
                    display: 'flex', alignItems: 'center', gap: 8,
                    boxShadow: scanning ? 'none' : '0 4px 16px rgba(59,130,246,0.3)',
                  }}
                >
                  <Scan size={16} className={scanning ? 'animate-spin' : ''} />
                  {scanning ? 'Analyzing...' : 'Analyze'}
                </button>
              </div>

              {/* Results */}
              {result && (
                <div className="animate-fade-in-up">
                  {/* Two Column Layout: Risk Result + Threat Indicators */}
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, marginBottom: 20 }}>
                    {/* LEFT: Risk Result Card */}
                    <div className="glass-card" style={{
                      padding: 28,
                      borderColor: classColor(result.classification),
                      borderWidth: 2,
                      background: classBg(result.classification),
                    }}>
                      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 20 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                          {classIcon(result.classification)}
                          <div>
                            <h3 style={{
                              fontSize: 22, fontWeight: 800, letterSpacing: '-0.02em',
                              color: classColor(result.classification),
                            }}>
                              {classLabel(result.classification)}
                            </h3>
                            <p style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
                              Scan #{result.scan_id} • {result.input_type.toUpperCase()} Analysis
                            </p>
                          </div>
                        </div>
                        <div style={{ textAlign: 'right' }}>
                          <p style={{ fontSize: 36, fontWeight: 800, color: classColor(result.classification), lineHeight: 1 }}>
                            {result.risk_score}
                          </p>
                          <p style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 500 }}>Risk Score</p>
                        </div>
                      </div>

                      {/* Risk Meter */}
                      <div style={{ marginBottom: 20 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, marginBottom: 6, color: 'var(--text-muted)' }}>
                          <span>Safe (0–30)</span>
                          <span>Suspicious (31–60)</span>
                          <span>Phishing (61–100)</span>
                        </div>
                        <div style={{
                          width: '100%', height: 10, borderRadius: 6,
                          background: 'rgba(30, 41, 59, 0.6)', overflow: 'hidden',
                          position: 'relative',
                        }}>
                          <div className="risk-meter-gradient" style={{
                            height: '100%', borderRadius: 6,
                            width: `${result.risk_score}%`,
                            animation: 'risk-meter-fill 1s ease-out',
                          }} />
                        </div>
                      </div>

                      {/* ML Probability */}
                      <div style={{
                        display: 'inline-flex', alignItems: 'center', gap: 8,
                        padding: '8px 16px', borderRadius: 10,
                        background: 'rgba(59,130,246,0.1)', border: '1px solid rgba(59,130,246,0.2)',
                      }}>
                        <Brain size={14} color="var(--accent-blue)" />
                        <span style={{ fontSize: 13, color: 'var(--text-muted)' }}>ML Probability:</span>
                        <span style={{ fontSize: 14, fontWeight: 700, color: 'var(--accent-blue)' }}>
                          {(result.ml_probability * 100).toFixed(1)}%
                        </span>
                      </div>
                    </div>

                    {/* RIGHT: Threat Indicators */}
                    <div className="glass-card" style={{ padding: 28 }}>
                      <h4 style={{ fontSize: 15, fontWeight: 700, color: 'white', marginBottom: 16, display: 'flex', alignItems: 'center', gap: 8 }}>
                        <ShieldAlert size={16} color="var(--accent-yellow)" />
                        Threat Indicators
                        {result.indicators.length > 0 && (
                          <span style={{
                            fontSize: 11, fontWeight: 700, padding: '2px 10px', borderRadius: 20,
                            background: 'rgba(239,68,68,0.15)', color: 'var(--accent-red)',
                          }}>
                            {result.indicators.length}
                          </span>
                        )}
                      </h4>
                      {result.indicators.length > 0 ? (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxHeight: 240, overflowY: 'auto' }}>
                          {result.indicators.map((ind, i) => (
                            <div key={i} style={{
                              display: 'flex', alignItems: 'flex-start', gap: 10,
                              padding: '10px 14px', borderRadius: 10, fontSize: 13,
                              background: 'rgba(239,68,68,0.06)',
                              border: '1px solid rgba(239,68,68,0.12)',
                            }}>
                              <AlertTriangle size={14} style={{ marginTop: 2, flexShrink: 0, color: 'var(--accent-yellow)' }} />
                              <span style={{ color: 'var(--text-primary)' }}>{ind}</span>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: 16, color: 'var(--text-muted)' }}>
                          <CheckCircle2 size={18} color="var(--accent-green)" />
                          No threat indicators detected
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Score Breakdown Cards */}
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 20 }}>
                    {[
                      { label: 'ML Model', value: result.score_breakdown.ml_component, color: '#8b5cf6', icon: <Brain size={18} /> },
                      { label: 'URL Indicators', value: result.score_breakdown.url_component, color: '#3b82f6', icon: <Globe size={18} /> },
                      { label: 'Content Analysis', value: result.score_breakdown.content_component, color: '#06b6d4', icon: <FileText size={18} /> },
                      { label: 'Behavioral', value: result.score_breakdown.behavioral_component, color: '#f59e0b', icon: <Activity size={18} /> },
                    ].map((item) => (
                      <div key={item.label} className="glass-card" style={{ padding: 20, textAlign: 'center' }}>
                        <div style={{
                          width: 40, height: 40, borderRadius: 12, margin: '0 auto 12px',
                          display: 'flex', alignItems: 'center', justifyContent: 'center',
                          background: `${item.color}18`, color: item.color,
                        }}>
                          {item.icon}
                        </div>
                        <p style={{ fontSize: 24, fontWeight: 800, color: item.color, marginBottom: 4 }}>
                          {item.value.toFixed(1)}
                        </p>
                        <p style={{ fontSize: 12, color: 'var(--text-muted)', fontWeight: 500 }}>{item.label}</p>
                      </div>
                    ))}
                  </div>

                  {/* Analysis Explanation */}
                  {(result.payload || result.extracted_text || result.extracted_urls.length > 0) && (
                    <div className="glass-card" style={{ padding: 24, marginBottom: 20 }}>
                      <h4 style={{ fontSize: 15, fontWeight: 700, color: 'white', marginBottom: 12 }}>
                        Extracted content
                      </h4>
                      {result.payload && <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 8 }}>QR payload ({result.payload_type}): {result.payload}</p>}
                      {result.extracted_urls.length > 0 && <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 8 }}>URLs: {result.extracted_urls.join(', ')}</p>}
                      {result.extracted_text && <pre style={{ whiteSpace: 'pre-wrap', fontFamily: 'inherit', fontSize: 13, color: 'var(--text-secondary)', maxHeight: 180, overflow: 'auto' }}>{result.extracted_text}</pre>}
                    </div>
                  )}

                  {/* Analysis Explanation */}
                  <div className="glass-card" style={{ padding: 24, marginBottom: 20 }}>
                    <h4 style={{ fontSize: 15, fontWeight: 700, color: 'white', marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
                      <Eye size={16} color="var(--accent-cyan)" />
                      Analysis Explanation
                    </h4>
                    <p style={{ fontSize: 14, color: 'var(--text-secondary)', lineHeight: 1.7 }}>
                      {result.explanation}
                    </p>
                  </div>

                  {/* Recommended Actions */}
                  <div className="glass-card" style={{ padding: 24 }}>
                    <h4 style={{ fontSize: 15, fontWeight: 700, color: 'white', marginBottom: 14, display: 'flex', alignItems: 'center', gap: 8 }}>
                      <Lock size={16} color="var(--accent-green)" />
                      Recommended Actions
                    </h4>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                      {result.recommendations.map((rec, i) => (
                        <div key={i} style={{
                          display: 'flex', alignItems: 'flex-start', gap: 10,
                          padding: '10px 14px', borderRadius: 10, fontSize: 13,
                          background: 'rgba(16,185,129,0.06)',
                          border: '1px solid rgba(16,185,129,0.12)',
                        }}>
                          <CheckCircle2 size={14} style={{ marginTop: 2, flexShrink: 0, color: 'var(--accent-green)' }} />
                          <span style={{ color: 'var(--text-primary)' }}>{rec}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Why Was This Detected? Section */}
                  <ThreatExplanation result={result} />
                </div>
              )}

              {/* Feature Cards (shown when no result) */}
              {!result && !scanning && (
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginTop: 16 }}>
                  {[
                    { icon: <Brain size={24} />, title: 'AI-Powered', desc: 'Machine learning models detect sophisticated threats', color: '#8b5cf6' },
                    { icon: <Zap size={24} />, title: 'Real-time Analysis', desc: 'Instantly analyze URLs and messages', color: '#3b82f6' },
                    { icon: <Eye size={24} />, title: 'Detailed Insights', desc: 'Get explainable results with threat indicators', color: '#06b6d4' },
                    { icon: <Lock size={24} />, title: 'Stay Protected', desc: 'Build safer digital habits', color: '#10b981' },
                  ].map((item) => (
                    <div key={item.title} className="glass-card" style={{ padding: 24, textAlign: 'center' }}>
                      <div style={{
                        width: 52, height: 52, borderRadius: 14, margin: '0 auto 16px',
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        background: `${item.color}15`, color: item.color,
                      }}>
                        {item.icon}
                      </div>
                      <h4 style={{ fontSize: 15, fontWeight: 700, color: 'white', marginBottom: 8 }}>{item.title}</h4>
                      <p style={{ fontSize: 13, color: 'var(--text-muted)', lineHeight: 1.5 }}>{item.desc}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* ===== HISTORY ===== */}
          {tab === 'history' && (
            <div className="animate-fade-in">
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
                <p style={{ fontSize: 13, color: 'var(--text-muted)' }}>
                  {history.length} scan{history.length !== 1 ? 's' : ''} recorded
                </p>
                <button
                  id="refresh-history"
                  onClick={loadHistory}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 6,
                    padding: '8px 16px', borderRadius: 10, fontSize: 13, fontWeight: 600,
                    background: 'var(--bg-card)', border: '1px solid var(--border-color)',
                    color: 'var(--text-secondary)', cursor: 'pointer',
                  }}
                >
                  <RefreshCw size={14} />
                  Refresh
                </button>
              </div>

              {history.length === 0 ? (
                <div className="glass-card" style={{ padding: 48, textAlign: 'center' }}>
                  <History size={48} style={{ color: 'var(--border-color)', margin: '0 auto 16px' }} />
                  <p style={{ color: 'var(--text-muted)', fontSize: 14 }}>
                    No scan history yet. Use the Scanner to analyze URLs or messages.
                  </p>
                </div>
              ) : (
                <div className="glass-card" style={{ overflow: 'hidden' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                    <thead>
                      <tr style={{ background: 'rgba(6, 10, 20, 0.6)' }}>
                        <th style={{ padding: '14px 18px', textAlign: 'left', fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Time</th>
                        <th style={{ padding: '14px 18px', textAlign: 'left', fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Type</th>
                        <th style={{ padding: '14px 18px', textAlign: 'left', fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Input</th>
                        <th style={{ padding: '14px 18px', textAlign: 'left', fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Classification</th>
                        <th style={{ padding: '14px 18px', textAlign: 'left', fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Risk Score</th>
                      </tr>
                    </thead>
                    <tbody>
                      {history.map((item) => (
                        <tr key={item.id} style={{ borderTop: '1px solid var(--border-subtle)' }}>
                          <td style={{ padding: '14px 18px', fontSize: 13, color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>
                            {new Date(item.timestamp).toLocaleString()}
                          </td>
                          <td style={{ padding: '14px 18px' }}>
                            <span style={{
                              padding: '3px 10px', borderRadius: 6, fontSize: 11, fontWeight: 600,
                              background: 'rgba(59,130,246,0.12)', color: 'var(--accent-blue)',
                            }}>
                              {item.input_type.toUpperCase()}
                            </span>
                          </td>
                          <td style={{ padding: '14px 18px', fontSize: 13, color: 'var(--text-primary)', maxWidth: 320, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {item.input_text}
                          </td>
                          <td style={{ padding: '14px 18px' }}>
                            <span className={`badge badge-${item.classification.toLowerCase()}`}>
                              {item.classification}
                            </span>
                          </td>
                          <td style={{ padding: '14px 18px', fontSize: 14, fontWeight: 700, color: classColor(item.classification) }}>
                            {item.risk_score}%
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* ===== ABOUT ===== */}
          {tab === 'about' && (
            <div className="animate-fade-in">
              <div className="glass-card" style={{ padding: 32, marginBottom: 24 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 20 }}>
                  <div style={{
                    width: 56, height: 56, borderRadius: 16,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    background: 'var(--gradient-blue)',
                    boxShadow: '0 4px 20px rgba(59, 130, 246, 0.3)',
                  }}>
                    <Shield size={28} color="white" />
                  </div>
                  <div>

                  <button
                    type="button"
                    onClick={resetScanner}
                    style={{ marginTop: 16, display: 'flex', alignItems: 'center', gap: 8, padding: '11px 18px', borderRadius: 10, border: '1px solid var(--border-color)', background: 'var(--bg-card)', color: 'var(--text-primary)', cursor: 'pointer', fontWeight: 600 }}
                  >
                    <RefreshCw size={15} /> Scan Again
                  </button>
                    <h3 style={{ fontSize: 22, fontWeight: 800, color: 'white' }}>PhishGuard AI</h3>
                    <p style={{ fontSize: 13, color: 'var(--text-muted)' }}>AI-Based Multi-Layer Phishing Detection System</p>
                  </div>
                </div>
                <p style={{ fontSize: 14, color: 'var(--text-secondary)', lineHeight: 1.8, maxWidth: 700 }}>
                  PhishGuard AI uses advanced machine learning models and multi-layer heuristic analysis
                  to detect phishing threats in URLs and messages. The system provides explainable risk
                  assessments with detailed threat indicators, behavioral analysis, and actionable
                  security recommendations.
                </p>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16 }}>
                {[
                  { icon: <Brain size={22} />, title: 'ML Detection', desc: 'Random Forest classifiers trained on real phishing datasets for URL and message analysis', color: '#8b5cf6' },
                  { icon: <TrendingUp size={22} />, title: 'Multi-Layer Analysis', desc: 'URL heuristics, content pattern matching, behavioral detection, and ML probability fusion', color: '#3b82f6' },
                  { icon: <Eye size={22} />, title: 'Explainable Results', desc: 'Transparent score breakdowns, threat indicators, and actionable security recommendations', color: '#06b6d4' },
                ].map((item) => (
                  <div key={item.title} className="glass-card" style={{ padding: 24 }}>
                    <div style={{
                      width: 44, height: 44, borderRadius: 12, marginBottom: 16,
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      background: `${item.color}15`, color: item.color,
                    }}>
                      {item.icon}
                    </div>
                    <h4 style={{ fontSize: 15, fontWeight: 700, color: 'white', marginBottom: 8 }}>{item.title}</h4>
                    <p style={{ fontSize: 13, color: 'var(--text-muted)', lineHeight: 1.6 }}>{item.desc}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </main>

        {/* Footer */}
        <footer style={{
          padding: '12px 32px',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          borderTop: '1px solid var(--border-subtle)',
          background: 'var(--bg-secondary)',
          fontSize: 12, color: 'var(--text-muted)',
        }}>
          <span>PhishGuard AI v1.0</span>
          <span>Cybersecurity for a Safer Tomorrow</span>
        </footer>
      </div>
    </div>
  );
}

/* ---- Sub-components ---- */

function StatCard({ label, value, color, icon, gradient }: {
  label: string; value: number; color: string; icon: React.ReactNode; gradient: string;
}) {
  return (
    <div className="glass-card animate-fade-in-up" style={{ padding: 22, background: gradient }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
        <span style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-secondary)' }}>{label}</span>
        <div style={{
          width: 36, height: 36, borderRadius: 10,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          background: `${color}20`, color,
        }}>
          {icon}
        </div>
      </div>
      <p style={{ fontSize: 32, fontWeight: 800, color, letterSpacing: '-0.02em' }}>{value}</p>
    </div>
  );
}

function DistributionBar({ label, count, total, color }: {
  label: string; count: number; total: number; color: string;
}) {
  const pct = total > 0 ? (count / total) * 100 : 0;
  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13, marginBottom: 6 }}>
        <span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{label}</span>
        <span style={{ color: 'var(--text-muted)' }}>{count} ({pct.toFixed(0)}%)</span>
      </div>
      <div style={{ width: '100%', height: 8, borderRadius: 4, background: 'rgba(30, 41, 59, 0.6)' }}>
        <div style={{
          height: '100%', borderRadius: 4, background: color,
          width: `${pct}%`, transition: 'width 0.7s ease',
        }} />
      </div>
    </div>
  );
}
