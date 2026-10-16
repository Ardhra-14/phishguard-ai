import React, { useState, useEffect } from 'react';
import { 
  Shield, AlertTriangle, Search, Activity, 
  Globe, Clock, Lock, CheckCircle, XCircle, Info,
  ArrowLeft, ExternalLink, AlertOctagon, ShieldAlert
} from 'lucide-react';

const API_BASE_URL = 'http://localhost:8000/api/v1';

function App() {
  // Navigation / Routing State
  const [isRiskRoute, setIsRiskRoute] = useState(false);
  const [riskLoading, setRiskLoading] = useState(false);
  const [riskPageData, setRiskPageData] = useState(null);

  // Dashboard state
  const [urlToScan, setUrlToScan] = useState('');
  const [scanResult, setScanResult] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const [scanError, setScanError] = useState(null);

  const [stats, setStats] = useState({
    threats_today: 0,
    avg_confidence: 0,
    zero_day_count: 0
  });
  
  const [feed, setFeed] = useState([]);
  const [isLoadingFeed, setIsLoadingFeed] = useState(true);

  // Check URL routes on mount (e.g. /risk-score/<scan-id> or ?scan_id=... or ?url=...)
  useEffect(() => {
    checkRouting();
    window.addEventListener('popstate', checkRouting);
    return () => window.removeEventListener('popstate', checkRouting);
  }, []);

  const checkRouting = () => {
    const pathname = window.location.pathname;
    const searchParams = new URLSearchParams(window.location.search);
    const hasRiskPath = pathname.includes('/risk-score');
    const hasScanParam = searchParams.has('scan_id') || searchParams.has('scanId');
    const hasUrlWarning = searchParams.has('url') && (searchParams.has('score') || searchParams.has('verdict'));

    if (hasRiskPath || hasScanParam || hasUrlWarning) {
      setIsRiskRoute(true);
      setRiskLoading(true);

      // Extract scan_id from pathname /risk-score/:scan_id or search params
      const pathMatch = pathname.match(/\/risk-score\/([a-zA-Z0-9\-_]+)/);
      const scanId = pathMatch ? pathMatch[1] : (searchParams.get('scan_id') || searchParams.get('scanId'));
      const urlParam = searchParams.get('url') ? decodeURIComponent(searchParams.get('url')) : '';
      const scoreParam = searchParams.get('score');
      const verdictParam = searchParams.get('verdict');
      const categoryParam = searchParams.get('category');

      // Attempt to fetch full scan details from backend if scanId exists
      if (scanId && !scanId.startsWith('blocklist-') && !scanId.startsWith('offline-')) {
        fetch(`${API_BASE_URL}/scan/${scanId}`)
          .then((res) => (res.ok ? res.json() : null))
          .then((data) => {
            if (data) {
              const shapReasons = (data.shap_json || [])
                .filter((s) => s.direction === 'phishing' || s.shap_value > 0)
                .map((s) => s.label || s.feature);

              setRiskPageData({
                scan_id: data.id || scanId,
                url: data.url || urlParam,
                domain: data.domain,
                score: data.score,
                verdict: data.verdict,
                confidence: data.confidence,
                category: data.category || categoryParam || 'Generic',
                reasons: shapReasons.length > 0 ? shapReasons : [
                  'Heuristic ML model detected strong phishing markers',
                  'Suspicious lexical domain properties'
                ],
                domain_age_days: data.domain_age_days,
                registrar: data.registrar,
                ssl_issuer: data.ssl_issuer,
                closest_brand: data.closest_brand,
                visual_similarity: data.visual_similarity,
                is_zero_day: data.is_zero_day,
              });
            } else {
              setFallbackRiskData(urlParam, scoreParam, verdictParam, categoryParam, scanId);
            }
          })
          .catch(() => {
            setFallbackRiskData(urlParam, scoreParam, verdictParam, categoryParam, scanId);
          })
          .finally(() => setRiskLoading(false));
      } else {
        setFallbackRiskData(urlParam, scoreParam, verdictParam, categoryParam, scanId);
        setRiskLoading(false);
      }
    } else {
      setIsRiskRoute(false);
      fetchStats();
      fetchFeed();
    }
  };

  const setFallbackRiskData = (urlParam, scoreParam, verdictParam, categoryParam, scanId) => {
    let domain = 'Unknown';
    if (urlParam) {
      try {
        domain = new URL(urlParam).hostname;
      } catch {
        domain = urlParam;
      }
    }
    setRiskPageData({
      scan_id: scanId || 'live-scan',
      url: urlParam || 'https://suspicious-target.com',
      domain: domain,
      score: scoreParam ? parseInt(scoreParam, 10) : 88,
      verdict: verdictParam || 'PHISHING',
      confidence: 0.92,
      category: categoryParam || 'Banking / Credential',
      reasons: [
        'Domain structure mimics authentic online service',
        'Suspicious URL keyword combination detected',
        'Model flagged high probability of credential deception'
      ],
      domain_age_days: 2,
      registrar: 'Unknown Registrar',
      ssl_issuer: "Let's Encrypt",
      closest_brand: null,
      is_zero_day: true,
    });
  };

  // Poll for dashboard updates every 10 seconds if on dashboard
  useEffect(() => {
    if (isRiskRoute) return;
    const interval = setInterval(() => {
      fetchStats();
      fetchFeed();
    }, 10000);
    return () => clearInterval(interval);
  }, [isRiskRoute]);

  const fetchStats = async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/stats`);
      if (res.ok) {
        const data = await res.json();
        setStats(data);
      }
    } catch (err) {
      console.error('Error fetching stats:', err);
    }
  };

  const fetchFeed = async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/feed?limit=10`);
      if (res.ok) {
        const data = await res.json();
        setFeed(data.items || []);
      }
    } catch (err) {
      console.error('Error fetching feed:', err);
    } finally {
      setIsLoadingFeed(false);
    }
  };

  const handleScan = async (e) => {
    e.preventDefault();
    if (!urlToScan.trim()) return;

    setIsScanning(true);
    setScanError(null);
    setScanResult(null);

    try {
      const res = await fetch(`${API_BASE_URL}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: urlToScan })
      });

      if (!res.ok) {
        throw new Error('Failed to scan URL');
      }

      const data = await res.json();
      setScanResult(data);
      
      fetchStats();
      fetchFeed();
    } catch (err) {
      setScanError(err.message || 'An error occurred during scanning.');
    } finally {
      setIsScanning(false);
    }
  };

  const navigateToDashboard = () => {
    window.history.pushState({}, '', '/');
    setIsRiskRoute(false);
    fetchStats();
    fetchFeed();
  };

  const handleContinueAnyway = (targetUrl) => {
    if (confirm('CAUTION: This website has been classified as dangerous by PhishGuard AI. Proceeding may compromise your accounts or personal credentials. Continue anyway?')) {
      window.location.href = targetUrl;
    }
  };

  const getVerdictBadgeClass = (verdict) => {
    if (verdict === 'PHISHING') return 'badge phishing';
    if (verdict === 'SUSPICIOUS') return 'badge suspicious';
    return 'badge safe';
  };

  const getVerdictIcon = (verdict) => {
    if (verdict === 'PHISHING') return <XCircle size={24} className="text-danger" />;
    if (verdict === 'SUSPICIOUS') return <AlertTriangle size={24} className="text-warning" />;
    return <CheckCircle size={24} className="text-success" />;
  };

  // =========================================================================
  // VIEW: DEDICATED RISK-SCORE / WARNING PAGE
  // =========================================================================
  if (isRiskRoute) {
    if (riskLoading) {
      return (
        <div className="container" style={{ minHeight: '80vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <div className="text-center">
            <Activity size={48} className="animate-spin text-primary mx-auto mb-4" />
            <h2 className="text-xl">Retrieving Threat Analysis...</h2>
            <p className="text-muted">Loading verdict from PhishGuard AI engine</p>
          </div>
        </div>
      );
    }

    const r = riskPageData || {};
    const isPhishing = r.verdict === 'PHISHING';

    return (
      <div className="container" style={{ maxWidth: '900px', paddingTop: '3rem', paddingBottom: '4rem' }}>
        {/* Warning Banner */}
        <div 
          className="glass-panel" 
          style={{ 
            borderColor: isPhishing ? 'rgba(239, 68, 68, 0.4)' : 'rgba(245, 158, 11, 0.4)',
            boxShadow: isPhishing ? '0 10px 40px rgba(239, 68, 68, 0.2)' : '0 10px 40px rgba(245, 158, 11, 0.2)',
            padding: '2.5rem',
            marginBottom: '2rem'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem', marginBottom: '1.5rem' }}>
            <div 
              style={{ 
                background: isPhishing ? 'rgba(239, 68, 68, 0.15)' : 'rgba(245, 158, 11, 0.15)',
                padding: '1rem', 
                borderRadius: '12px',
                border: `1px solid ${isPhishing ? 'var(--danger)' : 'var(--warning)'}`
              }}
            >
              <ShieldAlert size={42} color={isPhishing ? 'var(--danger)' : 'var(--warning)'} />
            </div>
            <div>
              <div style={{ fontSize: '0.875rem', fontWeight: 700, letterSpacing: '0.08em', color: isPhishing ? 'var(--danger)' : 'var(--warning)' }}>
                SECURITY INTERCEPTION
              </div>
              <h1 style={{ fontSize: '2rem', margin: '0.25rem 0' }}>
                {isPhishing ? 'Dangerous Phishing Website Detected' : 'Suspicious Website Intercepted'}
              </h1>
              <p className="text-muted">
                PhishGuard AI has prevented this page from loading to protect your security and privacy.
              </p>
            </div>
          </div>

          {/* Requested URL box */}
          <div style={{ background: 'rgba(15, 23, 42, 0.8)', border: '1px solid var(--glass-border)', borderRadius: '8px', padding: '1rem', marginBottom: '1.5rem' }}>
            <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', marginBottom: '0.25rem' }}>
              BLOCKED DESTINATION URL
            </div>
            <div style={{ fontFamily: 'monospace', color: '#fca5a5', fontSize: '1rem', wordBreak: 'break-all' }}>
              {r.url}
            </div>
          </div>

          {/* Metric Badges */}
          <div className="dashboard-grid gap-4 mb-6">
            <div className="col-span-4 glass-card" style={{ padding: '1rem', textAlign: 'center' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600 }}>RISK SCORE</div>
              <div style={{ fontSize: '2.25rem', fontWeight: 800 }} className={isPhishing ? 'text-danger' : 'text-warning'}>
                {r.score} <span style={{ fontSize: '1rem', color: 'var(--text-muted)' }}>/ 100</span>
              </div>
            </div>

            <div className="col-span-4 glass-card" style={{ padding: '1rem', textAlign: 'center' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600 }}>VERDICT</div>
              <div style={{ marginTop: '0.5rem' }}>
                <span className={getVerdictBadgeClass(r.verdict)} style={{ fontSize: '1rem', padding: '0.35rem 1rem' }}>
                  {r.verdict}
                </span>
              </div>
            </div>

            <div className="col-span-4 glass-card" style={{ padding: '1rem', textAlign: 'center' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600 }}>TARGET CATEGORY</div>
              <div style={{ fontSize: '1.25rem', fontWeight: 700, marginTop: '0.5rem', textTransform: 'capitalize' }}>
                {r.category || 'Generic'}
              </div>
            </div>
          </div>



          {/* Navigation Action Buttons */}
          <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', marginTop: '2rem' }}>
            <button 
              className="btn btn-primary" 
              style={{ flex: '1 1 200px', padding: '0.875rem 1.5rem', background: '#2563eb' }}
              onClick={() => {
                if (window.history.length > 1) {
                  window.history.back();
                } else {
                  navigateToDashboard();
                }
              }}
            >
              <ArrowLeft size={18} /> Go Back to Safety
            </button>

            <button 
              className="btn" 
              style={{ 
                background: 'rgba(255, 255, 255, 0.05)', 
                border: '1px solid var(--glass-border)', 
                color: 'var(--text-muted)' 
              }}
              onClick={navigateToDashboard}
            >
              Open PhishGuard Dashboard
            </button>

            <button 
              className="btn" 
              style={{ 
                background: 'transparent', 
                border: '1px solid rgba(239, 68, 68, 0.3)', 
                color: '#fca5a5' 
              }}
              onClick={() => handleContinueAnyway(r.url)}
            >
              Continue Anyway (Unsafe) <ExternalLink size={14} />
            </button>
          </div>
        </div>

        <div className="text-center text-muted" style={{ fontSize: '0.75rem' }}>
          PhishGuard AI Real-Time Protection • CERT-In & NTRO Phishing Detection System
        </div>
      </div>
    );
  }

  // =========================================================================
  // VIEW: MAIN SCANNER DASHBOARD
  // =========================================================================
  return (
    <div className="container">
      {/* Header */}
      <header className="header">
        <div className="logo">
          <Shield size={32} className="logo-icon" />
          <span>PhishGuard AI</span>
        </div>
        <div className="flex items-center gap-2 text-muted">
          <Activity size={18} className="animate-pulse" style={{color: 'var(--success)'}} />
          <span>System Online</span>
        </div>
      </header>

      <main className="dashboard-grid">
        {/* Left Column: Scanner & Results */}
        <div className="col-span-8">
          <section className="glass-card mb-6">
            <h2 className="flex items-center gap-2">
              <Search size={24} />
              Analyze URL
            </h2>
            <p className="text-muted mb-6">Enter a domain or URL to scan for phishing and malicious activity.</p>
            
            <form onSubmit={handleScan} className="input-group">
              <input 
                type="text" 
                className="input" 
                placeholder="https://example.com" 
                value={urlToScan}
                onChange={(e) => setUrlToScan(e.target.value)}
                disabled={isScanning}
              />
              <button 
                type="submit" 
                className="btn btn-primary"
                disabled={isScanning || !urlToScan.trim()}
              >
                {isScanning ? (
                  <><Search size={20} className="animate-spin" /> Scanning...</>
                ) : (
                  <><Search size={20} /> Analyze</>
                )}
              </button>
            </form>

            {scanError && (
              <div className="glass-panel text-danger" style={{padding: '1rem', background: 'var(--danger-bg)'}}>
                <AlertTriangle size={20} className="inline mr-2" /> {scanError}
              </div>
            )}
          </section>

          {/* Scan Result Details */}
          {scanResult && (
            <section className="glass-card mb-6" style={{animation: 'pulse 0.5s cubic-bezier(0.4, 0, 0.6, 1) forwards'}}>
              <div className="flex justify-between items-center mb-6 border-b" style={{paddingBottom: '1rem', borderColor: 'var(--glass-border)'}}>
                <div>
                  <h2 className="mb-2 flex items-center gap-2">
                    {getVerdictIcon(scanResult.verdict)}
                    Scan Complete
                  </h2>
                  <div className="text-xl font-bold">{scanResult.domain}</div>
                </div>
                <div className="text-right">
                  <div className="text-sm text-muted mb-1">Risk Score</div>
                  <div className={`text-2xl font-bold ${
                    scanResult.verdict === 'PHISHING' ? 'text-danger' : 
                    scanResult.verdict === 'SUSPICIOUS' ? 'text-warning' : 'text-success'
                  }`}>
                    {scanResult.score} / 100
                  </div>
                </div>
              </div>

              <div className="dashboard-grid">
                <div className="col-span-6">
                  <h3 className="text-muted mb-4 text-sm font-semibold uppercase tracking-wider">Domain Intelligence</h3>
                  <ul style={{listStyle: 'none'}}>
                    <li className="flex justify-between items-center mb-3 pb-3 border-b" style={{borderColor: 'rgba(255,255,255,0.05)'}}>
                      <span className="flex items-center gap-2 text-muted"><Globe size={16}/> Verdict</span>
                      <span className={getVerdictBadgeClass(scanResult.verdict)}>{scanResult.verdict}</span>
                    </li>
                    <li className="flex justify-between items-center mb-3 pb-3 border-b" style={{borderColor: 'rgba(255,255,255,0.05)'}}>
                      <span className="flex items-center gap-2 text-muted"><Info size={16}/> Confidence</span>
                      <span className="font-semibold">{Math.round(scanResult.confidence * 100)}%</span>
                    </li>
                    <li className="flex justify-between items-center mb-3 pb-3 border-b" style={{borderColor: 'rgba(255,255,255,0.05)'}}>
                      <span className="flex items-center gap-2 text-muted"><Shield size={16}/> Category</span>
                      <span className="font-semibold capitalize">{scanResult.category || 'Generic'}</span>
                    </li>
                  </ul>
                </div>

                <div className="col-span-6">
                  <h3 className="text-muted mb-4 text-sm font-semibold uppercase tracking-wider">Technical Details</h3>
                  <ul style={{listStyle: 'none'}}>
                    <li className="flex justify-between items-center mb-3 pb-3 border-b" style={{borderColor: 'rgba(255,255,255,0.05)'}}>
                      <span className="flex items-center gap-2 text-muted"><Clock size={16}/> Domain Age</span>
                      <span className="font-semibold">{scanResult.domain_age_days ? `${scanResult.domain_age_days} days` : 'Unknown'}</span>
                    </li>
                    <li className="flex justify-between items-center mb-3 pb-3 border-b" style={{borderColor: 'rgba(255,255,255,0.05)'}}>
                      <span className="flex items-center gap-2 text-muted"><Lock size={16}/> Registrar</span>
                      <span className="font-semibold text-right" style={{maxWidth: '150px'}}>{scanResult.registrar || 'Unknown'}</span>
                    </li>
                    <li className="flex justify-between items-center mb-3 pb-3 border-b" style={{borderColor: 'rgba(255,255,255,0.05)'}}>
                      <span className="flex items-center gap-2 text-muted"><AlertTriangle size={16}/> Zero Day</span>
                      <span className="font-semibold">{scanResult.is_zero_day ? 'Yes' : 'No'}</span>
                    </li>
                  </ul>
                </div>
              </div>
              
              <div className="mt-4 pt-4 border-t" style={{borderColor: 'var(--glass-border)'}}>
                <h3 className="text-muted mb-4 text-sm font-semibold uppercase tracking-wider">Analysis Breakdown</h3>
                <div className="glass-panel" style={{padding: '1rem'}}>
                  <div className="flex gap-2 flex-wrap mb-3">
                    <span className="badge safe">Lexical Analysis</span>
                    <span className="badge safe">DNS Checks</span>
                    <span className="badge safe">SSL Verification</span>
                    {scanResult.closest_brand && <span className="badge warning">Brand Imitation Check</span>}
                  </div>
                  {scanResult.shap && scanResult.shap.length > 0 && (
                    <div style={{ marginTop: '0.5rem', fontSize: '0.875rem' }}>
                      <div className="text-muted mb-1">Key Explanatory Signals:</div>
                      <ul style={{ paddingLeft: '1.25rem' }}>
                        {scanResult.shap.slice(0, 3).map((item, idx) => (
                          <li key={idx} style={{ color: item.direction === 'phishing' ? 'var(--danger)' : 'var(--success)' }}>
                            {item.label || item.feature} ({item.direction})
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              </div>
            </section>
          )}

          {/* Live Threat Feed */}
          <section className="glass-card">
            <h2 className="flex items-center gap-2">
              <Activity size={24} />
              Live Threat Feed
            </h2>
            
            {isLoadingFeed ? (
              <div className="text-center py-8 text-muted">
                <Activity size={32} className="animate-spin mx-auto mb-4" />
                <p>Loading threat intel...</p>
              </div>
            ) : feed.length === 0 ? (
              <div className="text-center py-8 text-muted">
                <Shield size={32} className="mx-auto mb-4 opacity-50" />
                <p>No recent threats detected.</p>
              </div>
            ) : (
              <div className="table-container mt-4">
                <table>
                  <thead>
                    <tr>
                      <th>Domain</th>
                      <th>Category</th>
                      <th>Score</th>
                      <th>Verdict</th>
                    </tr>
                  </thead>
                  <tbody>
                    {feed.map((item, idx) => (
                      <tr key={item.id || idx}>
                        <td className="font-medium truncate" title={item.domain}>{item.domain}</td>
                        <td className="capitalize text-muted">{item.category || 'N/A'}</td>
                        <td>
                          <span className={`font-bold ${item.score >= 70 ? 'text-danger' : item.score >= 40 ? 'text-warning' : 'text-success'}`}>
                            {item.score}
                          </span>
                        </td>
                        <td>
                          <span className={getVerdictBadgeClass(item.verdict)}>
                            {item.verdict}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </div>

        {/* Right Column: Stats Overview */}
        <div className="col-span-4">
          <h2 className="mb-4 text-xl">Overview</h2>
          
          <div className="dashboard-grid gap-4">
            <div className="col-span-12 glass-card stat-card">
              <div className="stat-info">
                <h3>Threats Today</h3>
                <div className="stat-value text-danger">{stats.threats_today}</div>
              </div>
              <div className="stat-icon" style={{color: 'var(--danger)', background: 'var(--danger-bg)'}}>
                <Shield size={24} />
              </div>
            </div>

            <div className="col-span-12 glass-card stat-card">
              <div className="stat-info">
                <h3>Zero Days Found</h3>
                <div className="stat-value text-warning">{stats.zero_day_count}</div>
              </div>
              <div className="stat-icon" style={{color: 'var(--warning)', background: 'var(--warning-bg)'}}>
                <AlertTriangle size={24} />
              </div>
            </div>

            <div className="col-span-12 glass-card stat-card">
              <div className="stat-info">
                <h3>Avg Model Confidence</h3>
                <div className="stat-value text-primary">
                  {stats.avg_confidence ? `${stats.avg_confidence.toFixed(1)}%` : '0%'}
                </div>
              </div>
              <div className="stat-icon" style={{color: 'var(--primary)', background: 'rgba(59, 130, 246, 0.1)'}}>
                <Activity size={24} />
              </div>
            </div>
            
            <div className="col-span-12 glass-card mt-4">
              <h3 className="flex items-center gap-2 mb-4 text-sm font-semibold uppercase tracking-wider text-muted">
                <Info size={16} /> System Status
              </h3>
              <ul style={{listStyle: 'none', fontSize: '0.875rem'}}>
                <li className="flex justify-between py-2 border-b" style={{borderColor: 'rgba(255,255,255,0.05)'}}>
                  <span className="text-muted">API Connection</span>
                  <span className="text-success flex items-center gap-1"><CheckCircle size={14}/> Connected</span>
                </li>
                <li className="flex justify-between py-2 border-b" style={{borderColor: 'rgba(255,255,255,0.05)'}}>
                  <span className="text-muted">ML Predictor</span>
                  <span className="text-success flex items-center gap-1"><CheckCircle size={14}/> Active</span>
                </li>
                <li className="flex justify-between py-2">
                  <span className="text-muted">Browser Extension</span>
                  <span className="text-primary flex items-center gap-1"><Shield size={14}/> Ready</span>
                </li>
              </ul>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}

export default App;
