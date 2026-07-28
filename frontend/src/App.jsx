import React, { useState, useEffect } from 'react';
import { 
  Shield, AlertTriangle, Search, Activity, 
  Globe, Clock, Lock, CheckCircle, XCircle, Info
} from 'lucide-react';

const API_BASE_URL = 'http://localhost:8000/api/v1';

function App() {
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

  // Fetch initial data
  useEffect(() => {
    fetchStats();
    fetchFeed();
    
    // Poll for updates every 10 seconds
    const interval = setInterval(() => {
      fetchStats();
      fetchFeed();
    }, 10000);
    
    return () => clearInterval(interval);
  }, []);

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
      
      // Refresh feed and stats immediately after a scan
      fetchStats();
      fetchFeed();
    } catch (err) {
      setScanError(err.message || 'An error occurred during scanning.');
    } finally {
      setIsScanning(false);
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
                  <p className="text-sm text-muted mb-2">Detailed feature breakdown and SHAP explainability will appear here (Phase 3).</p>
                  <div className="flex gap-2 flex-wrap">
                    <span className="badge safe">Lexical Analysis</span>
                    <span className="badge safe">DNS Checks</span>
                    <span className="badge safe">SSL Verification</span>
                  </div>
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
                  <span className="text-warning flex items-center gap-1"><Info size={14}/> Stub Mode</span>
                </li>
                <li className="flex justify-between py-2">
                  <span className="text-muted">Database</span>
                  <span className="text-success flex items-center gap-1"><CheckCircle size={14}/> Online</span>
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
