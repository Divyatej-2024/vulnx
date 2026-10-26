import React, { useCallback, useEffect, useState } from 'react';
import axios from 'axios';
import './App.css';

const configuredApiUrl = process.env.REACT_APP_API_URL?.trim();
const API = (configuredApiUrl || '/api/v1').replace(/\/+$/, '');
// CRA embeds environment variables at build time. A production build without
// this value cannot reach the separate FastAPI service from Vercel's static host.
const API_CONFIG_MISSING = process.env.NODE_ENV === 'production' && !configuredApiUrl;
const PAGE_SIZE = 12;
const severityFor = (score) => {
  if (score == null) return 'Unknown';
  if (score >= 9) return 'Critical';
  if (score >= 7) return 'High';
  if (score >= 4) return 'Medium';
  return 'Low';
};
const prettyDate = (value) => value ? new Date(value).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }) : '—';

function App() {
  const [summary, setSummary] = useState(null);
  const [vulns, setVulns] = useState([]);
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState('');
  const [page, setPage] = useState(0);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selected, setSelected] = useState(null);
  const [installPrompt, setInstallPrompt] = useState(null);
  const [installHelp, setInstallHelp] = useState(false);
  const [isOnline, setIsOnline] = useState(() => navigator.onLine);
  const [isInstalled, setIsInstalled] = useState(() => window.matchMedia('(display-mode: standalone)').matches || navigator.standalone === true);
  // The import runs server-side; the client never invents a percentage or claims completion.
  const waitingForFeed = Boolean(error && !summary && vulns.length === 0 && isOnline && !API_CONFIG_MISSING);

  useEffect(() => {
    const onInstallPrompt = (event) => {
      event.preventDefault();
      setInstallPrompt(event);
    };
    const onInstalled = () => {
      setIsInstalled(true);
      setInstallPrompt(null);
    };
    const onOnline = () => setIsOnline(true);
    const onOffline = () => setIsOnline(false);
    window.addEventListener('beforeinstallprompt', onInstallPrompt);
    window.addEventListener('appinstalled', onInstalled);
    window.addEventListener('online', onOnline);
    window.addEventListener('offline', onOffline);
    return () => {
      window.removeEventListener('beforeinstallprompt', onInstallPrompt);
      window.removeEventListener('appinstalled', onInstalled);
      window.removeEventListener('online', onOnline);
      window.removeEventListener('offline', onOffline);
    };
  }, []);

  const installApp = async () => {
    if (!installPrompt) {
      setInstallHelp(true);
      return;
    }
    await installPrompt.prompt();
    const result = await installPrompt.userChoice;
    if (result.outcome === 'accepted') setIsInstalled(true);
    setInstallPrompt(null);
  };

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      if (API_CONFIG_MISSING) {
        setVulns([]);
        setTotal(0);
        setSummary(null);
        setError('Production API URL is not configured. Set REACT_APP_API_URL in Vercel to your public HTTPS VulnX API address ending in /api/v1, then redeploy.');
        return;
      }
      const params = { limit: PAGE_SIZE, offset: page * PAGE_SIZE };
      if (search.trim()) params.search = search.trim();
      if (severity) params.severity = severity.toLowerCase();
      const [list, stats] = await Promise.all([
        axios.get(`${API}/vulns`, { params }), axios.get(`${API}/summary`),
      ]);
      setVulns(list.data.vulns || []);
      setTotal(list.data.total || 0);
      setSummary(stats.data);
    } catch (e) {
      setError(e.response?.data?.detail || 'Could not reach the VulnX API. Start the backend and try again.');
    } finally {
      setLoading(false);
    }
  }, [page, search, severity]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    const refreshWhenVisible = () => {
      if (document.visibilityState === 'visible') load();
    };
    const timer = window.setInterval(load, waitingForFeed ? 30 * 1000 : 5 * 60 * 1000);
    document.addEventListener('visibilitychange', refreshWhenVisible);
    return () => {
      window.clearInterval(timer);
      document.removeEventListener('visibilitychange', refreshWhenVisible);
    };
  }, [load, waitingForFeed]);
  useEffect(() => { setPage(0); }, [search, severity]);

  const openDetails = async (cveId) => {
    try {
      const response = await axios.get(`${API}/vulns/${cveId}`);
      setSelected(response.data);
    } catch (e) {
      setError('Could not load vulnerability details. Please try again.');
    }
  };

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="/" aria-label="VulnX home"><span className="brand-mark">V</span><span>vuln<span className="brand-accent">x</span></span></a>
        <div className="side-caption">WORKSPACE</div>
        <button className="nav-item active"><span className="nav-icon">◫</span> Overview</button>
        <button className="nav-item" onClick={() => document.getElementById('vulnerability-table')?.scrollIntoView({ behavior: 'smooth' })}><span className="nav-icon">⌕</span> Vulnerabilities</button>
        <div className="sidebar-bottom"><div className="live-dot" /> NVD feed monitor <span className="online">LIVE</span></div>
      </aside>

      <main className="main-content">
        <header className="topbar"><div className="breadcrumb">Workspace <span>/</span> <strong>Overview</strong></div><div className="topbar-actions">{!isInstalled && <button className="install-button" onClick={installApp}>⬇ <span>Install app</span></button>}<button className="refresh-button" onClick={load} disabled={loading}><span className={loading ? 'refresh-spin' : ''}>↻</span> Refresh data</button></div></header>
        <div className="content-wrap">
          {!isOnline && <div className="offline-banner" role="status"><span className="offline-indicator" /> Offline mode · showing saved feed data where available</div>}
          <section className="page-heading"><div><div className="eyebrow">THREAT INTELLIGENCE</div><h1>Vulnerability overview</h1><p>Track, search, and prioritize vulnerabilities from the NVD.</p></div><div className={`feed-status ${waitingForFeed ? 'feed-status-waiting' : ''}`}><span className={waitingForFeed ? 'wait-dot' : 'live-dot'} /> {waitingForFeed ? 'Feed data pending' : error ? 'API unavailable' : loading ? 'Checking API…' : 'Feed operational'}</div></section>

          {waitingForFeed && <section className="import-panel" aria-live="polite"><div className="import-orbit"><span className="import-orbit-core">NVD</span></div><div className="import-copy"><div className="import-kicker"><span className="wait-dot" /> DATA INGESTION</div><h2>Preparing your vulnerability feed</h2><p>The dashboard is available while the NVD data service catches up. Import progress is handled in the background; this screen checks again automatically and will populate when the API returns data.</p><div className="import-progress"><span /></div><div className="import-foot"><span><span className="loader" /> Waiting for the API</span><span>Auto-check every 30 seconds</span></div></div><button className="import-retry" onClick={load} disabled={loading}>{loading ? 'Checking…' : 'Check now ↻'}</button></section>}

          <section className="stats-grid" aria-label="Vulnerability statistics">
            <Stat label="Tracked vulnerabilities" value={summary?.total} icon="◈" tone="blue" note="Across ingested NVD records" />
            <Stat label="Critical severity" value={summary?.critical} icon="⌁" tone="red" note="CVSS score 9.0 – 10.0" />
            <Stat label="High severity" value={summary?.high} icon="⌁" tone="amber" note="CVSS score 7.0 – 8.9" />
            <Stat label="Latest publication" value={summary?.latest_published ? prettyDate(summary.latest_published) : '—'} icon="◷" tone="green" note="Most recent CVE in your feed" />
          </section>

          <section className="table-card" id="vulnerability-table">
            <div className="table-heading"><div><h2>Vulnerabilities</h2><p>Prioritized by CVSS severity and publication date.</p></div><div className="record-count">{total.toLocaleString()} records</div></div>
            <div className="filters"><label className="search-box"><span>⌕</span><input aria-label="Search vulnerabilities" placeholder="Search CVE or description..." value={search} onChange={(e) => setSearch(e.target.value)} /><kbd>/</kbd></label><label className="select-wrap"><span className="sr-only">Filter by severity</span><select value={severity} onChange={(e) => setSeverity(e.target.value)}><option value="">All severities</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Unknown</option></select></label></div>
            {error && !waitingForFeed && <div className="error-banner" role="alert"><span>!</span>{error}<button onClick={load}>Retry</button></div>}
            <div className="table-scroll"><table><thead><tr><th>VULNERABILITY</th><th>SEVERITY</th><th>CVSS V3</th><th>PUBLISHED</th><th>PRIORITY</th><th /></tr></thead>
              <tbody>{loading ? <tr><td colSpan="6" className="state-cell"><span className="loader" />Loading vulnerability data…</td></tr> : vulns.length === 0 ? <tr><td colSpan="6" className="state-cell">{waitingForFeed ? 'The feed will appear here when the API is ready.' : error ? 'Data is unavailable.' : 'No vulnerabilities match these filters.'}</td></tr> : vulns.map((v) => <tr key={v.cve_id} onClick={() => openDetails(v.cve_id)} className="data-row"><td><div className="cve-id">{v.cve_id}</div><div className="cve-title">{v.title || 'NVD vulnerability record'}</div></td><td><span className={`severity severity-${severityFor(v.cvss_v3).toLowerCase()}`}><i />{severityFor(v.cvss_v3)}</span></td><td><span className="cvss-value">{v.cvss_v3 == null ? '—' : Number(v.cvss_v3).toFixed(1)}</span><span className="cvss-max"> / 10</span></td><td className="date-cell">{prettyDate(v.published_date)}</td><td><div className="priority"><div className="priority-track"><span style={{ width: `${(v.score || 0) * 100}%` }} /></div><span>{Math.round((v.score || 0) * 100)}</span></div></td><td className="arrow-cell">↗</td></tr>)}</tbody>
            </table></div>
            <div className="pagination"><span>Showing {total ? page * PAGE_SIZE + 1 : 0}–{Math.min((page + 1) * PAGE_SIZE, total)} of {total.toLocaleString()}</span><div><button aria-label="Previous page" disabled={page === 0 || loading} onClick={() => setPage((p) => p - 1)}>←</button><span>Page {page + 1} of {Math.max(1, Math.ceil(total / PAGE_SIZE))}</span><button aria-label="Next page" disabled={(page + 1) * PAGE_SIZE >= total || loading} onClick={() => setPage((p) => p + 1)}>→</button></div></div>
          </section>
          <footer className="page-footer"><span>VulnX <span className="footer-sep">·</span> Vulnerability intelligence</span><span>Priority score is normalized CVSS v3, not a predictive model.</span></footer>
        </div>
      </main>

      {selected && <div className="modal-backdrop" role="presentation" onClick={() => setSelected(null)}><section className="detail-modal" role="dialog" aria-modal="true" aria-labelledby="detail-title" onClick={(e) => e.stopPropagation()}><button className="modal-close" aria-label="Close details" onClick={() => setSelected(null)}>×</button><div className="eyebrow">VULNERABILITY DETAILS</div><h2 id="detail-title">{selected.cve_id}</h2><div className="detail-meta"><span className={`severity severity-${severityFor(selected.cvss_v3).toLowerCase()}`}><i />{severityFor(selected.cvss_v3)}</span><span>CVSS v3 <strong>{selected.cvss_v3 == null ? 'N/A' : Number(selected.cvss_v3).toFixed(1)}</strong></span><span>Published <strong>{prettyDate(selected.published_date)}</strong></span></div><h3>Description</h3><p className="detail-description">{selected.description}</p><a className="nvd-link" href={`https://nvd.nist.gov/vuln/detail/${selected.cve_id}`} target="_blank" rel="noreferrer">View official NVD record <span>↗</span></a></section></div>}
      {installHelp && <div className="modal-backdrop" role="presentation" onClick={() => setInstallHelp(false)}><section className="detail-modal install-guide" role="dialog" aria-modal="true" aria-labelledby="install-title" onClick={(e) => e.stopPropagation()}><button className="modal-close" aria-label="Close install instructions" onClick={() => setInstallHelp(false)}>×</button><div className="eyebrow">VULNX FOR MOBILE</div><h2 id="install-title">Add VulnX to your home screen</h2><p className="detail-description">Open your browser menu or Share menu, then choose <strong>Install app</strong> or <strong>Add to Home Screen</strong>. VulnX will open in its own window and keep the latest feed data available when you are offline.</p><button className="refresh-button" onClick={() => setInstallHelp(false)}>Got it</button></section></div>}
    </div>
  );
}

function Stat({ label, value, icon, tone, note }) {
  return <article className="stat-card"><div className={`stat-icon ${tone}`}>{icon}</div><div className="stat-label">{label}</div><div className="stat-value">{value == null ? <span className="skeleton" /> : typeof value === 'number' ? value.toLocaleString() : value}</div><div className="stat-note">{note}</div></article>;
}

export default App;
