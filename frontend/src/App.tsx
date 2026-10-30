import { useEffect, useRef, useState } from 'react';
import { NavLink, Route, Routes, useLocation, Link } from 'react-router';
import { ShieldCheck, LayoutDashboard, ListFilter, Layers, ChartNoAxesCombined, GitBranch, Sparkles, Workflow, CloudOff, Upload, RotateCcw, Menu, X, ChevronRight } from 'lucide-react';
import { loadReport, parseReport } from './services/reports';
import demo from './data/demo.json';
import type { ReportState } from './types/reports';
import { Badge, Empty, Note, Panel } from './components/ui';
import { Overview } from './pages/Overview';
import { Findings } from './pages/Findings';
import { Posture } from './pages/Posture';
import { Risk } from './pages/Risk';
import { Graph } from './pages/Graph';
import { Advisory } from './pages/Advisory';
import { Scans } from './pages/Scans';
import { Aws } from './pages/Aws';

const navigation = [
  { path: '/', title: 'Overview', icon: LayoutDashboard }, { path: '/findings', title: 'Findings', icon: ListFilter },
  { path: '/posture', title: 'Cloud Posture', icon: Layers }, { path: '/risk', title: 'Risk Analysis', icon: ChartNoAxesCombined },
  { path: '/graph', title: 'Security Graph', icon: GitBranch }, { path: '/advisory', title: 'AI Advisory', icon: Sparkles },
  { path: '/scans', title: 'CI / Scan Status', icon: Workflow }, { path: '/aws', title: 'AWS Integration', icon: CloudOff },
];

export function App({ initialState }: { initialState?: ReportState }) {
  const [state, setState] = useState<ReportState>(() => initialState ?? parseReport(demo));
  const [menu, setMenu] = useState(false);
  const [loading, setLoading] = useState(false);
  const [imported, setImported] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);
  const location = useLocation();
  const main = useRef<HTMLElement>(null);
  const previousPath = useRef(location.pathname);
  const title = navigation.find(n => n.path === location.pathname)?.title ?? 'Page not found';
  useEffect(() => {
    document.title = `CloudGuard AI | ${title}`;
    setMenu(false);
    if (previousPath.current !== location.pathname) main.current?.focus();
    previousPath.current = location.pathname;
  }, [location.pathname, title]);
  return <div className="app-shell"><a className="skip-link" href="#main" onClick={event => { event.preventDefault(); main.current?.focus(); }}>Skip to content</a>
    <aside className={`sidebar ${menu ? 'open' : ''}`} aria-label="Workspace navigation"><Link to="/" className="brand"><span className="brand-icon"><ShieldCheck size={26}/></span><span>CloudGuard <b>AI</b><small>SECURITY INTELLIGENCE</small></span></Link>
      <div className="workspace-card"><span className="workspace-avatar">CG</span><div><strong>CloudGuard workspace</strong><small>Local evidence environment</small></div></div>
      <p className="nav-label">WORKSPACE</p><nav>{navigation.map(({ path, title, icon: Icon }) => <NavLink key={path} end={path === '/'} to={path}><Icon size={19}/><span>{title}</span>{path === '/advisory' && <small>INFO</small>}</NavLink>)}</nav>
      <div className="sidebar-bottom"><div className="offline-status"><span/> Offline mode</div><p>No AWS connection required.</p><div className="sidebar-rule"/><p>Deterministic tools decide.<br/>AI explains. PR reporting informs.</p><small>CloudGuard AI · Capstone</small></div>
    </aside>
    {menu && <button className="sidebar-scrim" aria-label="Close navigation" onClick={() => setMenu(false)}/>}
    <div className="main-shell"><header className="topbar"><button className="icon-button menu-toggle" onClick={() => setMenu(!menu)} aria-expanded={menu} aria-label={menu ? 'Close navigation' : 'Open navigation'}>{menu ? <X size={22}/> : <Menu size={22}/>}</button><div className="breadcrumb"><span>Workspace</span><ChevronRight size={14}/><strong>{title}</strong></div><div className="topbar-right"><span className="desktop-only"><Badge value="OFFLINE / SYNTHETIC"/></span><span className="avatar" aria-label="Local workspace">CG</span></div></header>
      <main id="main" ref={main} tabIndex={-1}><div className="report-toolbar"><span>{imported ? 'User-supplied snapshot · authenticity UNKNOWN' : 'Bundled snapshot · no live refresh'}</span><div>
        <input ref={fileInput} type="file" accept="application/json,.json" className="sr-only" aria-label="Select sanitized report bundle" onChange={async event => {
          const file = event.target.files?.[0]; if (!file) return;
          setLoading(true); setImported(true); setState({ status: 'unavailable' });
          setState(await loadReport(file)); setLoading(false); event.target.value = '';
        }}/>
        <button className="button quiet" disabled={loading} onClick={() => fileInput.current?.click()}><Upload size={14}/>{loading ? 'Reading…' : 'Load sanitized bundle'}</button>
        <button className="button quiet" disabled={loading} onClick={() => { setState(parseReport(demo)); setImported(false); }}><RotateCcw size={14}/>Reset demo</button>
      </div></div>
      {imported && <Note>Local file only; nothing is uploaded. Schema validity is not evidence authenticity or freshness. No supplied file can change AWS integration status.</Note>}
      <div aria-live="polite">{state.status !== 'ready' && <Panel title={state.status === 'malformed' ? 'Report rejected' : 'Report unavailable'}><Empty title={loading ? 'Reading sanitized report…' : state.status === 'malformed' ? 'Malformed or unsupported report' : 'No valid evidence available'}>Values are withheld. Use a bounded sanitized bundle with valid summaries and matching completion receipts. No PASS or risk score is inferred. Reset demo to restore the reviewed snapshot.</Empty></Panel>}</div>
      <Routes>
        <Route path="/aws" element={<Aws/>}/>
        <Route path="/" element={state.status === 'ready' ? <Overview data={state.data}/> : null}/>
        <Route path="/findings" element={state.status === 'ready' ? <Findings data={state.data}/> : null}/>
        <Route path="/posture" element={state.status === 'ready' ? <Posture data={state.data}/> : null}/>
        <Route path="/risk" element={state.status === 'ready' ? <Risk data={state.data}/> : null}/>
        <Route path="/graph" element={state.status === 'ready' ? <Graph data={state.data}/> : null}/>
        <Route path="/advisory" element={state.status === 'ready' ? <Advisory data={state.data}/> : null}/>
        <Route path="/scans" element={state.status === 'ready' ? <Scans data={state.data}/> : null}/>
        <Route path="*" element={<Panel title="Page not found"><p>This view is not available. <Link to="/">Return to overview</Link>.</p></Panel>}/>
      </Routes>
      <footer><span><ShieldCheck size={14}/> Evidence-led security. Human-reviewed decisions.</span><span>Informational dashboard · No deployment controls</span></footer>
      </main></div></div>;
}
