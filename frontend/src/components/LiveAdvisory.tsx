import { useState } from 'react';
import { Panel, Badge } from './ui';
import { validCatalog } from '../services/publicFindings';
interface Finding { id: string; control_id: string; domain: string; severity: string; status: string; resource_type: string }
const fields = ['summary','why_it_matters','recommended_action','remediation_steps','terraform_guidance','limitations'];
export function LiveAdvisory() {
  const [items, setItems] = useState<Finding[]>([]), [selected, setSelected] = useState('');
  const [configured, setConfigured] = useState(false), [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('Live AI advisory is not configured until the local service confirms availability.');
  const [advice, setAdvice] = useState<Record<string,string> | null>(null);
  const [catalogId, setCatalogId] = useState<string | null>(null);
  const [source, setSource] = useState('SYNTHETIC');
  const finding = items.find(f => f.id === selected);
  async function request(explain: boolean) {
    setBusy(true); setAdvice(null);
    const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 30000);
    try {
      const response = await fetch(explain ? '/api/ai/advisory' : '/api/ai/catalog', { method: 'POST', credentials: 'omit', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(explain ? { finding_id: selected, ...(catalogId ? { catalog_id:catalogId } : {}) } : {}), signal: controller.signal });
      const text = await response.text();
      if (!response.ok || text.length > 131072) throw Error();
      const value = JSON.parse(text);
      if (explain) {
        if (value.available !== true || value.informational_only !== true || value.authority !== 'deterministic-cloudguard' || !value.advisory || Object.keys(value.advisory).length !== fields.length || !fields.every(k => typeof value.advisory[k] === 'string' && value.advisory[k].length <= 1200)) throw Error();
        setAdvice(value.advisory); setMessage('LIVE OPENAI ADVISORY');
      } else {
        if (value.catalog_id) {
          if (!/^[0-9a-f-]{36}$/.test(value.catalog_id) || !validCatalog(value.catalog) || value.catalog.source !== value.source || JSON.stringify(value.findings) !== JSON.stringify(value.catalog.findings)) throw Error();
        } else if (value.source !== 'SYNTHETIC' || !Array.isArray(value.findings) || value.findings.length > 100 || !value.findings.every((f: Finding) => /^[a-z]+-\d+$/.test(f.id) && /^CGA_(IAM|NET|DATA)_\d+$/.test(f.control_id) && ['iam','network','data'].includes(f.domain) && ['CRITICAL','HIGH','MEDIUM','LOW','INFO','UNKNOWN'].includes(f.severity) && ['FINDING','UNKNOWN'].includes(f.status) && /^aws_[a-z0-9_]{1,80}$/.test(f.resource_type))) throw Error();
        if (typeof value.configured !== 'boolean') throw Error();
        setCatalogId(value.catalog_id ?? null); setSource(value.source);
        setItems(value.findings); setSelected(value.findings[0]?.id ?? ''); setConfigured(value.configured);
        setMessage(value.configured ? 'Ready. Explicitly request one explanation.' : 'Live AI advisory is not configured.');
      }
    } catch { setMessage('Live advisory unavailable. No deterministic result was changed.'); }
    finally { clearTimeout(timer); setBusy(false); }
  }
  return <Panel title="Live OpenAI advisory" className="mt-6"><p>Server-reviewed finding source: {source}. Context, freshness and authenticity remain UNKNOWN. The server catalog is independent of browser uploads.</p><button className="button mt-4" disabled={busy} onClick={() => request(false)}>Load advisory finding selector</button><p role="status" className="mt-4">{busy ? 'Loading advisory service…' : message}</p>
    {!!items.length && <><label className="block mt-4">Advisory finding <select aria-label="Advisory finding" disabled={busy} value={selected} onChange={e => { setSelected(e.target.value); setAdvice(null); }}>{items.map(f => <option key={f.id} value={f.id}>{f.control_id} · {f.domain} · {f.severity}</option>)}</select></label>{finding && <div className="status-strip mt-4"><strong>Deterministic CloudGuard Result</strong><span>{finding.control_id}</span><Badge value={finding.severity}/><Badge value={finding.status}/><span>{finding.resource_type}</span></div>}<button className="button" disabled={busy || !configured || !finding} onClick={() => request(true)}>Explain with AI</button></>}
    {advice && <section className="mt-6"><strong>AI-generated advisory — informational only.</strong><p>CloudGuard deterministic security controls remain authoritative.</p>{fields.map(k => <div key={k} className="mt-4"><h3>{k.replaceAll('_',' ')}</h3><p style={{ whiteSpace: 'pre-wrap' }}>{advice[k]}</p></div>)}</section>}
  </Panel>;
}
