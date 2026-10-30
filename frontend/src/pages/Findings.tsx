import { useMemo, useState } from 'react';
import { Search, SlidersHorizontal } from 'lucide-react';
import type { ReportBundle } from '../types/reports';
import { findingGroups } from '../services/reports';
import { Badge, Empty, Note, PageTitle, Panel } from '../components/ui';

export function Findings({ data }: { data: ReportBundle }) {
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState('All severities');
  const [domain, setDomain] = useState('All domains');
  const [status, setStatus] = useState('All statuses');
  const groups = useMemo(() => findingGroups(data), [data]);
  const rows = groups.filter(row => (severity === 'All severities' || row.severity === severity) &&
    (domain === 'All domains' || row.domain === domain) && (status === 'All statuses' || row.status === status) &&
    `${row.domain} ${row.severity} ${row.status} ${row.source}`.toLowerCase().includes(search.toLowerCase()));
  return <><PageTitle title="Findings" text="Explore public finding aggregates without exposing private infrastructure."/>
    <Note>Aggregate view: each row is a group, not an individual finding. Control IDs, resources, messages and per-finding review decisions are withheld. Phase 3 and Phase 4 counts are separate evidence scopes; do not add them into one scan total.</Note>
    <Panel title="Finding groups" action={<span className="subtle" aria-live="polite">{rows.length} groups shown</span>}>
      <div className="filters"><label className="search-field"><Search size={17} aria-hidden="true"/><span className="sr-only">Search findings</span><input placeholder="Search aggregates…" value={search} onChange={e => setSearch(e.target.value)}/></label>
        <SlidersHorizontal size={17} aria-hidden="true" className="filter-icon"/>
        {[{ label: 'Severity', value: severity, set: setSeverity, options: ['All severities', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN'] },
          { label: 'Domain', value: domain, set: setDomain, options: ['All domains', 'Policy', 'IAM', 'Network', 'Data Protection'] },
          { label: 'Status', value: status, set: setStatus, options: ['All statuses', 'APPROVED EXCEPTION', 'FAILED', 'UNKNOWN'] }].map(filter => <label key={filter.label}><span className="sr-only">{filter.label}</span><select aria-label={filter.label} value={filter.value} onChange={e => filter.set(e.target.value)}>{filter.options.map(o => <option key={o}>{o}</option>)}</select></label>)}
      </div>
      {!groups.length ? <Empty title={data.pr || data.posture ? 'No reported findings' : 'Reports unavailable'}>Missing reports do not imply a clean scan.</Empty> : rows.length ? <div className="table-wrap"><table><caption className="sr-only">Sanitized finding groups by domain and severity</caption><thead><tr><th scope="col">Severity</th><th scope="col">Domain</th><th scope="col">Count</th><th scope="col">Status</th><th scope="col">Source</th><th scope="col">Review</th></tr></thead><tbody>{rows.map(row => <tr key={row.id}><td><Badge value={row.severity}/></td><td>{row.domain}</td><td className="tabular-nums">{row.count}</td><td><Badge value={row.status}/></td><td className="subtle">{row.source}</td><td className="subtle">Not exposed per finding</td></tr>)}</tbody></table></div> : <Empty title="No matching groups">Change your search or filters to see available evidence.</Empty>}
      <p className="subtle table-foot">UNKNOWN status means the sanitized summary does not expose a finding status. It does not mean PASS.</p>
    </Panel></>;
}
