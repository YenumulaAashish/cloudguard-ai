import { useState } from 'react';
import { GitBranch, Fingerprint, Network, Database } from 'lucide-react';
import type { ReportBundle } from '../types/reports';
import { Badge, Empty, Metric, Note, PageTitle, Panel } from '../components/ui';

export function Graph({ data }: { data: ReportBundle }) {
  const [selected, setSelected] = useState<'iam' | 'network' | 'data'>('iam');
  const p = data.posture;
  return <><PageTitle title="Security graph" text="A privacy-preserving view of available relationship evidence." tag="SUMMARY ONLY"/>
    <Note>Graph relationships represent static Terraform relationships and do not prove runtime reachability or exploitability.</Note>
    {p ? <><div className="three-columns"><Metric label="Unresolved references" value={p.graph.unresolved_count} detail="From the sanitized graph summary"/><Metric label="Nodes / relationships" value="Withheld" detail="Not exposed by the public contract"/><Metric label="Graph review flag" value={p.graph.requires_review ? 'Yes' : 'No'} detail="Context remains UNKNOWN in either case"/></div>
      <div className="two-columns mt-6"><Panel title="Analyzer summary explorer" eyebrow="INTERACTIVE · NOT RESOURCE TOPOLOGY">
        <div className="summary-explorer"><div className="summary-center"><GitBranch size={28}/><strong>Sanitized posture</strong><Badge value="UNKNOWN"/></div>
          <div className="summary-buttons" role="group" aria-label="Choose analyzer summary">{([{ key: 'iam', label: 'IAM', Icon: Fingerprint }, { key: 'network', label: 'Network', Icon: Network }, { key: 'data', label: 'Data', Icon: Database }] as const).map(({ key, label, Icon }) => <button key={key} className={selected === key ? 'selected' : ''} aria-pressed={selected === key} onClick={() => setSelected(key)}><Icon size={22}/>{label}<b>{p.domains[key].finding_count}</b></button>)}</div>
        </div><p className="subtle">Select a domain to inspect its public summary. These controls are not graph nodes or inferred resource associations.</p>
      </Panel><Panel title={`${{ iam: 'IAM', network: 'Network', data: 'Data Protection' }[selected]} summary`}>
        <div className="gate-list" aria-live="polite"><div><span>Category</span><Badge value={p.domains[selected].category}/></div><div><span>Finding count</span><b>{p.domains[selected].finding_count}</b></div><div><span>Unknown findings</span><b>{p.domains[selected].severity_counts.unknown}</b></div><div><span>Unknown context</span><b>{p.domains[selected].unknown_context_count}</b></div><div><span>Review required</span><b>{p.domains[selected].requires_review ? 'Yes' : 'No'}</b></div></div>
        <p className="subtle">Analyzer associations, node identifiers and edges remain private. Zero unresolved references does not prove reachability or complete coverage.</p>
      </Panel></div></> : <Panel title="Graph summary"><Empty title="Graph unavailable">The graph summary requires a valid posture bundle. Private graph files are never loaded.</Empty></Panel>}
    <Note>Topology is unavailable by design at this privacy boundary. The dashboard does not reconstruct the private Phase 4.4 graph.</Note></>;
}
