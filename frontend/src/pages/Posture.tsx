import { Fingerprint, Network, Database, GitBranch } from 'lucide-react';
import type { PostureSummary, ReportBundle } from '../types/reports';
import { Badge, Empty, Note, PageTitle, Panel } from '../components/ui';
import { EvidenceChart } from '../components/charts';

export const domains = [{ key: 'iam', label: 'IAM Security', icon: Fingerprint, explanation: 'Static permissions and trust analysis.' },
  { key: 'network', label: 'Network Security', icon: Network, explanation: 'Static network rule exposure analysis.' },
  { key: 'data', label: 'Data Protection', icon: Database, explanation: 'S3 configuration and protection analysis.' }] as const;

export function DomainCards({ posture }: { posture: PostureSummary }) {
  return <div className="domain-grid">{domains.map(({ key, label, icon: Icon, explanation }) => {
    const d = posture.domains[key];
    return <section key={key} className="domain-card"><div className="spread"><Icon size={23}/><Badge value={d.category}/></div><h3>{label}</h3>
      <div className="domain-number">{d.finding_count}<span>findings</span></div><p>{explanation}</p>
      <div className="domain-footer">{d.requires_review ? 'Review required' : 'No domain review flag'}<span>{d.severity_counts.unknown + d.unknown_context_count} unknown*</span></div></section>;
  })}<section className="domain-card"><div className="spread"><GitBranch size={23}/><Badge value="UNKNOWN"/></div><h3>Security Graph</h3>
    <div className="domain-number">{posture.graph.unresolved_count}<span>unresolved references</span></div><p>Summary only. Private topology withheld.</p>
    <div className="domain-footer">{posture.graph.requires_review ? 'Graph review required' : 'No unresolved review flag'}<span>Context unknown</span></div></section></div>;
}

export function Posture({ data }: { data: ReportBundle }) {
  const p = data.posture;
  return <><PageTitle title="Cloud posture" text="Deterministic analyzer summaries, with uncertainty kept visible." tag="SYNTHETIC FIXTURE"/>
    {p ? <><div className="status-strip"><span>Overall synthetic posture</span><Badge value={p.overall.category}/><Badge value="REVIEW REQUIRED"/><span className="ml-auto">Context <Badge value={p.context_status}/></span></div>
      <DomainCards posture={p}/><p className="subtle mt-4">*Unknown findings and unknown configuration contexts are shown together here; they are not additional findings.</p>
      <div className="two-columns mt-6"><Panel title="Findings by domain" eyebrow="SYNTHETIC · COUNTS ONLY"><EvidenceChart label="Synthetic findings by domain" rows={domains.map(d => ({ name: { iam: 'IAM', network: 'Network', data: 'Data' }[d.key], count: p.domains[d.key].finding_count }))}/></Panel>
        <Panel title="What the posture means"><p>The overall category is supplied by the existing Phase 4 integrator. The dashboard does not recalculate it or combine it with the Phase 3 risk score.</p><div className="gate-list"><div><span>Same-plan provenance</span><Badge value="UNKNOWN"/></div><div><span>Freshness</span><Badge value="UNKNOWN"/></div><div><span>Authenticity</span><Badge value="UNKNOWN"/></div></div></Panel></div>
    </> : <Panel title="Cloud posture"><Empty title="Report unavailable">Provide both the sanitized summary and its valid completion receipt.</Empty></Panel>}
    <Note>Analyzer completion confirms report integration, not AWS security or runtime behavior. Individual control IDs, resource identities and messages are absent from the public contract.</Note>
  </>;
}
