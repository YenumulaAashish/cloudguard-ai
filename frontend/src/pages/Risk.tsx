import type { ReportBundle } from '../types/reports';
import { Badge, Empty, Metric, Note, PageTitle, Panel } from '../components/ui';
import { EvidenceChart } from '../components/charts';

export function Risk({ data }: { data: ReportBundle }) {
  const p = data.pr;
  return <><PageTitle title="Risk analysis" text="Transparent prioritization from the deterministic CloudGuard risk engine."/>
    <Note>CloudGuard risk scores are calculated deterministically. AI advisory analysis cannot modify the score.</Note>
    {p ? <><div className="three-columns"><Metric label="Deterministic risk score" value={`${p.risk.score} / 100`} detail="Original Python engine result"/><Metric label="Risk category" value={<Badge value={p.risk.category}/>} detail="Independent of policy gate status"/><Metric label="Review required" value={p.risk.requires_review ? 'Yes' : 'No'} detail="Preserved from the risk report"/></div>
      <div className="two-columns mt-6"><Panel title="Finding status distribution" eyebrow="PHASE 3 · SOURCE SNAPSHOT"><EvidenceChart label="Phase 3 finding statuses" rows={[
        { name: 'Exceptions', count: p.findings.approved_exceptions, color: '#82b9ec' }, { name: 'Failed', count: p.findings.failed, color: '#f7838f' },
        { name: 'Other', count: p.findings.total - p.findings.failed - p.findings.approved_exceptions, color: '#b8a2f7' }]}/></Panel>
        <Panel title="Risk interpretation"><p>Approved exceptions remain visible findings. Their presence does not turn skipped checks into passed checks.</p><p>Risk, policy gates and review flags are distinct outputs. A LOW category cannot authorize a deployment or establish real-plan compliance.</p><p className="subtle">Per-finding scores, severity distribution and status weights are not in the Phase 3 public summary. No JavaScript risk algorithm or inferred ranking is used.</p></Panel></div>
      <Panel title="Highest-risk findings" className="mt-6"><Empty title="Detailed ranking is private">The sanitized contract omits individual scores, identifiers and remediation context. Use the existing private review workflow for detailed investigation.</Empty></Panel>
    </> : <Panel title="Risk result"><Empty title="Risk report unavailable">No score is inferred from missing evidence.</Empty></Panel>}</>;
}
