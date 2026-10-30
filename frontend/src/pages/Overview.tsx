import { ShieldCheck, ScanLine, Workflow, LockKeyhole } from 'lucide-react';
import type { ReportBundle } from '../types/reports';
import { Badge, Empty, Metric, Note, PageLink, PageTitle, Panel } from '../components/ui';
import { EvidenceChart } from '../components/charts';
import { DomainCards } from './Posture';

export function Overview({ data }: { data: ReportBundle }) {
  const { pr, posture } = data;
  const severity = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'].map(name => ({ name,
    count: posture ? Object.values(posture.domains).reduce((sum, d) => sum + (d.severity_counts[name.toLowerCase() as keyof typeof d.severity_counts] ?? 0), 0) : 0 }));
  return <><PageTitle title="Security overview" text="A clear view of your infrastructure security evidence."/>
    <div className="scope-banner"><div className="scope-icon"><ScanLine size={21}/></div><div><strong>Offline evidence workspace</strong><p>Source-scan snapshot + synthetic posture fixture. These are separate analyses, not a live AWS scan.</p></div><Badge value="AWS PENDING"/></div>
    <div className="overview-top">
      <Panel title="Deterministic risk" eyebrow="PHASE 3 · SOURCE SCAN" className="risk-panel" action={<ShieldCheck size={22} className="muted"/>}>
        {pr ? <><div className="risk-reading"><strong data-testid="risk-score">{pr.risk.score}</strong><span>/ 100<Badge value={pr.risk.category}/></span></div>
          <div className="risk-meter" aria-label={`Deterministic risk ${pr.risk.score} out of 100`}><span style={{ width: `${pr.risk.score}%` }}/></div>
          <div className="spread"><span>Review required</span><strong>{pr.risk.requires_review ? 'Yes' : 'No'}</strong></div><p className="subtle">Produced by the Python risk engine. Independent of the synthetic posture shown below.</p></>
          : <Empty title="Risk unavailable">No valid Phase 3 summary supplied.</Empty>}
        <PageLink to="/risk">Explore risk analysis</PageLink>
      </Panel>
      <div className="metrics-grid">
        <Metric label="Reported findings" value={pr?.findings.total ?? '—'} detail="Phase 3 source-scan findings"/>
        <Metric label="Failed findings" value={pr?.findings.failed ?? '—'} detail="Reported failures, not a gate verdict"/>
        <Metric label="Approved exceptions" value={pr?.findings.approved_exceptions ?? '—'} detail="Existing resource-scoped approvals"/>
        <Metric label="Real-plan policy" value={<Badge value={pr?.policy.opa_conftest ?? 'UNKNOWN'}/>} detail="OPA / Conftest · no real plan executed"/>
      </div>
    </div>
    <div className="section-heading"><div><h2>Cloud security posture</h2><p>Synthetic fixture · highest known severity · context UNKNOWN</p></div><PageLink to="/posture">View posture</PageLink></div>
    {posture ? <DomainCards posture={posture}/> : <Panel title="Cloud posture"><Empty title="Report unavailable">A valid posture summary and completion receipt are required.</Empty></Panel>}
    <div className="two-columns mt-6"><Panel title="Findings by severity" eyebrow="PHASE 4 · SYNTHETIC ONLY">
      {posture ? <EvidenceChart rows={severity} label="Synthetic findings by severity"/> : <Empty title="Distribution unavailable">No posture evidence.</Empty>}
    </Panel><Panel title="Policy evidence" eyebrow="PHASE 3 · LOCAL SNAPSHOT" action={<Workflow size={20} className="muted"/>}>
      <div className="gate-list">{[['Checkov source scan', pr?.policy.checkov], ['Exception contract', pr?.policy.exception_contract], ['OPA / Conftest fixture tests', pr?.policy.policy_tests], ['OPA / Conftest real plan', pr?.policy.opa_conftest]].map(([label, status]) => <div key={label}><span>{label}</span><Badge value={status ?? 'UNKNOWN'}/></div>)}</div>
      <PageLink to="/scans">Inspect evidence status</PageLink>
    </Panel></div>
    <Note><LockKeyhole size={15} className="inline-icon"/> Deterministic tools decide. AI explains. PR reporting informs. Report completion does not authorize deployment.</Note>
  </>;
}
