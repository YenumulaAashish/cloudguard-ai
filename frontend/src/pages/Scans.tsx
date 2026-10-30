import type { ReportBundle } from '../types/reports';
import { Badge, Note, PageTitle, Panel } from '../components/ui';

export function Scans({ data }: { data: ReportBundle }) {
  const rows = [
    ['Checkov source gate', data.pr?.policy.checkov ?? 'UNKNOWN', 'Phase 3 sanitized local source-scan snapshot'],
    ['Exception contract', data.pr?.policy.exception_contract ?? 'UNKNOWN', 'Existing exception contract evidence'],
    ['OPA / Conftest tests', data.pr?.policy.policy_tests ?? 'UNKNOWN', 'Unit policies and synthetic fixtures; not real-plan compliance'],
    ['OPA / Conftest real plan', data.pr?.policy.opa_conftest ?? 'UNKNOWN', 'No authenticated real-plan execution'],
    ['Phase 3 integration', data.phase3?.completion ?? 'UNAVAILABLE', 'Completion receipt; not a policy verdict'],
    ['Phase 4 integration', data.phase4?.status ?? 'UNAVAILABLE', 'Synthetic fixture receipt; context remains UNKNOWN'],
    ['Hosted CI result', 'UNKNOWN', 'No hosted run identity is included in this dashboard bundle'],
  ];
  return <><PageTitle title="CI / scan status" text="Evidence provenance and gate outcomes, without inferred success."/>
    <div className="status-strip"><span>Latest supplied evidence</span><Badge value="OFFLINE / SYNTHETIC"/><span>Reviewed snapshot · no live refresh or timestamp claim</span></div>
    <Panel title="Validation evidence"><div className="table-wrap"><table><caption className="sr-only">Available evidence and limitations</caption><thead><tr><th>Check</th><th>Status</th><th>Evidence scope</th></tr></thead><tbody>{rows.map(([name, status, source]) => <tr key={name}><td>{name}</td><td><Badge value={status}/></td><td className="subtle">{source}</td></tr>)}</tbody></table></div></Panel>
    <div className="two-columns mt-6"><Panel title="Phase 4 completion receipt"><div className="gate-list">{['4.1 IAM', '4.2 Network', '4.3 Data Protection', '4.4 Security Graph', '4.5 Integration'].map(label => <div key={label}><span>{label}</span><Badge value={data.phase4?.components[label.slice(0, 3) as keyof typeof data.phase4.components] ?? 'UNKNOWN'}/></div>)}</div></Panel>
      <Panel title="How to read this evidence"><p>PASS is displayed only when supplied by a validated public gate field. Missing data remains UNKNOWN or unavailable.</p><p>Completion receipts are unsigned integration records. They do not attest authenticity, freshness, a shared plan, hosted execution or deployment safety.</p><p className="subtle">The historical Phase 4 receipt's Phase 5 field describes its original contract, not the project's current roadmap.</p></Panel></div>
    <Note>Checkov passed/failed/skipped scan totals and individual OPA test counts are not present in these four public contracts. The dashboard does not invent them from the number of normalized findings.</Note></>;
}
