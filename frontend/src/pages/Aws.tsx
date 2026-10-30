import { CloudOff, ArrowRight, LockKeyhole } from 'lucide-react';
import { Badge, Note, PageTitle, Panel } from '../components/ui';

export function Aws() {
  return <><PageTitle title="AWS integration" text="Offline analysis is available while account verification is pending."/>
    <div className="aws-hero"><CloudOff size={42}/><Badge value="WAITING FOR AWS VERIFICATION"/><h2>Pending / Not Connected</h2><p>Your security workspace operates without AWS.<br/>Phase 5.2 remains blocked. No real Terraform plan has been executed.</p></div>
    <div className="two-columns"><Panel title="Integration status"><div className="gate-list">{[['AWS Account Verification', 'PENDING'], ['OIDC', 'NOT VERIFIED'], ['Real Terraform Plan', 'NOT EXECUTED'], ['AWS Deployment', 'DISABLED']].map(([name, value]) => <div key={name}><span>{name}</span><Badge value={value}/></div>)}</div></Panel>
      <Panel title="A read-only reporting boundary"><LockKeyhole size={25} className="accent mb-4"/><p>The browser has no AWS login, credentials, SDK or deployment controls.</p><p>Future authenticated planning belongs in protected GitHub Actions. Only reviewed, sanitized evidence may reach this dashboard.</p><p className="subtle">Loading a report cannot connect AWS or verify OIDC.</p></Panel></div>
    <Panel title="Future real-plan reporting flow" eyebrow="PLANNED ARCHITECTURE · NOT EXECUTED" className="mt-6"><ol className="pipeline">{['GitHub Actions', 'GitHub OIDC', 'cloudguard-ai-plan role', 'terraform plan', 'CloudGuard analyzers', 'Sanitized report', 'Dashboard'].map((step, i) => <li key={step}><span><small>{String(i + 1).padStart(2, '0')}</small>{step}</span>{i < 6 && <ArrowRight size={15} aria-hidden="true"/>}</li>)}</ol></Panel>
    <Note>Real-plan inputs need an explicitly reviewed provenance adapter before they can be labeled REAL AWS PLAN. This release accepts offline snapshots only and cannot claim AWS connectivity.</Note></>;
}
