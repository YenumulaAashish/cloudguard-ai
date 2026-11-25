import { CloudOff, LockKeyhole } from 'lucide-react';
import { Badge, Note, PageTitle, Panel } from '../components/ui';
import type { ReportBundle } from '../types/reports';
export function Aws({data}:{data?:ReportBundle}) {
  const imported=data?.source==='AUTHENTICATED_PLAN';
  return <><PageTitle title="AWS integration" text="Report origin and current connectivity are separate evidence scopes."/>
    <div className="aws-hero"><CloudOff size={42}/><Badge value="LIVE CONNECTIVITY UNVERIFIED"/><h2>No live connection in this dashboard</h2><p>{imported?'Authenticated-plan report supplied. Its origin is claimed by the imported file; authenticity and freshness remain UNKNOWN.':'No authenticated-plan report supplied. The displayed snapshot does not establish whether an external plan has run.'}</p></div>
    <div className="two-columns"><Panel title="Integration status"><div className="gate-list">{[['Live AWS connectivity','UNVERIFIED'],['OIDC in imported evidence','NOT INDEPENDENTLY VERIFIED'],['Terraform plan report',imported?'SUPPLIED':'NOT SUPPLIED'],['AWS Deployment','DISABLED']].map(([name,value])=><div key={name}><span>{name}</span><Badge value={value}/></div>)}</div></Panel>
      <Panel title="A read-only reporting boundary"><LockKeyhole size={25}/><p>The browser has no AWS login, credentials, SDK or deployment controls.</p><p>Protected GitHub Actions can produce sanitized plan evidence. Importing it does not reconnect AWS or verify the live IAM trust.</p><p>Historical owner-confirmed authentication and planning succeeded; the historical security verdict failed. Current report values remain authoritative for display.</p></Panel></div>
    <Note>Plan execution, a passing policy verdict, source authenticity, freshness and live connectivity are distinct. No imported report authorizes another attempt or deployment.</Note></>;
}
