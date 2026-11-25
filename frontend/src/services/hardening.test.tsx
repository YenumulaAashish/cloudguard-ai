import { render,screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { expect,it } from 'vitest';
import fixture from '../test/plan-demo.json';
import { parseReport } from './reports';
import { App } from '../App';
function authenticated() {return {...structuredClone(fixture),source:'AUTHENTICATED_PLAN',findings:{...structuredClone(fixture.findings),source:'AUTHENTICATED_PLAN'},pr:{...structuredClone(fixture.pr),policy:{...fixture.pr.policy,opa_conftest:'FAIL'}}};}
it('shows imported plan evidence without claiming live connectivity',()=>{
 render(<MemoryRouter initialEntries={['/aws']}><App initialState={parseReport(authenticated())}/></MemoryRouter>);
 expect(screen.getByText(/Authenticated-plan report supplied/)).toBeVisible();
 expect(screen.getByText('LIVE CONNECTIVITY UNVERIFIED')).toBeVisible();
 expect(screen.queryByText(/No real Terraform plan has been executed/)).not.toBeInTheDocument();
 expect(screen.getByText(/authenticity and freshness remain UNKNOWN/)).toBeVisible();
});
it('uses plan verdict label without asserting an external plan never ran',()=>{
 render(<MemoryRouter><App initialState={parseReport(authenticated())}/></MemoryRouter>);
 expect(screen.getByText('Imported authenticated-plan verdict · provenance unverified')).toBeVisible();
 expect(screen.queryByText(/no real plan executed/)).not.toBeInTheDocument();
});
it('renders allowlisted failed reasons from a new bundle',()=>{
 const value={...authenticated(),version:'1.2',policy_reasons:[{rule_id:'UNKNOWN',reason_code:'UNRESOLVED_SECURITY_FIELD',count:1}]};
 render(<MemoryRouter initialEntries={['/scans']}><App initialState={parseReport(value)}/></MemoryRouter>);
 expect(screen.getByText(/UNRESOLVED_SECURITY_FIELD/)).toBeVisible();
 expect(screen.getByText(/Phase 4 analyzer receipt/)).toBeVisible();
});
it('does not guess missing historic rule reasons',()=>{
 render(<MemoryRouter initialEntries={['/scans']}><App initialState={parseReport(authenticated())}/></MemoryRouter>);
 expect(screen.getByText(/Safe rule reasons are unavailable/)).toBeVisible();
});
it('rejects arbitrary reasons, raw prose, duplicate pairs and contradictory verdicts',()=>{
 const r={rule_id:'UNKNOWN',reason_code:'UNRESOLVED_SECURITY_FIELD',count:1};
 for(const reasons of [[{...r,reason_code:'PRIVATE_CANARY'}],[{...r,message:'PRIVATE_CANARY'}],[r,r],[{...r,count:0}],[{...r,count:true}]])
  expect(parseReport({...authenticated(),version:'1.2',policy_reasons:reasons}).status).toBe('malformed');
 const f=authenticated();f.pr.policy.opa_conftest='PASS';
 expect(parseReport({...f,version:'1.2',policy_reasons:[r]}).status).toBe('malformed');
});
it('keeps unknown analyzer context separate from Phase 3 scanner evidence',()=>{
 render(<MemoryRouter initialEntries={['/findings']}><App initialState={parseReport(authenticated())}/></MemoryRouter>);
 expect(screen.getByText(/UNKNOWN means unresolved or unsupported context/)).toBeVisible();
 expect(screen.getByText(/Phase 4 analyzer findings are separate from Phase 3/)).toBeVisible();
});
