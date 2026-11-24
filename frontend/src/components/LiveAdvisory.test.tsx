import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, expect, it, vi } from 'vitest';
import { LiveAdvisory } from './LiveAdvisory';
import bundle from '../test/plan-demo.json';
afterEach(() => vi.unstubAllGlobals());
const findings = [{ id:'network-0', control_id:'CGA_NET_009', domain:'network', severity:'UNKNOWN', status:'UNKNOWN', resource_type:'aws_instance' }];
const response = (value: unknown) => ({ ok:true, text:async () => JSON.stringify(value) });
it('makes no automatic request and handles no key', async () => {
  const fetcher = vi.fn().mockResolvedValue(response({ configured:false, source:'SYNTHETIC', findings })); vi.stubGlobal('fetch', fetcher);
  render(<LiveAdvisory/>); expect(fetcher).not.toHaveBeenCalled();
  await userEvent.click(screen.getByText('Load advisory finding selector'));
  expect(screen.getByText('Live AI advisory is not configured.')).toBeVisible();
  expect(screen.getByText('Explain with AI')).toBeDisabled();
});
it('requires a click, renders advisory separately and preserves deterministic severity', async () => {
  const advice = Object.fromEntries(['summary','why_it_matters','recommended_action','remediation_steps','terraform_guidance','limitations'].map(k => [k,'Human review guidance.']));
  const fetcher = vi.fn().mockResolvedValueOnce(response({ configured:true,source:'SYNTHETIC',findings })).mockResolvedValueOnce(response({ available:true,informational_only:true,authority:'deterministic-cloudguard',advisory:advice }));
  vi.stubGlobal('fetch', fetcher); render(<LiveAdvisory/>);
  await userEvent.click(screen.getByText('Load advisory finding selector')); expect(fetcher).toHaveBeenCalledTimes(1);
  await userEvent.click(screen.getByText('Explain with AI'));
  expect(screen.getByText('AI-generated advisory — informational only.')).toBeVisible();
  expect(screen.getAllByText('UNKNOWN').length).toBeGreaterThan(0); expect(fetcher).toHaveBeenCalledTimes(2);
});
it('shows loading then safe provider error', async () => {
  let reject!: (e: Error) => void;
  vi.stubGlobal('fetch', vi.fn().mockImplementation(() => new Promise((_, r) => { reject = r; })));
  render(<LiveAdvisory/>); await userEvent.click(screen.getByText('Load advisory finding selector'));
  expect(screen.getByText('Loading advisory service…')).toBeVisible();
  reject(Error('PRIVATE_CANARY'));
  expect(await screen.findByText('Live advisory unavailable. No deterministic result was changed.')).toBeVisible();
  expect(screen.queryByText('PRIVATE_CANARY')).not.toBeInTheDocument();
});
it('binds actual catalog requests to the server revision without sending raw findings', async () => {
  const catalogId='01234567-0123-0123-0123-012345678901';
  const fetcher=vi.fn().mockResolvedValueOnce(response({ configured:true,source:bundle.source,findings:bundle.findings.findings,catalog:bundle.findings,catalog_id:catalogId })).mockResolvedValueOnce({ok:false,text:async ()=>'{}'});
  vi.stubGlobal('fetch',fetcher);render(<LiveAdvisory/>);
  await userEvent.click(screen.getByText('Load advisory finding selector'));
  await userEvent.click(screen.getByText('Explain with AI'));
  const options=fetcher.mock.calls[1][1];
  expect(JSON.parse(options.body)).toEqual({finding_id:bundle.findings.findings[0].id,catalog_id:catalogId});
  expect(screen.getByText('Live advisory unavailable. No deterministic result was changed.')).toBeVisible();
});
