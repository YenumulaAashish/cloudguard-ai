import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, expect, it, vi } from 'vitest';
import { LiveAdvisory } from './LiveAdvisory';
afterEach(() => vi.unstubAllGlobals());
const findings = [{ id:'network-0', control_id:'CGA_NET_009', domain:'network', severity:'UNKNOWN', status:'UNKNOWN', resource_type:'aws_instance' }];
const response = (value: unknown) => ({ ok:true, text:async () => JSON.stringify(value) });
it('makes no automatic request and handles no key', async () => {
  const fetcher = vi.fn().mockResolvedValue(response({ configured:false, source:'SYNTHETIC', findings })); vi.stubGlobal('fetch', fetcher);
  render(<LiveAdvisory/>); expect(fetcher).not.toHaveBeenCalled();
  await userEvent.click(screen.getByText('Load synthetic finding selector'));
  expect(screen.getByText('Live AI advisory is not configured.')).toBeVisible();
  expect(screen.getByText('Explain with AI')).toBeDisabled();
});
it('requires a click, renders advisory separately and preserves deterministic severity', async () => {
  const advice = Object.fromEntries(['summary','why_it_matters','recommended_action','remediation_steps','terraform_guidance','limitations'].map(k => [k,'Human review guidance.']));
  const fetcher = vi.fn().mockResolvedValueOnce(response({ configured:true,source:'SYNTHETIC',findings })).mockResolvedValueOnce(response({ available:true,informational_only:true,authority:'deterministic-cloudguard',advisory:advice }));
  vi.stubGlobal('fetch', fetcher); render(<LiveAdvisory/>);
  await userEvent.click(screen.getByText('Load synthetic finding selector')); expect(fetcher).toHaveBeenCalledTimes(1);
  await userEvent.click(screen.getByText('Explain with AI'));
  expect(screen.getByText('AI-generated advisory — informational only.')).toBeVisible();
  expect(screen.getAllByText('UNKNOWN').length).toBeGreaterThan(0); expect(fetcher).toHaveBeenCalledTimes(2);
});
it('shows loading then safe provider error', async () => {
  let reject!: (e: Error) => void;
  vi.stubGlobal('fetch', vi.fn().mockImplementation(() => new Promise((_, r) => { reject = r; })));
  render(<LiveAdvisory/>); await userEvent.click(screen.getByText('Load synthetic finding selector'));
  expect(screen.getByText('Loading advisory service…')).toBeVisible();
  reject(Error('PRIVATE_CANARY'));
  expect(await screen.findByText('Live advisory unavailable. No deterministic result was changed.')).toBeVisible();
  expect(screen.queryByText('PRIVATE_CANARY')).not.toBeInTheDocument();
});
