import { describe, expect, it } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router';
import { App } from './App';
import { parseReport } from './services/reports';
import demo from './data/demo.json';
import type { ReportState } from './types/reports';

function mount(path = '/', state?: ReportState) {
  return render(<MemoryRouter initialEntries={[path]}><App initialState={state}/></MemoryRouter>);
}
describe('dashboard behavior', () => {
  it('renders report-derived risk and an honest offline context', () => {
    const value = structuredClone(demo); value.pr.risk.score = 27;
    mount('/', parseReport(value));
    expect(screen.getByRole('heading', { name: 'Security overview' })).toBeVisible();
    expect(screen.getByTestId('risk-score')).toHaveTextContent('27');
    expect(screen.getByText('AWS PENDING')).toBeVisible();
  });
  it('shows pending AWS without a login or deployment action', () => {
    mount('/aws');
    expect(screen.getByText('WAITING FOR AWS VERIFICATION')).toBeVisible();
    expect(screen.getByText('Pending / Not Connected')).toBeVisible();
    expect(screen.getByText('NOT VERIFIED')).toBeVisible();
    expect(screen.getByText('NOT EXECUTED')).toBeVisible();
    expect(screen.getByText('DISABLED')).toBeVisible();
    expect(screen.queryByRole('button', { name: /connect|deploy|login/i })).not.toBeInTheDocument();
  });
  it('marks advisory informational and withholds private prose', () => {
    mount('/advisory');
    expect(screen.getByText('ADVISORY — INFORMATIONAL ONLY')).toBeVisible();
    expect(screen.getByText('AI explanations do not override deterministic security controls.')).toBeVisible();
    expect(screen.getByText('Advisory prose is not published')).toBeVisible();
  });
  it('keeps real-plan UNKNOWN separate from fixture PASS', () => {
    mount('/scans');
    const row = screen.getByText('OPA / Conftest real plan').closest('tr')!;
    expect(within(row).getByText('UNKNOWN')).toBeVisible();
    expect(within(row).queryByText('PASS')).not.toBeInTheDocument();
  });
  it('filters by domain, severity and status and handles empty matches', async () => {
    const user = userEvent.setup(); mount('/findings');
    await user.selectOptions(screen.getByLabelText('Domain'), 'IAM');
    await user.selectOptions(screen.getByLabelText('Severity'), 'CRITICAL');
    expect(screen.getByText('1 groups shown')).toBeVisible();
    await user.selectOptions(screen.getByLabelText('Status'), 'FAILED');
    expect(screen.getByText('No matching groups')).toBeVisible();
  });
  it('searches only available aggregate metadata', async () => {
    const user = userEvent.setup(); mount('/findings');
    await user.type(screen.getByLabelText('Search findings'), 'approved exception');
    expect(screen.getByText('1 groups shown')).toBeVisible();
    expect(within(screen.getByRole('table')).getByText('APPROVED EXCEPTION')).toBeVisible();
  });
  it('supports keyboard-operable domain summary exploration', async () => {
    const user = userEvent.setup(); mount('/graph');
    const button = screen.getByRole('button', { name: /Network/ });
    button.focus(); await user.keyboard('{Enter}');
    expect(button).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByRole('heading', { name: 'Network summary' })).toBeVisible();
  });
  it('rejects private canaries without displaying input or a risk score', () => {
    const bad = structuredClone(demo);
    Object.assign(bad.pr.risk, { account: 'PRIVATE_CANARY', secret: 'PRIVATE_CANARY' });
    mount('/', parseReport(bad));
    expect(screen.getByText('Report rejected')).toBeVisible();
    expect(screen.queryByText(/PRIVATE_CANARY/)).not.toBeInTheDocument();
    expect(screen.queryByTestId('risk-score')).not.toBeInTheDocument();
  });
  it('shows unavailable reports and allows reset', async () => {
    const user = userEvent.setup(); mount('/', { status: 'unavailable' });
    expect(screen.getByText('Report unavailable')).toBeVisible();
    await user.click(screen.getByRole('button', { name: 'Reset demo' }));
    expect(screen.getByTestId('risk-score')).toHaveTextContent(String(demo.pr.risk.score));
  });
  it('handles empty findings without a fabricated scan pass', () => {
    mount('/findings', parseReport({ ...demo, pr: null, phase3: null, posture: null, phase4: null }));
    expect(screen.getByText('Reports unavailable')).toBeVisible();
    expect(screen.queryByText('PASS')).not.toBeInTheDocument();
  });
  it('shows advisory unavailable when the report is absent', () => {
    mount('/advisory', parseReport({ ...demo, pr: null, phase3: null }));
    expect(screen.getByText('Advisory unavailable')).toBeVisible();
  });
  it('shows graph unavailable when its report is absent', () => {
    mount('/graph', parseReport({ ...demo, posture: null, phase4: null }));
    expect(screen.getByText('Graph unavailable')).toBeVisible();
  });
  it('navigates between all eight pages', async () => {
    const user = userEvent.setup(); mount();
    for (const label of ['Findings', 'Cloud Posture', 'Risk Analysis', 'Security Graph', 'AI Advisory', 'CI / Scan Status', 'AWS Integration', 'Overview']) {
      const link = within(screen.getByRole('navigation')).getByRole('link', { name: new RegExp(label, 'i') });
      await user.click(link); expect(link).toHaveAttribute('aria-current', 'page');
    }
  });
});
