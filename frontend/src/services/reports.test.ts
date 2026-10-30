import { describe, expect, it } from 'vitest';
import { parseReport, parseText, loadReport, findingGroups } from './reports';
import demo from '../data/demo.json';

describe('closed public report boundary', () => {
  it('accepts existing public reports and keeps supplied risk unchanged', () => {
    const value = structuredClone(demo);
    value.pr.risk.score = 27;
    const state = parseReport(value);
    expect(state.status).toBe('ready');
    if (state.status === 'ready') expect(state.data.pr?.risk.score).toBe(27);
  });
  it('preserves UNKNOWN real-plan evidence', () => {
    const state = parseReport(demo);
    expect(state.status === 'ready' && state.data.pr?.policy.opa_conftest).toBe('UNKNOWN');
  });
  it.each(['PASS', 'FAIL'])('rejects unsupported real-plan %s claims in an offline bundle', verdict => {
    const value = structuredClone(demo); value.pr.policy.opa_conftest = verdict;
    expect(parseReport(value).status).toBe('malformed');
  });
  it.each([null, undefined])('marks unavailable input unavailable', value => expect(parseReport(value).status).toBe('unavailable'));
  it.each(['{', 'null trailing', '[]', '"PASS"'])('rejects invalid JSON or shape', text => expect(parseText(text).status).toBe('malformed'));
  it('rejects oversize input before parsing', () => expect(parseText(' '.repeat(20_001)).status).toBe('malformed'));
  it('rejects oversize files without reading', async () => {
    let read = false;
    expect((await loadReport({ size: 30_000, text: async () => { read = true; return '{}'; } } as File)).status).toBe('malformed');
    expect(read).toBe(false);
  });
  it('handles read errors without leaking values', async () => {
    expect(await loadReport({ size: 10, text: async () => { throw Error('PRIVATE_CANARY'); } } as unknown as File)).toEqual({ status: 'unavailable' });
  });
  it.each(['pr', 'posture', 'phase3', 'phase4'] as const)('rejects unexpected/private fields in %s', field => {
    const value = structuredClone(demo);
    Object.assign(value[field], { resource: 'PRIVATE_CANARY', topology: [], credentials: 'PRIVATE_CANARY' });
    expect(parseReport(value)).toEqual({ status: 'malformed' });
  });
  it.each(['pr', 'posture'] as const)('requires the completion receipt for %s', field => {
    const value = { ...structuredClone(demo), [field === 'pr' ? 'phase3' : 'phase4']: null };
    expect(parseReport(value).status).toBe('malformed');
  });
  it('supports absent report pairs without inferring values', () => {
    const state = parseReport({ ...demo, pr: null, phase3: null, posture: null, phase4: null });
    expect(state.status).toBe('ready');
    if (state.status === 'ready') expect(findingGroups(state.data)).toEqual([]);
  });
  it('rejects inconsistent public finding counts', () => {
    const value = structuredClone(demo); value.pr.findings.total = 0;
    expect(parseReport(value).status).toBe('malformed');
  });
  it('rejects inconsistent advisory count', () => {
    const value = structuredClone(demo); value.pr.advisory.findings_reviewed = 0;
    expect(parseReport(value).status).toBe('malformed');
  });
  it('rejects inconsistent domain totals', () => {
    const value = structuredClone(demo); value.posture.domains.iam.finding_count += 1;
    expect(parseReport(value).status).toBe('malformed');
  });
  it('rejects incorrect graph review flag', () => {
    const value = structuredClone(demo); value.posture.graph.requires_review = true;
    expect(parseReport(value).status).toBe('malformed');
  });
  it('rejects real-plan claims without a future provenance adapter', () => {
    expect(parseReport({ ...demo, source: 'REAL_AWS_PLAN' }).status).toBe('malformed');
  });
  it('never synthesizes per-finding identities or statuses', () => {
    const state = parseReport(demo);
    if (state.status !== 'ready') throw Error('Fixture invalid');
    const rows = findingGroups(state.data);
    expect(rows.filter(r => r.domain !== 'Policy').every(r => r.status === 'UNKNOWN')).toBe(true);
    expect(rows.every(r => !('resource' in r) && !('control_id' in r))).toBe(true);
    expect(rows.filter(r => r.domain === 'Policy').reduce((n, r) => n + r.count, 0)).toBe(demo.pr.findings.total);
  });
  it('does not mutate input', () => {
    const before = JSON.stringify(demo); const state = parseReport(demo);
    if (state.status === 'ready' && state.data.pr) state.data.pr.risk.score = 90;
    expect(JSON.stringify(demo)).toBe(before);
  });
});
