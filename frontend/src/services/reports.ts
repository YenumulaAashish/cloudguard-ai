import Ajv2020 from 'ajv/dist/2020';
import contracts from '../data/contracts.json';
import type { ReportBundle, ReportState, FindingGroup, Severity, Domain } from '../types/reports';

const ajv = new Ajv2020({ allErrors: false, strict: true });
const validators = Object.fromEntries(Object.entries(contracts).map(([key, schema]) => [key, ajv.compile(schema)]));
const keys = ['version', 'source', 'pr', 'phase3', 'posture', 'phase4'];
export const MAX_BUNDLE_BYTES = 20_000;

/** Validate closed existing schemas before exposing any data to a component.
 * No error includes input values. Nothing is uploaded or persisted. */
export function parseReport(value: unknown): ReportState {
  if (value == null) return { status: 'unavailable' };
  try {
    if (JSON.stringify(value).length > MAX_BUNDLE_BYTES || typeof value !== 'object' || Array.isArray(value)) throw Error();
    const raw = value as Record<string, unknown>;
    if (Object.keys(raw).length !== keys.length || !keys.every(key => Object.hasOwn(raw, key))) throw Error();
    if (raw.version !== '1.0' || raw.source !== 'OFFLINE_SYNTHETIC') throw Error();
    for (const key of ['pr', 'phase3', 'posture', 'phase4']) {
      if (raw[key] !== null && !validators[key](raw[key])) throw Error();
      if (raw[key] !== null && JSON.stringify(raw[key]).length > 4096) throw Error();
    }
    const data = structuredClone(value) as ReportBundle;
    if (Boolean(data.pr) !== Boolean(data.phase3) || Boolean(data.posture) !== Boolean(data.phase4)) throw Error();
    if (data.pr) {
      const { findings: f, advisory: a } = data.pr;
      // This envelope cannot attest a real plan. Reject contradictory known
      // real-plan verdicts rather than relabeling or silently overriding them.
      if (data.pr.policy.opa_conftest !== 'UNKNOWN') throw Error();
      if (f.failed + f.approved_exceptions > f.total ||
          a.findings_reviewed !== (a.mode === 'NOT_RUN' ? 0 : f.total) ||
          a.mode !== data.phase3?.advisory_mode) throw Error();
    }
    if (data.posture) {
      for (const domain of Object.values(data.posture.domains)) {
        if (Object.values(domain.severity_counts).reduce((a, b) => a + b, 0) !== domain.finding_count) throw Error();
      }
      if (data.posture.graph.requires_review !== (data.posture.graph.unresolved_count > 0)) throw Error();
    }
    return { status: 'ready', data };
  } catch { return { status: 'malformed' }; }
}

export function parseText(text: string): ReportState {
  if (new TextEncoder().encode(text).byteLength > MAX_BUNDLE_BYTES) return { status: 'malformed' };
  try { return parseReport(JSON.parse(text)); } catch { return { status: 'malformed' }; }
}

export async function loadReport(file: File): Promise<ReportState> {
  if (file.size > MAX_BUNDLE_BYTES) return { status: 'malformed' };
  try { return parseText(await file.text()); } catch { return { status: 'unavailable' }; }
}

/** Aggregate rows only; no invented control IDs, per-finding review flags or identities. */
export function findingGroups(data: ReportBundle): FindingGroup[] {
  const rows: FindingGroup[] = [];
  if (data.pr) {
    const f = data.pr.findings;
    const groups = [['APPROVED EXCEPTION', f.approved_exceptions], ['FAILED', f.failed],
      ['UNKNOWN', f.total - f.failed - f.approved_exceptions]] as const;
    for (const [status, count] of groups) if (count) rows.push({ id: `policy-${status}`, domain: 'Policy', severity: 'UNKNOWN', status, count, source: 'Offline source scan' });
  }
  const labels: Record<string, Domain> = { iam: 'IAM', network: 'Network', data: 'Data Protection' };
  if (data.posture) for (const [key, domain] of Object.entries(data.posture.domains)) {
    for (const [severity, count] of Object.entries(domain.severity_counts)) if (count) rows.push({
      id: `${key}-${severity}`, domain: labels[key], severity: severity.toUpperCase() as Severity,
      status: 'UNKNOWN', count, source: 'Synthetic fixture',
    });
  }
  return rows;
}
