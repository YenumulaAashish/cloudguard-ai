// Public schema 1.0 only. Deliberately no private finding, policy, or topology types.
export type Gate = 'PASS' | 'FAIL' | 'UNKNOWN';
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'UNKNOWN';
export type Category = Exclude<Severity, 'INFO'> | 'NONE';
export type Domain = 'Policy' | 'IAM' | 'Network' | 'Data Protection';
export interface PrSummary {
  schema_version: '1.0'; generated_by: 'cloudguard-ai'; informational_only: true;
  policy: Record<'checkov' | 'opa_conftest' | 'exception_contract' | 'policy_tests', Gate>;
  findings: { total: number; failed: number; approved_exceptions: number };
  risk: { score: number; category: Exclude<Category, 'UNKNOWN'>; requires_review: boolean };
  advisory: { mode: 'offline' | 'ai' | 'NOT_RUN'; findings_reviewed: number };
}
export interface DomainSummary {
  category: Category; finding_count: number; requires_review: boolean; unknown_context_count: number;
  severity_counts: Record<'critical' | 'high' | 'medium' | 'low' | 'unknown', number>;
}
export interface PostureSummary {
  schema_version: '1.0'; integrator: 'cloudguard-posture'; informational_only: true; phase: '4';
  completion_requirement: 'VALID_RECEIPT_REQUIRED'; context_status: 'UNKNOWN';
  domains: Record<'iam' | 'network' | 'data', DomainSummary>;
  graph: { unresolved_count: number; requires_review: boolean };
  overall: { category: Category; requires_review: true };
}
export interface Phase3Receipt {
  schema_version: '1.0'; phase: '3'; informational_only: true; completion: 'COMPLETE'; advisory_mode: 'offline';
  components: Record<'normalization' | 'risk' | 'advisory' | 'pr_reporting', 'PASS'>;
  validation: Record<'schemas' | 'cross_phase_consistency' | 'byte_reproduction', 'PASS'>;
}
export interface Phase4Receipt {
  schema_version: '1.0'; phase: '4'; status: 'COMPLETE'; informational_only: true;
  components: Record<'4.1' | '4.2' | '4.3' | '4.4' | '4.5', 'COMPLETE'>;
  phase5_status: 'NOT_STARTED'; context_status: 'UNKNOWN'; execution_mode: 'offline';
  validation: Record<'input_schemas' | 'cross_report_consistency' | 'output_schemas' | 'byte_reproduction', 'PASS'>;
}
export interface ReportBundle {
  version: '1.0'; source: 'OFFLINE_SYNTHETIC';
  pr: PrSummary | null; phase3: Phase3Receipt | null;
  posture: PostureSummary | null; phase4: Phase4Receipt | null;
}
export interface FindingGroup {
  id: string; domain: Domain; severity: Severity; count: number;
  status: 'APPROVED EXCEPTION' | 'FAILED' | 'UNKNOWN';
  source: 'Offline source scan' | 'Synthetic fixture';
}
export type ReportState = { status: 'ready'; data: ReportBundle } | { status: 'unavailable' | 'malformed' };
