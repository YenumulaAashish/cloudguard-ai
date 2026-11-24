import Ajv2020 from 'ajv/dist/2020';
import schema from '../data/public-findings.schema.json';
export interface PublicFinding { id: string; domain: 'iam'|'network'|'data'; control_id: string; resource_type: string; severity: 'CRITICAL'|'HIGH'|'MEDIUM'|'LOW'|'UNKNOWN'; status: 'FINDING'|'UNKNOWN'; requires_review: boolean }
export interface PublicCatalog { schema_version:'1.0'; source:'SYNTHETIC'|'OFFLINE'|'AUTHENTICATED_PLAN'; context_status:'UNKNOWN'; informational_only:true; total_count:number; omitted_count:number; findings:PublicFinding[] }
const validate = new Ajv2020({ strict:true }).compile(schema);
export function validCatalog(value: unknown): value is PublicCatalog {
  if (!validate(value)) return false;
  const c = value as unknown as PublicCatalog;
  return c.total_count === c.findings.length+c.omitted_count && new Set(c.findings.map(f => f.id)).size === c.findings.length && c.findings.every(f => f.control_id.startsWith({ iam:'CGA_IAM_', network:'CGA_NET_', data:'CGA_DATA_' }[f.domain]));
}
