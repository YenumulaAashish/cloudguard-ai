import type { PublicCatalog } from '../services/publicFindings';
import { Badge, Panel } from './ui';
export function ActualFindings({ catalog }: { catalog:PublicCatalog }) {
  return <Panel title="Analyzer findings" className="mt-6"><p>Source: {catalog.source}. Context, freshness and authenticity: UNKNOWN. {catalog.total_count} findings; {catalog.omitted_count} omitted by the public size limit. Resource identities and prose remain private.</p>
    <div className="table-wrap"><table><thead><tr><th>Control</th><th>Domain</th><th>Severity</th><th>Status</th><th>Resource type</th><th>Review</th></tr></thead><tbody>{catalog.findings.map(f => <tr key={f.id}><td>{f.control_id}</td><td>{f.domain}</td><td><Badge value={f.severity}/></td><td><Badge value={f.status}/></td><td>{f.resource_type}</td><td>{f.requires_review?'Required':'No flag'}</td></tr>)}</tbody></table></div></Panel>;
}
