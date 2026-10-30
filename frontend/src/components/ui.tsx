import type { ReactNode } from 'react';
import { ShieldCheck, Info, ArrowUpRight } from 'lucide-react';
import { Link } from 'react-router';

export function Badge({ value }: { value: string }) {
  const color = ['PASS', 'LOW', 'COMPLETE'].includes(value) ? 'green'
    : ['CRITICAL', 'FAIL', 'FAILED'].includes(value) ? 'red'
    : ['HIGH', 'MEDIUM', 'REVIEW REQUIRED', 'PENDING'].includes(value) ? 'amber'
    : ['UNKNOWN', 'NOT RUN', 'UNAVAILABLE'].includes(value) ? 'purple' : 'neutral';
  return <span className={`badge ${color}`}><span className="badge-dot" aria-hidden="true" />{value}</span>;
}
export function Panel({ title, eyebrow, children, className = '', action }: {
  title: string; eyebrow?: string; children: ReactNode; className?: string; action?: ReactNode;
}) {
  return <section className={`panel ${className}`}><div className="panel-heading"><div>
    {eyebrow && <p className="eyebrow">{eyebrow}</p>}<h2>{title}</h2></div>{action}</div>{children}</section>;
}
export function Note({ children, tone = '' }: { children: ReactNode; tone?: string }) {
  return <div className={`note ${tone}`}><Info size={17} aria-hidden="true"/><div>{children}</div></div>;
}
export function Empty({ title, children }: { title: string; children: ReactNode }) {
  return <div className="empty"><ShieldCheck size={29} aria-hidden="true"/><h3>{title}</h3><p>{children}</p></div>;
}
export function PageTitle({ title, text, tag }: { title: string; text: string; tag?: string }) {
  return <div className="page-title"><div><p className="eyebrow">SECURITY WORKSPACE / {tag ?? 'OFFLINE EVIDENCE'}</p><h1>{title}</h1><p>{text}</p></div></div>;
}
export function Metric({ label, value, detail, accent = '' }: { label: string; value: ReactNode; detail: string; accent?: string }) {
  return <div className={`metric ${accent}`}><span>{label}</span><strong>{value}</strong><small>{detail}</small></div>;
}
export function PageLink({ to, children }: { to: string; children: ReactNode }) {
  return <Link className="text-link" to={to}>{children}<ArrowUpRight size={15} aria-hidden="true"/></Link>;
}
