import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis, Cell } from 'recharts';
import { useId } from 'react';

export const colors: Record<string, string> = {
  CRITICAL: '#f7838f', HIGH: '#ecae74', MEDIUM: '#e7cb7b', LOW: '#6dd9bd', INFO: '#82b9ec', UNKNOWN: '#b8a2f7',
};
export function EvidenceChart({ rows, label }: { rows: { name: string; count: number; color?: string }[]; label: string }) {
  const id = useId();
  return <figure aria-labelledby={id}><figcaption id={id} className="sr-only">{label}</figcaption>
    <div className="chart" aria-hidden="true"><ResponsiveContainer width="100%" height="100%" minWidth={0} initialDimension={{ width: 400, height: 175 }}>
      <BarChart data={rows} margin={{ left: -25, right: 10, top: 12, bottom: 4 }} accessibilityLayer={false}>
        <CartesianGrid stroke="#273143" vertical={false} strokeDasharray="3 5"/>
        <XAxis dataKey="name" tick={{ fill: '#a9b5c8', fontSize: 11 }} axisLine={false} tickLine={false}/>
        <YAxis allowDecimals={false} tick={{ fill: '#a9b5c8', fontSize: 11 }} axisLine={false} tickLine={false}/>
        <Tooltip cursor={{ fill: '#ffffff06' }} contentStyle={{ background: '#151e2d', border: '1px solid #34425a', borderRadius: 8, color: '#eef3ff' }}/>
        <Bar dataKey="count" radius={[4, 4, 0, 0]} maxBarSize={37} isAnimationActive={false}>
          {rows.map(row => <Cell key={row.name} fill={row.color ?? colors[row.name] ?? '#6dd9bd'}/>)}</Bar>
      </BarChart>
    </ResponsiveContainer></div>
    <div className="chart-key">{rows.map(row => <span key={row.name}><i style={{ background: row.color ?? colors[row.name] ?? '#6dd9bd' }}/>{row.name} <b>{row.count}</b></span>)}</div>
  </figure>;
}
