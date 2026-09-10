import type { ReactNode } from 'react';
export function Stat({ label, value, icon }: { label: string; value: ReactNode; icon: string }) {
  return <div className="stat"><span className="stat-icon">{icon}</span><div><div className="stat-label">{label}</div><div className="stat-value">{value}</div></div></div>;
}
