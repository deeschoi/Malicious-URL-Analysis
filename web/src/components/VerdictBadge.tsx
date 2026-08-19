import { badgeClass, verdictLabel } from "../verdict";

export function VerdictBadge({ verdict }: { verdict: string }) {
  return <span className={`badge ${badgeClass(verdict)}`}>{verdictLabel(verdict)}</span>;
}
