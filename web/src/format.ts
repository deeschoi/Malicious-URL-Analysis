export function pct(value: number | null | undefined, digits = 1): string {
  if (value == null || Number.isNaN(value)) return "—";
  return `${(value * 100).toFixed(digits)}%`;
}

export function fixed(value: number | null | undefined, digits: number): string {
  if (value == null || Number.isNaN(value)) return "—";
  return Number(value).toFixed(digits);
}

export function formatProbability(value: number): string {
  const percent = value * 100;
  return `${percent.toFixed(percent < 1 ? 2 : 0)}%`;
}

export function formatDuration(ms: number | null | undefined): string {
  if (ms == null || Number.isNaN(ms)) return "—";
  if (ms < 1000) return `${Math.round(ms)} ms`;
  return `${(ms / 1000).toFixed(1)} s`;
}

export function formatTimestamp(iso: string | null | undefined): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function yesNo(value: boolean | null | undefined): string {
  if (value == null) return "not probed";
  return value ? "yes" : "no";
}
