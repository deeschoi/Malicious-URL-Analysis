export const GAUGE_CIRCUMFERENCE = 327;

export const VERDICT_LABEL: Record<string, string> = {
  phishing: "phishing",
  suspicious: "suspicious",
  "probably safe": "probably safe",
  legitimate: "legitimate",
  unreachable: "unreachable",
  fetch_failed: "fetch failed",
};

export const BADGE_CLASS: Record<string, string> = {
  phishing: "is-phishing",
  suspicious: "is-suspicious",
  "probably safe": "is-safe",
  legitimate: "is-safe",
  unreachable: "is-unknown",
  fetch_failed: "is-unknown",
};

export const GAUGE_COLOUR: Record<string, string> = {
  phishing: "#ff5f56",
  suspicious: "#f5a524",
  "probably safe": "#35c98b",
  legitimate: "#35c98b",
  unreachable: "#a89478",
  fetch_failed: "#a89478",
};

export const VERDICT_ORDER = [
  "phishing",
  "suspicious",
  "probably safe",
  "legitimate",
  "unreachable",
  "fetch_failed",
] as const;

export function verdictLabel(verdict: string): string {
  return VERDICT_LABEL[verdict] ?? verdict;
}

export function badgeClass(verdict: string): string {
  return BADGE_CLASS[verdict] ?? "is-unknown";
}

export function gaugeColour(verdict: string): string {
  return GAUGE_COLOUR[verdict] ?? "#a89478";
}

const URL_PATTERN_CLASS: Record<string, string> = {
  phishing: "is-pattern-phishing",
  suspicious: "is-pattern-suspicious",
  "probably safe": "is-pattern-safe",
  legitimate: "is-pattern-safe",
};

/** Styling for the URL-string chip. Never reuses the live-verdict classes. */
export function urlPatternClass(risk: string): string {
  return URL_PATTERN_CLASS[risk] ?? "";
}

export function urlPatternLabel(risk: string): string {
  return `URL pattern: ${verdictLabel(risk)}`;
}
