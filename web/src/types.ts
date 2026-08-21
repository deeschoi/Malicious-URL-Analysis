export type Verdict =
  | "phishing"
  | "suspicious"
  | "probably safe"
  | "legitimate"
  | "unreachable"
  | "fetch_failed"
  | string;

export interface Signal {
  feature: string;
  label: string;
  contribution: number;
  measured: boolean;
  value_meaning: string;
  encoding_unreliable: boolean;
  evidence: string;
  direction: string;
}

export interface Coverage {
  reachability: string;
  dns_ok: boolean | null;
  page_fetched: boolean;
  tls_checked: boolean;
  features_used: number;
  features_in_dataset: number;
  features_unavailable: number;
}

export interface ModelQuality {
  accuracy: number;
  auroc: number;
  recall_at_warn: number;
  false_positive_rate_at_warn: number;
  warn_threshold: number;
  block_threshold: number;
}

export interface ScanResult {
  url: string;
  final_url: string;
  verdict: Verdict;
  url_only: boolean;
  probability: number;
  /** Page-model score before any disagreement fallback; null when HTML was not measured. */
  page_probability?: number | null;
  /** URL-string-only score, always present when the fallback model is loaded. */
  url_probability?: number | null;
  /** Judgment of the URL string alone. Not a live-site verdict. */
  url_pattern_risk?: Verdict | null;
  /** True when the URL-string score replaced a high page-model score. */
  url_disagreement?: boolean;
  rationale: string;
  notes: string[];
  error: string | null;
  signals: Signal[];
  coverage: Coverage;
  model: string;
  model_quality: ModelQuality;
  scan_id?: number | null;
  duration_ms?: number;
}

export interface ScanRecord {
  id: number;
  created_at: string | null;
  url: string;
  host: string;
  verdict: string;
  probability: number;
  model: string;
  duration_ms: number;
  page_fetched: boolean;
  tls_checked: boolean;
}

export interface ScanList {
  scans: ScanRecord[];
}

export interface DailyStat {
  date: string;
  scans: number;
  mean_probability: number;
}

export interface ScanStats {
  total_scans: number;
  verdicts: Record<string, number>;
  daily: DailyStat[];
}

export interface Leakage {
  duplicate_row_fraction?: number;
  random_split_test_rows_seen_in_train?: number;
  conflicting_label_patterns?: number;
}

export interface ModelRow {
  model: string;
  random_accuracy: number;
  grouped_accuracy: number;
  accuracy_optimism: number;
}

export interface EncodingAuditRow {
  feature: string;
  "documented -1 means": string;
  "P(phish|-1)": number;
  "P(phish|+1)": number;
  verdict: string;
}

export interface ScenarioRow {
  scenario: string;
  n_features: number;
  accuracy: number;
  delta_vs_full: number;
}

export interface Findings {
  leakage: Leakage;
  models: ModelRow[];
  reversed_features: string[];
  no_signal_features: string[];
  encoding_audit: EncodingAuditRow[];
  scenarios: ScenarioRow[];
  unavailable_features: Array<{ feature: string; reason: string }>;
}
