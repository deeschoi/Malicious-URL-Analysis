import { type FormEvent, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { scanUrl } from "../api";
import { Gauge } from "../components/Gauge";
import { StatusMessage } from "../components/EmptyState";
import { VerdictBadge } from "../components/VerdictBadge";
import { pct, yesNo } from "../format";
import type { ScanResult, Signal } from "../types";

const EXAMPLES = [
  { url: "https://www.wikipedia.org", label: "wikipedia.org" },
  { url: "http://neverssl.com", label: "neverssl.com" },
  { url: "https://github.com/python/cpython", label: "github.com" },
];

const LIVE_SIGNALS_TITLE = "Why the model decided this";
const LIVE_SIGNALS_SUB =
  "Each bar is a SHAP value: how far that single signal pushed the score, in log-odds, away from the model's average prediction.";
const URL_ONLY_SIGNALS_TITLE = "URL-string score (host not observed)";
const URL_ONLY_SIGNALS_SUB =
  "The model still scored the URL string and placeholder features. That number is not a live-site judgment.";

export function Scanner() {
  const [params] = useSearchParams();
  const [url, setUrl] = useState(params.get("url") ?? "");
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);

  useEffect(() => {
    const preset = params.get("url");
    if (preset) setUrl(preset);
  }, [params]);

  async function runScan(target: string) {
    const trimmed = target.trim();
    if (!trimmed) return;
    setBusy(true);
    setResult(null);
    setError(false);
        setStatus("Fetching the page and parsing its HTML…");
    try {
      const payload = await scanUrl(trimmed);
      setResult(payload);
      setStatus(null);
    } catch (err) {
      setError(true);
      setStatus(err instanceof Error ? err.message : "Scan failed.");
    } finally {
      setBusy(false);
    }
  }

  function onSubmit(event: FormEvent) {
    event.preventDefault();
    void runScan(url);
  }

  return (
    <>
      <form className="scanbar" autoComplete="off" onSubmit={onSubmit}>
        <input
          className="url-input"
          value={url}
          onChange={(event) => setUrl(event.target.value)}
          placeholder="Paste a URL, for example github.com or https://example.com"
          aria-label="URL to scan"
          spellCheck={false}
        />
        <button className="scan-button" type="submit" disabled={busy}>
          Scan
        </button>
      </form>
      <p className="examples">
        Try:
        {EXAMPLES.map((example) => (
          <button
            key={example.url}
            type="button"
            className="chip"
            onClick={() => {
              setUrl(example.url);
              void runScan(example.url);
            }}
          >
            {example.label}
          </button>
        ))}
      </p>
      {status ? <StatusMessage message={status} error={error} /> : null}
      {result ? <ScanResultView result={result} /> : null}
    </>
  );
}

function ScanResultView({ result }: { result: ScanResult }) {
  const coverage = result.coverage;
  const quality = result.model_quality;
  const notes = [...(result.notes ?? [])];
  if (result.error) notes.unshift(result.error);

  return (
    <article className="result">
      <div className="verdict-card">
        <div className="verdict-main">
          <VerdictBadge verdict={result.verdict} />
          <h2 className="verdict-url">{result.final_url}</h2>
          <p className="rationale">{result.rationale}</p>
        </div>
        <Gauge
          probability={result.probability}
          verdict={result.verdict}
          urlOnly={result.url_only}
        />
      </div>

      {notes.length ? (
        <div className="notes">
          {notes.map((text) => (
            <div className="note" key={text}>
              {text}
            </div>
          ))}
        </div>
      ) : null}

      <h3 className="section-title">
        {result.url_only ? URL_ONLY_SIGNALS_TITLE : LIVE_SIGNALS_TITLE}
      </h3>
      <p className="section-sub">
        {result.url_only ? URL_ONLY_SIGNALS_SUB : LIVE_SIGNALS_SUB}
      </p>
      <SignalList signals={result.signals} />

      <div className="meta-grid">
        <div className="meta-card">
          <h4>Scan coverage</h4>
          <dl>
            <Meta term="Reachability" value={coverage.reachability || "—"} />
            <Meta term="DNS resolved" value={yesNo(coverage.dns_ok)} />
            <Meta term="Page downloaded" value={yesNo(coverage.page_fetched)} />
            <Meta term="Certificate inspected" value={yesNo(coverage.tls_checked)} />
            <Meta
              term="Signals used"
              value={`${coverage.features_used} of ${coverage.features_in_dataset}`}
            />
            <Meta
              term="Unavailable in 2026"
              value={`${coverage.features_unavailable} features`}
            />
            <Meta term="Model" value={result.model} />
          </dl>
        </div>
        <div className="meta-card">
          <h4>Model reliability</h4>
          <dl>
            <Meta term="Held-out accuracy" value={pct(quality.accuracy)} />
            <Meta term="AUROC" value={quality.auroc.toFixed(3)} />
            <Meta
              term="Phishing caught at warn level"
              value={`${(quality.recall_at_warn * 100).toFixed(0)}%`}
            />
            <Meta
              term="False alarm rate"
              value={pct(quality.false_positive_rate_at_warn)}
            />
            <Meta
              term="Warn / block thresholds"
              value={`${quality.warn_threshold.toFixed(2)} / ${quality.block_threshold.toFixed(2)}`}
            />
          </dl>
        </div>
      </div>
    </article>
  );
}

function Meta({ term, value }: { term: string; value: string }) {
  return (
    <>
      <dt>{term}</dt>
      <dd>{value}</dd>
    </>
  );
}

function SignalList({ signals }: { signals: Signal[] }) {
  const scale = Math.max(...signals.map((s) => Math.abs(s.contribution)), 0.5);
  return (
    <ul className="signals">
      {signals.map((signal) => {
        const width = (Math.abs(signal.contribution) / scale) * 50;
        const dir = signal.contribution >= 0 ? "up" : "down";
        const flat = Math.abs(signal.contribution) < 0.005;
        return (
          <li
            key={signal.feature}
            className={`signal${signal.measured ? "" : " is-unmeasured"}`}
          >
            <div>
              <span className="signal-name">{signal.label}</span>
              <span className="signal-value">
                {signal.measured ? signal.value_meaning : "Could not be measured"}
              </span>
              {signal.encoding_unreliable ? (
                <span
                  className="signal-flag"
                  title="In this dataset the feature behaves opposite to its documented meaning."
                >
                  encoding unreliable
                </span>
              ) : null}
            </div>
            <div className="signal-evidence">{signal.evidence}</div>
            <div className="bar">
              <span className="bar-axis" />
              <span className={`bar-fill ${dir}`} style={{ width: `${width}%` }} />
            </div>
            <div
              className={`signal-score ${flat ? "flat" : dir}`}
              title={signal.direction}
            >
              {signal.contribution >= 0 ? "+" : "−"}
              {Math.abs(signal.contribution).toFixed(2)}
            </div>
          </li>
        );
      })}
    </ul>
  );
}
