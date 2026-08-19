import { formatProbability } from "../format";
import { GAUGE_CIRCUMFERENCE, gaugeColour } from "../verdict";

export function Gauge({
  probability,
  verdict,
  urlOnly,
}: {
  probability: number;
  verdict: string;
  urlOnly: boolean;
}) {
  const offset = GAUGE_CIRCUMFERENCE * (1 - probability);
  return (
    <div className="gauge">
      <svg viewBox="0 0 120 120" className="gauge-svg" aria-hidden="true">
        <circle className="gauge-track" cx="60" cy="60" r="52" />
        <circle
          className="gauge-arc"
          cx="60"
          cy="60"
          r="52"
          style={{ stroke: gaugeColour(verdict), strokeDashoffset: offset }}
        />
      </svg>
      <div className="gauge-label">
        <strong>{formatProbability(probability)}</strong>
        <span>
          {urlOnly ? (
            <>
              URL-string
              <br />
              score
            </>
          ) : (
            <>
              phishing
              <br />
              probability
            </>
          )}
        </span>
      </div>
    </div>
  );
}
