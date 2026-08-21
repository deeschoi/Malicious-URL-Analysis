import { type FormEvent, useEffect, useRef, useState } from "react";
import { askAnalyst, fetchAgentStatus } from "../api";
import type { AgentStatus, ChatMessage, ScanResult, ToolUse } from "../types";

/** Questions worth asking about any scan, phrased so the answer has to cite
 *  measured evidence rather than an opinion about the URL string. */
const PROMPTS = [
  "Why this verdict?",
  "What would change your mind?",
  "What could this scan have missed?",
  "How much should I trust this score?",
];

const TOOL_LABEL: Record<string, string> = {
  get_signals: "read the SHAP attributions",
  get_features: "read the extracted features",
  get_extraction_warnings: "checked what could not be measured",
  get_model_card: "read the model card",
  get_host_history: "looked up this host in scan history",
  rescan_url: "ran a fresh scan",
};

interface Turn extends ChatMessage {
  tools?: ToolUse[];
}

export function Analyst({ result }: { result: ScanResult }) {
  const [status, setStatus] = useState<AgentStatus | null>(null);
  const [turns, setTurns] = useState<Turn[]>([]);
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const endRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetchAgentStatus()
      .then((payload) => {
        if (!cancelled) setStatus(payload);
      })
      .catch(() => {
        if (!cancelled) setStatus({ enabled: false, model: null, detail: null });
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // Each scan is its own conversation. Carrying turns across scans would let
  // the analyst answer about one URL using evidence from another.
  useEffect(() => {
    setTurns([]);
    setError(null);
    setDraft("");
  }, [result.url, result.probability]);

  useEffect(() => {
    endRef.current?.scrollIntoView({ block: "nearest" });
  }, [turns, busy]);

  async function ask(question: string) {
    const text = question.trim();
    if (!text || busy) return;
    const next: Turn[] = [...turns, { role: "user", content: text }];
    setTurns(next);
    setDraft("");
    setBusy(true);
    setError(null);
    try {
      const reply = await askAnalyst(
        result,
        next.map(({ role, content }) => ({ role, content })),
      );
      setTurns([
        ...next,
        { role: "assistant", content: reply.reply, tools: reply.tools_used },
      ]);
    } catch (err) {
      setError(err instanceof Error ? err.message : "The analyst is unavailable.");
    } finally {
      setBusy(false);
    }
  }

  function onSubmit(event: FormEvent) {
    event.preventDefault();
    void ask(draft);
  }

  if (status && !status.enabled) {
    return (
      <section className="analyst is-off">
        <h3 className="section-title">Ask about this scan</h3>
        <p className="section-sub">
          {status.detail ??
            "The analyst is not configured on this deployment."}
        </p>
      </section>
    );
  }

  return (
    <section className="analyst" aria-label="Ask about this scan">
      <h3 className="section-title">Ask about this scan</h3>
      <p className="section-sub">
        Answers are grounded in this scan's own evidence — the SHAP
        attributions, the extracted features, what could not be measured, and
        the model card. The analyst explains the classifier's verdict; it does
        not produce one of its own.
      </p>

      <div className="analyst-log" aria-live="polite" aria-busy={busy}>
        {turns.length === 0 && !busy ? (
          <p className="analyst-hint">
            Nothing asked yet. Try one of the questions below.
          </p>
        ) : null}
        {turns.map((turn, index) => (
          <div
            key={`${turn.role}-${index}`}
            className={`analyst-turn is-${turn.role}`}
          >
            <span className="analyst-who">
              {turn.role === "user" ? "You" : "Analyst"}
            </span>
            <div className="analyst-text">{turn.content}</div>
            {turn.tools && turn.tools.length ? (
              <div className="analyst-tools">
                Checked:{" "}
                {[
                  ...new Set(
                    turn.tools.map((t) => TOOL_LABEL[t.tool] ?? t.tool),
                  ),
                ].join(", ")}
              </div>
            ) : null}
          </div>
        ))}
        {busy ? (
          <div className="analyst-turn is-assistant">
            <span className="analyst-who">Analyst</span>
            <div className="analyst-text analyst-thinking">Reading the evidence…</div>
          </div>
        ) : null}
        <div ref={endRef} />
      </div>

      {error ? (
        <div className="status is-error" role="alert">
          {error}
        </div>
      ) : null}

      <div className="analyst-prompts">
        {PROMPTS.map((prompt) => (
          <button
            key={prompt}
            type="button"
            className="chip"
            disabled={busy}
            onClick={() => void ask(prompt)}
          >
            {prompt}
          </button>
        ))}
      </div>

      <form className="analyst-bar" onSubmit={onSubmit} autoComplete="off">
        <input
          className="url-input"
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
          placeholder="Ask about the signals, the score, or what was missed"
          aria-label="Ask the analyst about this scan"
          maxLength={2000}
          disabled={busy}
        />
        <button className="scan-button" type="submit" disabled={busy || !draft.trim()}>
          Ask
        </button>
      </form>
      {status?.model ? (
        <p className="analyst-model">
          Answers generated by {status.model} via Groq, restricted to this scan's
          evidence. Treat them as an explanation of the model, not as security advice.
        </p>
      ) : null}
    </section>
  );
}
