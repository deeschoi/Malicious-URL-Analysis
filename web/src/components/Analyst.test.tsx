import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Analyst } from "./Analyst";
import { clearGroqApiKey } from "../groqKey";
import type { ScanResult } from "../types";

function jsonResponse(body: unknown, status = 200): Promise<Response> {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    statusText: "OK",
    json: () => Promise.resolve(body),
  } as Response);
}

function scanResult(): ScanResult {
  return {
    url: "https://example.com",
    final_url: "https://example.com",
    redirect_chain: [],
    http_status: 200,
    reachability: {
      status: "resolved",
      dns_ok: true,
      page_fetched: true,
      tls_inspected: true,
      final_url: "https://example.com",
      status_code: 200,
      n_redirects: 0,
      redirect_chain: [],
      truncated: false,
    },
    verdict: "legitimate",
    risk: "legitimate",
    prediction: "legitimate",
    threshold: 0.205,
    warnings: [],
    features: {},
    url_only: false,
    probability: 0.02,
    rationale: "Looks fine.",
    notes: [],
    error: null,
    signals: [],
    coverage: {
      reachability: "resolved",
      dns_ok: true,
      page_fetched: true,
      https: true,
      tls_checked: true,
      http_status: 200,
      redirects: 0,
      truncated: false,
      features_used: 48,
      features_in_dataset: 48,
    },
    model: "XGBoost",
    model_quality: {
      accuracy: 0.9995,
      auroc: 0.9999,
      recall_at_warn: 0.9995,
      false_positive_rate_at_warn: 0.0005,
      warn_threshold: 0.205,
      block_threshold: 0.9,
    },
  };
}

afterEach(() => {
  clearGroqApiKey();
  vi.restoreAllMocks();
});

describe("Analyst BYOK", () => {
  it("asks for a Groq key and sends it only on chat", async () => {
    const spy = vi.fn((input: RequestInfo | URL, _init?: RequestInit) => {
      const url = String(input);
      if (url.includes("/api/agent")) {
        return jsonResponse({
          enabled: true,
          requires_user_key: true,
          model: "openai/gpt-oss-120b",
          detail: "Scans work without a key. Chat needs a Groq API key from you.",
        });
      }
      if (url.includes("/api/chat")) {
        return jsonResponse({
          reply: "## Findings\n- Off-domain links = 3\n## Commentary\nGrounded.",
          tools_used: [],
          model: "fake",
        });
      }
      return jsonResponse({});
    });
    vi.stubGlobal("fetch", spy);

    const user = userEvent.setup();
    render(<Analyst result={scanResult()} />);

    expect(await screen.findByLabelText("Groq API key")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Why this verdict?" })).toBeDisabled();

    await user.type(screen.getByLabelText("Groq API key"), "gsk_test_key_xxxxxxxx");
    await user.click(screen.getByRole("button", { name: "Save" }));

    const chip = screen.getByRole("button", { name: "Why this verdict?" });
    await waitFor(() => expect(chip).not.toBeDisabled());
    await user.click(chip);

    await waitFor(() =>
      expect(
        spy.mock.calls.some(([input]) => String(input).includes("/api/chat")),
      ).toBe(true),
    );
    const chatCall = spy.mock.calls.find(([input]) =>
      String(input).includes("/api/chat"),
    );
    const headers = new Headers(chatCall?.[1]?.headers);
    expect(headers.get("X-Groq-Api-Key")).toBe("gsk_test_key_xxxxxxxx");
    expect(
      spy.mock.calls
        .filter(([input]) => String(input).includes("/api/agent"))
        .every(([, init]) => {
          const agentHeaders = new Headers(init?.headers);
          return agentHeaders.get("X-Groq-Api-Key") === null;
        }),
    ).toBe(true);
  });
});
