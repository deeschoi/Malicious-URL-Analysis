import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { EmptyState } from "./components/EmptyState";
import { FindingsView } from "./views/Findings";
import { History } from "./views/History";
import { Stats } from "./views/Stats";

function jsonResponse(body: unknown, status = 200): Promise<Response> {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(body),
  } as Response);
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("History", () => {
  it("shows an empty state when the API has no scans", async () => {
    vi.stubGlobal("fetch", vi.fn(() => jsonResponse({ scans: [] })));
    render(
      <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <History />
      </MemoryRouter>,
    );
    expect(await screen.findByText("No scans yet")).toBeInTheDocument();
  });

  it("renders a stored scan row", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() =>
        jsonResponse({
          scans: [
            {
              id: 1,
              created_at: "2026-08-16T12:00:00+00:00",
              url: "https://example.com/login",
              host: "example.com",
              verdict: "suspicious",
              probability: 0.62,
              model: "XGBoost",
              duration_ms: 123,
              page_fetched: true,
              tls_checked: true,
            },
          ],
        }),
      ),
    );
    render(
      <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <History />
      </MemoryRouter>,
    );
    expect(await screen.findByText("example.com")).toBeInTheDocument();
    expect(screen.getByText("suspicious")).toBeInTheDocument();
    expect(screen.getByText("Scan again")).toBeInTheDocument();
  });
});

describe("Stats", () => {
  it("shows an empty state when there is no telemetry", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() => jsonResponse({ total_scans: 0, verdicts: {}, daily: [] })),
    );
    render(
      <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <Stats />
      </MemoryRouter>,
    );
    expect(await screen.findByText("No telemetry yet")).toBeInTheDocument();
  });

  it("renders verdict mix totals", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() =>
        jsonResponse({
          total_scans: 3,
          verdicts: { "probably safe": 2, suspicious: 1 },
          daily: [{ date: "2026-08-16", scans: 3, mean_probability: 0.21 }],
        }),
      ),
    );
    render(
      <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <Stats />
      </MemoryRouter>,
    );
    expect(await screen.findByText("scans recorded")).toBeInTheDocument();
    expect(screen.getByText("3")).toBeInTheDocument();
    expect(screen.getByText("Verdict mix")).toBeInTheDocument();
  });
});

describe("Findings", () => {
  it("renders the leakage headline from the API payload", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() =>
        jsonResponse({
          leakage: {
            duplicate_row_fraction: 0.471,
            random_split_test_rows_seen_in_train: 0.646,
            conflicting_label_patterns: 64,
          },
          models: [
            {
              model: "LightGBM",
              random_accuracy: 0.973,
              grouped_accuracy: 0.956,
              accuracy_optimism: 0.017,
            },
          ],
          reversed_features: ["HTTPS_token"],
          no_signal_features: [],
          encoding_audit: [],
          scenarios: [],
          unavailable_features: [],
        }),
      ),
    );
    render(<FindingsView />);
    expect(
      await screen.findByText("Duplicate feature vectors inflate the published accuracy"),
    ).toBeInTheDocument();
    expect(screen.getByText("LightGBM")).toBeInTheDocument();
  });
});

describe("EmptyState", () => {
  it("renders the title", () => {
    render(<EmptyState title="Nothing here">Try again later.</EmptyState>);
    expect(screen.getByText("Nothing here")).toBeInTheDocument();
  });
});
