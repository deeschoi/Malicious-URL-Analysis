import { errorMessage } from "./api";
import { fixed, formatDuration, formatProbability, formatTimestamp, pct } from "./format";
import { badgeClass, gaugeColour, verdictLabel } from "./verdict";

describe("format", () => {
  it("renders percents and dashes for missing values", () => {
    expect(pct(0.471)).toBe("47.1%");
    expect(pct(null)).toBe("—");
    expect(fixed(0.9559, 4)).toBe("0.9559");
    expect(fixed(undefined, 2)).toBe("—");
  });

  it("formats probabilities the way the scanner gauge does", () => {
    expect(formatProbability(0.83)).toBe("83%");
    expect(formatProbability(0.004)).toBe("0.40%");
  });

  it("formats durations and timestamps", () => {
    expect(formatDuration(123)).toBe("123 ms");
    expect(formatDuration(1500)).toBe("1.5 s");
    expect(formatTimestamp(null)).toBe("—");
    expect(formatTimestamp("not-a-date")).toBe("not-a-date");
  });
});

describe("verdict", () => {
  it("maps live and reachability verdicts", () => {
    expect(verdictLabel("fetch_failed")).toBe("fetch failed");
    expect(badgeClass("phishing")).toBe("is-phishing");
    expect(badgeClass("mystery")).toBe("is-unknown");
    expect(gaugeColour("suspicious")).toBe("#f5a524");
  });
});

describe("errorMessage", () => {
  it("reads FastAPI string and validation details", () => {
    expect(errorMessage({ detail: "Refusing to scan a local address." })).toBe(
      "Refusing to scan a local address.",
    );
    expect(errorMessage({ detail: [{ msg: "field required" }] })).toBe("field required");
    expect(errorMessage({})).toBe("Request failed.");
  });
});
