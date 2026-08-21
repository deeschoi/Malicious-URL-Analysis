import { describe, expect, it } from "vitest";
import { parseAnalystReply, splitInlineEmphasis } from "./analystReply";

describe("parseAnalystReply", () => {
  it("splits explicit Findings and Commentary sections", () => {
    const reply = `## Findings
**Toward phishing**
- TLDLegitimateProb = 0.001 (SHAP +2.22)

## Commentary
The uncommon TLD outweighs the benign URL traits, so the verdict stays suspicious.`;

    const parsed = parseAnalystReply(reply);
    expect(parsed).not.toBeNull();
    expect(parsed?.findings.some((block) => block.kind === "subhead")).toBe(true);
    expect(parsed?.findings.some((block) => block.kind === "bullet")).toBe(true);
    expect(parsed?.commentary[0]).toMatchObject({
      kind: "paragraph",
      text: expect.stringContaining("uncommon TLD"),
    });
  });

  it("renders findings-only replies without showing raw section headings", () => {
    const reply = `## Findings
- **Toward legitimate**
  - HTML line count = 2277 (SHAP -3.90)
  - On-domain links = 355 (SHAP -2.95)`;

    const parsed = parseAnalystReply(reply);
    expect(parsed).not.toBeNull();
    expect(parsed?.findings.some((block) => block.text.includes("## Findings"))).toBe(false);
    expect(parsed?.findings.some((block) => block.kind === "subhead" && block.text === "Toward legitimate")).toBe(
      true,
    );
    expect(parsed?.findings.filter((block) => block.kind === "bullet")).toHaveLength(2);
    expect(parsed?.commentary).toHaveLength(0);
  });

  it("infers sections from legacy bold feature headers", () => {
    const reply = `This scan hit a 404, so only the URL string was scored.

**Key features that moved the score toward phishing**
- TLDLegitimateProb = 0.001 (SHAP +2.22)

**Features that pulled the score toward legitimate**
- IsHTTPS = 1 (SHAP -1.02)

The scan therefore lands in the suspicious band because the TLD prior dominates.`;

    const parsed = parseAnalystReply(reply);
    expect(parsed).not.toBeNull();
    expect(parsed?.findings.filter((block) => block.kind === "bullet")).toHaveLength(2);
    expect(parsed?.commentary.some((block) => block.text.includes("404"))).toBe(true);
    expect(parsed?.commentary.some((block) => block.text.includes("suspicious band"))).toBe(
      true,
    );
  });
});

describe("splitInlineEmphasis", () => {
  it("keeps plain text when no emphasis is present", () => {
    expect(splitInlineEmphasis("plain text")).toEqual([{ bold: false, text: "plain text" }]);
  });

  it("splits bold segments", () => {
    expect(splitInlineEmphasis("SHAP **+2.22** now")).toEqual([
      { bold: false, text: "SHAP " },
      { bold: true, text: "+2.22" },
      { bold: false, text: " now" },
    ]);
  });
});
