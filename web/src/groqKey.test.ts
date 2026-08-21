import { afterEach, describe, expect, it } from "vitest";
import { clearGroqApiKey, getGroqApiKey, setGroqApiKey } from "./groqKey";

describe("groqKey", () => {
  afterEach(() => {
    clearGroqApiKey();
  });

  it("round-trips a key through sessionStorage", () => {
    expect(getGroqApiKey()).toBe("");
    setGroqApiKey("  gsk_test  ");
    expect(getGroqApiKey()).toBe("gsk_test");
    clearGroqApiKey();
    expect(getGroqApiKey()).toBe("");
  });
});
