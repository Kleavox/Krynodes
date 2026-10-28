import { describe, expect, it } from "vitest";

import { cn } from "./utils";

describe("cn", () => {
  it("lets the selection border beat a severity border", () => {
    expect(cn("border-destructive/50", "border-primary-line")).toBe(
      "border-primary-line",
    );
    expect(cn("border-warning/50", "border-primary-line")).toBe(
      "border-primary-line",
    );
  });
});
