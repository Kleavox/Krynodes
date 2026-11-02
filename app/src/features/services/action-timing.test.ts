import { describe, expect, it } from "vitest";

import { MODES } from "@/features/deploy/deploy-dialog";

import { DESCRIPTION } from "./action-dialog";

describe("when an action starts", () => {
  it("says a server on agent 0.7.6 starts it within seconds", () => {
    const soon =
      "Servers on agent 0.7.6 or newer start it within seconds; older ones at their next report.";
    expect(DESCRIPTION.start).toBe(soon);
    expect(DESCRIPTION.restart).toBe(soon);
    expect(MODES.find((mode) => mode.value === "parallel")?.detail).toBe(
      "Every server runs it at once; one before agent 0.7.6 at its next report.",
    );
  });
});
