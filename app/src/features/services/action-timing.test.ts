import { describe, expect, it } from "vitest";

import { MODES } from "@/features/deploy/deploy-dialog";

import { DESCRIPTION } from "./action-dialog";

describe("when an action starts", () => {
  it("says a server starts it within seconds", () => {
    const soon = "Servers start it within seconds.";
    expect(DESCRIPTION.start).toBe(soon);
    expect(DESCRIPTION.restart).toBe(soon);
    expect(MODES.find((mode) => mode.value === "parallel")?.detail).toBe(
      "Every server runs it at once.",
    );
  });
});
