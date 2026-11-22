import { describe, expect, it } from "vitest";

import { SECTIONS } from "./nav";

describe("the menu", () => {
  it("is Fleet, Passkeys and History", () => {
    expect(SECTIONS.map((section) => [section.label, section.to])).toEqual([
      ["Fleet", "/"],
      ["Passkeys", "/passkeys"],
      ["History", "/history"],
    ]);
  });
});
