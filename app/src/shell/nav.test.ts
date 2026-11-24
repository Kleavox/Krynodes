import { describe, expect, it } from "vitest";

import { SECTIONS } from "./nav";

describe("the menu", () => {
  it("is Fleet, Network, Passkeys and History", () => {
    expect(SECTIONS.map((section) => [section.label, section.to])).toEqual([
      ["Fleet", "/"],
      ["Network", "/network"],
      ["Passkeys", "/passkeys"],
      ["History", "/history"],
    ]);
  });
});
