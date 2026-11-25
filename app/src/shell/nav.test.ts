import { describe, expect, it } from "vitest";

import { SECTIONS } from "./nav";

describe("the menu", () => {
  it("nav lists Stacks and Checks", () => {
    expect(SECTIONS.map((section) => [section.label, section.to])).toEqual([
      ["Fleet", "/"],
      ["Network", "/network"],
      ["Stacks", "/stacks"],
      ["Checks", "/checks"],
      ["Passkeys", "/passkeys"],
      ["History", "/history"],
    ]);
  });
});
