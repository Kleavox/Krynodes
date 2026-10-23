import { describe, expect, it } from "vitest";

import { heldProblem, secretChange, secretsProblem } from "./stack-fields";

describe("secrets the stack already has", () => {
  const before = ["A", "B", "C"];
  const untouched = before.map((name) => ({ name, value: null }));

  it("sends nothing when nothing was touched, so Cancel and Save alike change nothing", () => {
    expect(secretChange(untouched, [], before)).toBeUndefined();
    expect(
      secretChange(untouched, [{ name: " ", value: "" }], before),
    ).toBeUndefined();
  });

  it("keeps what was left alone, sets what was replaced or added, and drops what was removed", () => {
    expect(
      secretChange(
        [
          { name: "A", value: null },
          { name: "B", value: "new" },
        ],
        [{ name: " D ", value: "4" }],
        before,
      ),
    ).toEqual({ keep: ["A"], set: { B: "new", D: "4" } });
  });

  it("empties the file when every secret is removed", () => {
    expect(secretChange([], [], before)).toEqual({ keep: [], set: {} });
  });

  it("refuses a new secret named like one the stack has, and a bad replacement", () => {
    expect(heldProblem(untouched, [{ name: "B", value: "x" }])).toBe(
      "The secret B is listed twice.",
    );
    expect(heldProblem([{ name: "A", value: "it's" }], [])).toBe(
      "The secret A cannot contain ' or a line break.",
    );
    expect(heldProblem(untouched, [{ name: "D", value: "x" }])).toBeNull();
  });
});

describe("secrets", () => {
  it("accepts names an env file can hold and values that stay on one line", () => {
    expect(
      secretsProblem([
        { name: "SMTP_PASSWORD", value: "p@ss word$" },
        { name: "", value: "" },
      ]),
    ).toBeNull();
    expect(secretsProblem([{ name: "1BAD", value: "x" }])).toMatch(/letters/u);
    expect(
      secretsProblem([
        { name: "A", value: "x" },
        { name: "A", value: "y" },
      ]),
    ).toBe("The secret A is listed twice.");
    expect(secretsProblem([{ name: "A", value: "it's" }])).toBe(
      "The secret A cannot contain ' or a line break.",
    );
    expect(secretsProblem([{ name: "", value: "orphan" }])).toMatch(/letters/u);
  });
});
