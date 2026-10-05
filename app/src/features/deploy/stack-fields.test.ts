import { describe, expect, it } from "vitest";

import { secretsProblem } from "./stack-fields";

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
