import { describe, expect, it } from "vitest";

import { enrollmentStep, pollEnrollment } from "./enrollment";

describe("enrollmentStep", () => {
  it("starts with nothing created", () => {
    expect(enrollmentStep(false, undefined)).toBe("start");
  });

  it("waits while the command exists and no server has used it", () => {
    expect(enrollmentStep(true, undefined)).toBe("waiting");
    expect(enrollmentStep(true, { status: "pending" })).toBe("waiting");
  });

  it("is done once a server enrolled with the token", () => {
    expect(
      enrollmentStep(true, {
        status: "used",
        node: { id: "n1", name: "web-01" },
      }),
    ).toBe("connected");
  });

  it("offers a new command when the token ran out", () => {
    expect(enrollmentStep(true, { status: "expired" })).toBe("expired");
  });
});

describe("pollEnrollment", () => {
  it("polls every three seconds only while the token is unused", () => {
    expect(pollEnrollment(undefined)).toBe(3_000);
    expect(pollEnrollment({ status: "pending" })).toBe(3_000);
    expect(pollEnrollment({ status: "used", node: null })).toBe(false);
    expect(pollEnrollment({ status: "expired" })).toBe(false);
  });
});
