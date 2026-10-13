import { describe, expect, it } from "vitest";

import { enrollSetup } from "./enroll";

describe("setup sent with the enroll command", () => {
  it("sends what is ticked, with the restart hour in UTC", () => {
    expect(
      enrollSetup({ recommended: true, docker: true, hour: 3 }, -420),
    ).toEqual({ recommended: true, docker: true, rebootHour: 20 });
    expect(
      enrollSetup({ recommended: false, docker: true, hour: 3 }, -420),
    ).toEqual({ recommended: false, docker: true, rebootHour: null });
    expect(
      enrollSetup({ recommended: true, docker: false, hour: 3 }, 330),
    ).toEqual({ recommended: true, docker: false, rebootHour: 8 });
  });
});
