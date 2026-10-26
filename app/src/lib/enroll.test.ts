import { describe, expect, it } from "vitest";

import { enrollSetup } from "./enroll";

describe("setup sent with the enroll command", () => {
  it("sends what is ticked, with the restart hour in UTC", () => {
    expect(
      enrollSetup(
        { recommended: true, docker: true, hour: 3, network: false },
        -420,
      ),
    ).toEqual({ recommended: true, docker: true, rebootHour: 20 });
    expect(
      enrollSetup(
        { recommended: false, docker: true, hour: 3, network: false },
        -420,
      ),
    ).toEqual({ recommended: false, docker: true, rebootHour: null });
    expect(
      enrollSetup(
        { recommended: true, docker: false, hour: 3, network: false },
        330,
      ),
    ).toEqual({ recommended: true, docker: false, rebootHour: 8 });
  });

  it("asks for the private network only when it is ticked", () => {
    expect(
      enrollSetup(
        { recommended: false, docker: false, hour: 3, network: true },
        0,
      ),
    ).toEqual({
      recommended: false,
      docker: false,
      rebootHour: null,
      network: true,
    });
  });
});
