import { describe, expect, it } from "vitest";

import { setupFlags } from "./enroll";

describe("setup in the enroll command", () => {
  it("adds what is ticked, with the restart hour in UTC", () => {
    expect(
      setupFlags({ recommended: true, docker: true, hour: 3, offset: -420 }),
    ).toBe(" --setup recommended,docker --reboot-hour 20");
    expect(
      setupFlags({ recommended: false, docker: true, hour: 3, offset: -420 }),
    ).toBe(" --setup docker");
    expect(
      setupFlags({ recommended: true, docker: false, hour: 3, offset: 330 }),
    ).toBe(" --setup recommended --reboot-hour 8");
    expect(
      setupFlags({ recommended: false, docker: false, hour: 3, offset: 0 }),
    ).toBe("");
  });
});
