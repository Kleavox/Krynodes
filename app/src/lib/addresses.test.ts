import { describe, expect, it } from "vitest";

import { addressCount, STAND_IN } from "./addresses";

describe("server addresses", () => {
  it("counts addresses in words", () => {
    expect(addressCount(1)).toBe("1 address");
    expect(addressCount(3)).toBe("3 addresses");
  });

  it("stands in with nothing from a real server", () => {
    expect(STAND_IN).toEqual({ label: "IPv4", address: "000.000.000.00" });
  });
});
