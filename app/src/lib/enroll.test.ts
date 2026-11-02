import { describe, expect, it } from "vitest";

import { enrollSetup } from "./enroll";

describe("setup sent with the enroll command", () => {
  it("sends Docker and the restart hour in UTC", () => {
    expect(
      enrollSetup(
        { docker: true, hour: 3, network: false, adminName: "user1" },
        -420,
      ),
    ).toEqual({ docker: true, rebootHour: 20, adminName: "user1" });
    expect(
      enrollSetup(
        { docker: false, hour: 3, network: false, adminName: "user1" },
        330,
      ),
    ).toEqual({ docker: false, rebootHour: 8, adminName: "user1" });
  });

  it("asks for the private network only when it is ticked", () => {
    expect(
      enrollSetup(
        { docker: false, hour: 3, network: true, adminName: "user1" },
        0,
      ),
    ).toEqual({
      docker: false,
      rebootHour: 3,
      network: true,
      adminName: "user1",
    });
  });

  it("never sends the protections, SELinux or AppArmor, which every new server gets", () => {
    const ticked = {
      recommended: false,
      docker: false,
      hour: 3,
      network: false,
      confine: true,
      adminName: "user1",
    };
    expect(enrollSetup(ticked, 0)).toEqual({
      docker: false,
      rebootHour: 3,
      adminName: "user1",
    });
  });

  it("always sends the admin user's name, trimmed", () => {
    const base = { docker: false, hour: 3, network: false };
    expect(enrollSetup({ ...base, adminName: " user1 " }, 0)).toMatchObject({
      adminName: "user1",
    });
    expect(enrollSetup(base, 0)).toMatchObject({ adminName: "" });
  });
});
