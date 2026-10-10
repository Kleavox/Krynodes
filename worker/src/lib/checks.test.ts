import { describe, expect, it } from "vitest";

import { validateCheckTarget } from "./checks";

describe("Krynodes check validation", () => {
  it("accepts bounded HTTP, TCP, and service targets", () => {
    expect(validateCheckTarget("HTTP", "https://example.com/health")).toBe(
      "https://example.com/health",
    );
    expect(validateCheckTarget("TCP", "127.0.0.1:5432")).toBe("127.0.0.1:5432");
    expect(validateCheckTarget("SERVICE", "nginx.service")).toBe(
      "nginx.service",
    );
    expect(validateCheckTarget("TCP", "localhost:99999")).toBeNull();
    expect(validateCheckTarget("SERVICE", "nginx; reboot")).toBeNull();
    expect(validateCheckTarget("CONTAINER", "adguard-adguard-1")).toBe(
      "adguard-adguard-1",
    );
    expect(validateCheckTarget("CONTAINER", "web.1_a")).toBe("web.1_a");
    expect(validateCheckTarget("CONTAINER", "-web")).toBeNull();
    expect(validateCheckTarget("CONTAINER", "web;reboot")).toBeNull();
  });
});
