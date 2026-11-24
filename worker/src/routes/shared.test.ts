import { describe, expect, it } from "vitest";

import { dnsName } from "./shared";

describe("a machine's network name", () => {
  it("is the one label the agent writes into the hosts file", () => {
    for (const [name, label] of [
      ["VPS_2 (Singapore)", "vps-2-singapore"],
      ["---", "server"],
      ["server-2", "server-2"],
      ["Server-1 Home", "server-1-home"],
      [`${"a".repeat(62)}-b`, "a".repeat(62)],
    ]) {
      expect(dnsName(name!), name).toBe(label);
    }
  });
});
