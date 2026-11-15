import { describe, expect, it } from "vitest";

import { seal } from "./seal";
import { open, recipient } from "./seal-test-utils";

describe("sealing for a server", () => {
  it("seals so that only the server's key opens it", async () => {
    const server = await recipient();
    const sealed = await seal(server.public, "SMTP_PASSWORD=hunter2");
    expect(await open(server, sealed)).toEqual({
      version: 1,
      text: "SMTP_PASSWORD=hunter2",
    });
    const other = await recipient();
    await expect(open(other, sealed)).rejects.toThrow();
    expect(await seal(server.public, "SMTP_PASSWORD=hunter2")).not.toBe(sealed);
  });

  it("refuses a key that is not a server key", async () => {
    await expect(seal("short", "x")).rejects.toThrow();
  });
});
