import { describe, expect, it } from "vitest";

import { keysFor, liveUrl, retryDelay } from "./live";

describe("live updates", () => {
  it("refreshes only what a change touches, and everything for all", () => {
    expect(keysFor(["actions"])).toEqual([
      ["services"],
      ["actions"],
      ["network"],
    ]);
    expect(keysFor(["checks", "nodes"])).toEqual([
      ["overview"],
      ["checks", "results"],
      ["metrics", "recent"],
      ["network"],
    ]);
    expect(keysFor(["services"])).toEqual([
      ["services"],
      ["packages"],
      ["overview"],
    ]);
    expect(keysFor(["all"])).toBeNull();
    expect(keysFor(["unknown"])).toEqual([]);
  });

  it("waits longer after each failed connection, up to 30 seconds", () => {
    expect(retryDelay(0, 0.5)).toBe(1_000);
    expect(retryDelay(3, 0.5)).toBe(8_000);
    expect(retryDelay(10, 0.5)).toBe(30_000);
    expect(retryDelay(0, 0)).toBe(500);
  });

  it("opens the socket on the page's own host", () => {
    expect(liveUrl({ protocol: "https:", host: "kry.example.test" })).toBe(
      "wss://kry.example.test/api/live",
    );
    expect(liveUrl({ protocol: "http:", host: "localhost:8790" })).toBe(
      "ws://localhost:8790/api/live",
    );
  });
});
