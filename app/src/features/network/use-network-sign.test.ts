import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  postActions: vi.fn(async () => ({
    actions: [{ id: "answered" }, { id: "silent" }],
  })),
}));

vi.mock("@/lib/http", async (original) => ({
  ...(await original<typeof import("@/lib/http")>()),
  apiFetch: vi.fn(async (path: string) => ({
    action: path.endsWith("answered")
      ? { status: "done", output: JSON.stringify({ up: true }) }
      : { status: "sent", output: null },
  })),
}));

import { testPair } from "./use-network-sign";

describe("Test Link", () => {
  afterEach(() => vi.useRealTimers());

  it("stops waiting for a server that does not answer within two minutes", async () => {
    vi.useFakeTimers();
    let results: Record<string, unknown> | undefined;
    void testPair(
      [
        { nodeId: "a", peer: "b", address: "10.88.0.2" },
        { nodeId: "b", peer: "a", address: "10.88.0.1" },
      ],
      1420,
    ).then((value) => {
      results = value;
    });
    await vi.advanceTimersByTimeAsync(117_000);
    expect(results).toBeUndefined();
    await vi.advanceTimersByTimeAsync(6_000);
    expect(results).toEqual({ a: { up: true }, b: null });
  });
});
