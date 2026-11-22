import { QueryClient } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { liveUrl, onProgress, retryDelay, watch } from "./live";

class FakeSocket {
  static all: FakeSocket[] = [];
  readonly url: string;
  readonly sent: string[] = [];
  onopen: (() => void) | null = null;
  onmessage: ((event: { data: unknown }) => void) | null = null;
  onclose: (() => void) | null = null;
  closed = false;

  constructor(url: string) {
    this.url = url;
    FakeSocket.all.push(this);
  }

  send(data: string) {
    this.sent.push(data);
  }

  close() {
    this.closed = true;
  }

  deliver(data: unknown) {
    this.onmessage?.({ data });
  }
}

const URL = "wss://kry.example.test/api/live";
const current = () => FakeSocket.all.at(-1)!;

function start() {
  const client = new QueryClient();
  const invalidate = vi
    .spyOn(client, "invalidateQueries")
    .mockResolvedValue(undefined);
  const stop = watch(client, URL);
  const keys = () =>
    invalidate.mock.calls.map(([filters]) => filters?.queryKey);
  return { stop, keys };
}

beforeEach(() => {
  FakeSocket.all = [];
  vi.useFakeTimers();
  vi.stubGlobal("WebSocket", FakeSocket);
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("live updates", () => {
  it("opens the socket on the page's own host", () => {
    expect(liveUrl({ protocol: "https:", host: "kry.example.test" })).toBe(URL);
    expect(liveUrl({ protocol: "http:", host: "localhost:8790" })).toBe(
      "ws://localhost:8790/api/live",
    );
    start();
    expect(current().url).toBe(URL);
  });

  it("waits longer after each failed connection, up to 30 seconds", () => {
    expect(retryDelay(0, 0.5)).toBe(1_000);
    expect(retryDelay(3, 0.5)).toBe(8_000);
    expect(retryDelay(10, 0.5)).toBe(30_000);
  });

  it("refreshes the fleet and the actions once for a burst of changes", () => {
    const { keys } = start();
    current().deliver(JSON.stringify({ type: "changed", topics: ["fleet"] }));
    current().deliver(JSON.stringify({ type: "changed", topics: ["fleet"] }));
    expect(keys()).toEqual([]);
    vi.advanceTimersByTime(300);
    expect(keys()).toEqual([["fleet"], ["actions"]]);
  });

  it("ignores pongs and anything unreadable", () => {
    const { keys } = start();
    current().deliver("pong");
    current().deliver("{");
    current().deliver("null");
    current().deliver(new ArrayBuffer(1));
    vi.advanceTimersByTime(1_000);
    expect(keys()).toEqual([]);
  });

  it("reconnects after a delay and refreshes what it missed", () => {
    const { keys } = start();
    current().onopen?.();
    current().onclose?.();
    expect(FakeSocket.all).toHaveLength(1);
    vi.advanceTimersByTime(30_000);
    expect(FakeSocket.all).toHaveLength(2);
    current().onopen?.();
    vi.advanceTimersByTime(300);
    expect(keys()).toEqual([["fleet"], ["actions"]]);
  });

  it("backs off further while the server stays away", () => {
    start();
    current().onclose?.();
    vi.advanceTimersByTime(1_500);
    expect(FakeSocket.all).toHaveLength(2);
    current().onclose?.();
    vi.advanceTimersByTime(1_000);
    expect(FakeSocket.all).toHaveLength(2);
    vi.advanceTimersByTime(30_000);
    expect(FakeSocket.all).toHaveLength(3);
  });

  it("keeps the connection alive with a ping and closes when stopped", () => {
    const { stop } = start();
    const first = current();
    first.onopen?.();
    vi.advanceTimersByTime(25_000);
    expect(first.sent).toEqual(["ping"]);
    stop();
    expect(first.closed).toBe(true);
    first.onclose?.();
    vi.advanceTimersByTime(60_000);
    expect(FakeSocket.all).toHaveLength(1);
    expect(first.sent).toEqual(["ping"]);
  });

  it("hands progress lines to listeners in order, without refreshing", () => {
    const { keys } = start();
    const seen: string[] = [];
    const off = onProgress(({ id, line }) => seen.push(`${id}:${line}`));
    current().deliver(JSON.stringify({ type: "progress", id: "a", line: "1" }));
    current().deliver(JSON.stringify({ type: "progress", id: "a", line: "2" }));
    current().deliver(JSON.stringify({ type: "progress", id: "a" }));
    expect(seen).toEqual(["a:1", "a:2"]);
    off();
    current().deliver(JSON.stringify({ type: "progress", id: "a", line: "3" }));
    expect(seen).toEqual(["a:1", "a:2"]);
    vi.advanceTimersByTime(1_000);
    expect(keys()).toEqual([]);
  });
});
