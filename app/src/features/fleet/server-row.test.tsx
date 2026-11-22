import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { FleetNode } from "@/types";

import { ServerRow, serverActions } from "./server-row";

const node: FleetNode = {
  id: "node-1",
  name: "server-1",
  hostname: "server-1.example.test",
  os: "Ubuntu 24.04",
  arch: "amd64",
  version: "0.8.0",
  online: true,
  lastSeenAt: "2026-11-22T07:30:00.000Z",
  trust: null,
  update: null,
};

const html = (patch: Partial<FleetNode> = {}) =>
  renderToStaticMarkup(<ServerRow node={{ ...node, ...patch }} />);

const text = (patch: Partial<FleetNode> = {}) =>
  html(patch).replace(/<[^>]+>/gu, "");

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(Date.parse("2026-11-22T10:00:00Z"));
});

afterEach(() => {
  vi.useRealTimers();
});

describe("a server row", () => {
  it("an offline server says Offline and its last seen time", () => {
    const shown = text({ online: false });
    expect(shown).toContain("server-1");
    expect(shown).toContain("Offline");
    expect(shown).toContain("Last seen 14:30");
  });

  it("shows the day too when it was not seen today", () => {
    expect(
      text({ online: false, lastSeenAt: "2026-11-20T07:30:00Z" }),
    ).toContain("Last seen 20 Nov 14:30");
  });

  it("a server never seen shows --", () => {
    const shown = text({
      online: false,
      lastSeenAt: null,
      os: null,
      arch: null,
      version: null,
    });
    expect(shown).toContain("Last seen --");
    expect(shown).toContain("-- · --");
    expect(shown).toContain("Agent --");
  });

  it("an online server says Online with its system and agent version", () => {
    const shown = text();
    expect(shown).toContain("Online");
    expect(shown).toContain("Ubuntu 24.04 · amd64");
    expect(shown).toContain("Agent 0.8.0");
    expect(shown).not.toContain("Last seen");
    expect(shown).not.toContain("Update to");
  });

  it("offers the newer agent version when there is one", () => {
    expect(text({ update: "0.8.1" })).toContain("Update to 0.8.1");
  });

  it("can be jumped to and has a menu named after it", () => {
    const shown = html();
    expect(shown).toContain('id="server-node-1"');
    expect(shown).toContain('aria-label="Actions for server-1"');
  });

  it("offers Update Agent only when a newer agent exists, with its version", () => {
    const labels = (patch: Partial<FleetNode>) =>
      serverActions({ ...node, ...patch }).map((item) => [
        item.label,
        item.ask?.title ?? null,
      ]);
    expect(labels({})).toEqual([
      ["Update Agent", null],
      ["Restart Server", "Restart Server"],
      ["Remove Server", "Remove Server"],
    ]);
    expect(labels({ update: "0.8.1" })[0]).toEqual([
      "Update Agent",
      "Update Agent to 0.8.1",
    ]);
    const update = serverActions({ ...node, update: "0.8.1" })[0]!.ask!;
    expect(update).toMatchObject({
      kind: "agent",
      action: "update",
      args: { version: "0.8.1" },
    });
    const [, restart, remove] = serverActions(node);
    expect(restart!.ask).toMatchObject({ kind: "host", action: "restart" });
    expect(remove!.ask).toMatchObject({ kind: "agent", action: "remove" });
    expect(remove!.destructive).toBe(true);
  });

  it("offers Delete Server only while the server is offline", () => {
    const labels = (patch: Partial<FleetNode>) =>
      serverActions({ ...node, ...patch }).map((item) => item.label);
    expect(labels({ online: true })).not.toContain("Delete Server");
    expect(labels({ online: false })).toContain("Delete Server");
    const erase = serverActions({ ...node, online: false }).find(
      (item) => item.label === "Delete Server",
    )!;
    expect(erase.destructive).toBe(true);
    expect(erase.erase).toBe(true);
    expect(erase.ask).toBeUndefined();
    expect(serverActions(node).some((item) => item.erase === true)).toBe(false);
  });
});
