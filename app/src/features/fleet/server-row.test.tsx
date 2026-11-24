import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { FleetNode } from "@/types";

import { deleteTarget } from "./delete-dialog";
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
  kind: "server",
  address: null,
  via: null,
  ms: null,
  request: null,
};

const names = new Map([["node-1", "server-1"]]);

const html = (patch: Partial<FleetNode> = {}) =>
  renderToStaticMarkup(
    <ServerRow node={{ ...node, ...patch }} names={names} />,
  );

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

  it("a laptop shows Via server-1", () => {
    const shown = text({
      id: "laptop-id",
      name: "laptop-1",
      kind: "laptop",
      address: "10.88.37.77",
      via: "node-1",
      ms: 21.6,
    });
    expect(shown).toContain("laptop-1");
    expect(shown).toContain("Laptop");
    expect(shown).toContain("10.88.37.77");
    expect(shown).toContain("Via server-1");
    expect(shown).toContain("22 ms");
  });

  it("no round trip shows --", () => {
    const shown = text({ address: "10.88.37.14", ms: null });
    expect(shown).toContain("10.88.37.14");
    expect(shown).toContain("Direct");
    expect(shown).toMatch(/Direct\s*--/u);
    expect(text()).not.toContain("Direct");
  });

  it("a machine that asked to join or was rejected says so", () => {
    expect(text({ request: "requested" })).toContain("Wants to Join");
    expect(text({ request: "rejected" })).toContain("Join Rejected");
    expect(
      serverActions({ ...node, request: "rejected" }).map((item) => item.label),
    ).toContain("Ask to Join Again");
    expect(serverActions(node).map((item) => item.label)).not.toContain(
      "Ask to Join Again",
    );
    expect(
      serverActions({ ...node, kind: "laptop", request: "rejected" }).map(
        (item) => item.label,
      ),
    ).toEqual(["Ask to Join Again", "Delete Laptop"]);
  });

  it("offers Delete Laptop for a laptop in any state but in the network", () => {
    const laptop = { ...node, name: "laptop-1", kind: "laptop" as const };
    for (const patch of [
      { request: null },
      { request: "requested" as const },
      { request: "rejected" as const },
      { online: false },
    ]) {
      const erase = serverActions({ ...laptop, ...patch }).find(
        (item) => item.label === "Delete Laptop",
      );
      expect(erase, JSON.stringify(patch)).toMatchObject({
        destructive: true,
        erase: true,
      });
    }
    expect(
      serverActions({ ...laptop, address: "10.88.37.77" }).map(
        (item) => item.label,
      ),
    ).toEqual([]);
  });

  it("deletes a laptop through the laptops route and a server through the nodes route", () => {
    expect(
      deleteTarget({
        ...node,
        id: "laptop-id",
        name: "laptop-1",
        kind: "laptop",
      }),
    ).toEqual({
      path: "/api/laptops/laptop-id",
      heading: "Delete laptop-1 from the dashboard?",
      body: "Its history goes with it and it can no longer connect to Krynodes. Add it again with a new code to bring it back.",
    });
    expect(deleteTarget(node)).toEqual({
      path: "/api/nodes/node-1",
      heading: "Delete server-1 from the dashboard?",
      body: "Its history goes with it. Install it again to bring it back.",
    });
  });
});
