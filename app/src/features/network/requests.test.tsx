import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { networkApi } from "@/lib/api";
import type { JoinRequest } from "@/types";

import { RequestList } from "./requests";

const S2 = "22222222-2222-4222-8222-222222222222";

const request = (patch: Partial<JoinRequest> = {}): JoinRequest => ({
  node: S2,
  name: "server-2",
  kind: "server",
  hostname: "server-2.example.test",
  os: "Debian 13",
  key: null,
  signer: null,
  sealKey: null,
  ready: true,
  reason: null,
  since: "2026-11-22T03:00:00.000Z",
  ...patch,
});

const none = () => {};

const text = (
  requests: JoinRequest[],
  rejected = [] as { node: string; name: string }[],
) =>
  renderToStaticMarkup(
    <RequestList
      requests={requests}
      rejected={rejected}
      onApprove={none}
      onReject={none}
      onAskAgain={none}
    />,
  );

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(Date.parse("2026-11-22T10:00:00Z"));
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("join requests", () => {
  it("a ready request shows its machine and Ready, with Approve and Reject", () => {
    const html = text([request()]);
    expect(html).toContain("server-2");
    expect(html).toContain("Server");
    expect(html).toContain("Debian 13");
    expect(html).toContain("server-2.example.test");
    expect(html).toContain("Since 10:00");
    expect(html).toContain("Ready");
    expect(html).toMatch(/<button[^>]*>Approve<\/button>/u);
    expect(html).toMatch(/<button[^>]*>Reject<\/button>/u);
  });

  it("a request that is not ready shows its reason and no Approve", () => {
    const html = text([
      request({ ready: false, reason: "WireGuard is not installed." }),
    ]);
    expect(html).toContain("WireGuard is not installed.");
    expect(html).not.toContain("Ready");
    expect(html).not.toContain(">Approve<");
    expect(html).toContain(">Reject<");
    expect(text([request({ ready: false })])).toContain("Not ready yet");
  });

  it("Reject asks for no passkey", async () => {
    const get = vi.fn();
    vi.stubGlobal("navigator", { credentials: { get } });
    const fetch = vi.fn(
      async (..._sent: unknown[]) =>
        new Response(JSON.stringify({ state: "rejected" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    );
    vi.stubGlobal("fetch", fetch);
    await expect(networkApi.reject(S2)).resolves.toEqual({
      state: "rejected",
    });
    expect(get).not.toHaveBeenCalled();
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(String(fetch.mock.calls[0]![0])).toBe(
      `/api/network/requests/${S2}/reject`,
    );
  });

  it("rejected machines are one line with Ask to Join Again in their menu", () => {
    const html = text(
      [],
      [
        { node: S2, name: "server-4" },
        { node: "x", name: "laptop-1" },
      ],
    );
    expect(html.replace(/<[^>]+>/gu, " ").replace(/\s+/gu, " ")).toContain(
      "Rejected: server-4 laptop-1",
    );
    expect(html).toContain('aria-label="Actions for server-4"');
    expect(text([])).toBe("");
  });
});
