import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import { fingerprintOf } from "@/lib/approve";
import { recipient } from "@/lib/seal-test-utils";
import type { ActionRow, FleetNode, JoinRequest, NetworkView } from "@/types";

import { ApproveBody, runApprove, type ApproveState } from "./approve-dialog";

const S2 = "22222222-2222-4222-8222-222222222222";
const AT = "2026-11-22T00:00:00.000Z";

const wgKey = () =>
  btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));

const request: JoinRequest = {
  node: S2,
  name: "server-2",
  kind: "server",
  hostname: "server-2",
  os: "Debian 13",
  key: wgKey(),
  signer: wgKey(),
  sealKey: (await recipient()).public,
  ready: true,
  reason: null,
  since: AT,
};

const shown = await fingerprintOf(request);

const idle: ApproveState = { phase: "confirm", steps: [] };

const body = (
  state: ApproveState,
  fingerprint: typeof shown | undefined = shown,
) =>
  renderToStaticMarkup(
    <ApproveBody
      request={request}
      shown={fingerprint}
      state={state}
      onApprove={() => {}}
      onClose={() => {}}
    />,
  );

describe("the approve dialog", () => {
  it("the fingerprint is shown before anything is signed", () => {
    const html = body(idle);
    expect(html).toContain(shown.fingerprint);
    expect(html).toContain(
      "Check that server-2 shows the same fingerprint: run sudo kry network fingerprint on it.",
    );
    expect(html).toMatch(/<button[^>]*>Approve<\/button>/u);
    expect(html).not.toContain('aria-label="Progress"');
    expect(body(idle, null!)).toMatch(
      /<button[^>]*disabled=""[^>]*>Approve<\/button>/u,
    );
  });

  it("lists each step and each member's applied state", () => {
    const html = body({
      phase: "done",
      steps: [
        { kind: "session" },
        { kind: "inspect" },
        { kind: "prepare" },
        { kind: "sign" },
        {
          kind: "applied",
          members: [
            { name: "server-1", state: "Applied" },
            { name: "server-2", state: "Applying…" },
          ],
        },
      ],
    });
    expect(html).toContain("Passkey confirmed.");
    expect(html).toContain("Checking server-2.");
    expect(html).toContain("Preparing server-2.");
    expect(html).toContain("Signing the network document.");
    expect(html).toContain("server-1: Applied");
    expect(html).toContain("server-2: Applying…");
    expect(html).not.toMatch(/>Approve<\/button>/u);
  });

  it("cannot be closed while the approval runs", () => {
    const html = body({ phase: "running", steps: [{ kind: "session" }] });
    expect(html).toMatch(/<button[^>]*disabled=""[^>]*>Close<\/button>/u);
    expect(body(idle)).toMatch(
      /<button(?![^>]*disabled="")[^>]*>Cancel<\/button>/u,
    );
  });

  it("different prepared keys stop the approval and sign nothing", async () => {
    const signDocument = vi.fn();
    const signCommand = vi.fn(async () => "signed");
    const node = (id: string, name: string): FleetNode => ({
      id,
      name,
      hostname: null,
      os: null,
      arch: null,
      version: "0.7.92",
      online: true,
      lastSeenAt: null,
      trust: { version: 1, core: ["pk1"], access: ["pk1"] },
      update: null,
      kind: "server",
      address: null,
      via: null,
      ms: null,
      request: "requested",
    });
    const answers: Record<string, unknown> = {
      inspect: {
        kernel: { ok: true, version: "6.8", reason: null },
        tools: true,
        iptables: true,
        used: [],
        others: [],
        port: null,
        mtu: 1500,
        public: null,
      },
      prepare: { key: wgKey(), signer: request.signer, port: 51820, mtu: 1500 },
    };
    const posted = vi.fn();
    const empty: NetworkView = {
      network: null,
      members: [],
      requests: [request],
      rejected: [],
      allow: [],
      links: [],
    };
    let state: ApproveState = idle;
    await runApprove(
      request,
      shown.fingerprint,
      {
        api: {
          nodes: async () => [node(S2, "server-2")],
          network: async () => empty,
          applied: vi.fn(),
          next: async () => ({
            document: null,
            hash: null,
            prepared: {},
            addresses: {},
            relayPorts: {},
          }),
          current: async () => null,
          postDocument: posted,
          actions: async () => [],
          sendAction: async (sent): Promise<ActionRow> => ({
            id: sent.id,
            nodeId: sent.nodeId,
            kind: "network",
            name: sent.name,
            action: sent.action,
            title: sent.title,
            status: "done",
            message: JSON.stringify(answers[sent.action]),
            output: null,
            createdAt: AT,
            finishedAt: AT,
          }),
        },
        sign: {
          openSession: vi.fn(async () => ({}) as never),
          buildCommand: vi.fn(() => ({}) as never),
          signCommand,
          signDocument,
        },
      },
      (update) => {
        state = update(state);
      },
    );
    expect(state.error).toBe(
      "server-2 reported different keys; nothing was changed",
    );
    expect(state.phase).toBe("done");
    expect(signDocument).not.toHaveBeenCalled();
    expect(posted).not.toHaveBeenCalled();
    expect(signCommand).toHaveBeenCalledTimes(2);
  });
});
