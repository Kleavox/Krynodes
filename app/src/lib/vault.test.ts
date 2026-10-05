import { describe, expect, it } from "vitest";

import {
  exposeSteps,
  hostnameFor,
  moveSteps,
  pieceJson,
  planAddress,
  planRemoval,
  planSpread,
  reshareSteps,
  splitSteps,
  unexposeSteps,
} from "./vault";

const SET = "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a20";
const A = "11111111-1111-4111-8111-111111111111";
const B = "22222222-2222-4222-8222-222222222222";
const C = "33333333-3333-4333-8333-333333333333";

async function serverKey() {
  const pair = (await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  )) as CryptoKeyPair;
  const raw = new Uint8Array(
    await crypto.subtle.exportKey("raw", pair.publicKey),
  );
  return btoa(String.fromCharCode(...raw))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}

describe("the Cloudflare token in pieces", () => {
  it("writes a piece the way the agent reads it", () => {
    expect(pieceJson(SET, Uint8Array.from([1, 2, 3, 250]))).toBe(
      `{"set":"${SET}","piece":"AQID+g=="}`,
    );
  });

  it("gives every server a sealed piece of the same split", async () => {
    const holders = [
      { nodeId: A, sealKey: await serverKey() },
      { nodeId: B, sealKey: await serverKey() },
    ];
    const steps = await splitSteps(" cf-token ", holders, SET);
    expect(
      steps.map(({ piece, ...step }) => ({
        ...step,
        sealed: (piece ?? "").length > 50,
      })),
    ).toEqual([
      {
        nodeId: A,
        kind: "vault",
        name: "cloudflare",
        action: "store",
        args: { set: SET, holders: "2" },
        sealed: true,
      },
      {
        nodeId: B,
        kind: "vault",
        name: "cloudflare",
        action: "store",
        args: { set: SET, holders: "2" },
        sealed: true,
      },
    ]);
  });

  it("re-splits through one server and forgets the servers that drop out", () => {
    const steps = reshareSteps({
      releaser: B,
      assembler: A,
      holders: [
        { nodeId: A, sealKey: "KA" },
        { nodeId: C, sealKey: "KC" },
      ],
      keyOf: { [A]: "KA", [B]: "KB", [C]: "KC" },
      set: "next-set",
      cleanup: B,
      zone: "kleavox.xyz",
      forgets: [],
    });
    expect(steps).toEqual([
      {
        nodeId: B,
        kind: "vault",
        name: "cloudflare",
        action: "release",
        args: { to: A, key: "KA" },
      },
      {
        nodeId: A,
        kind: "vault",
        name: "cloudflare",
        action: "reshare",
        args: {
          holders: `${A}:KA,${C}:KC`,
          set: "next-set",
          cleanup: B,
          zone: "kleavox.xyz",
        },
        attachFrom: 0,
      },
      {
        nodeId: A,
        kind: "vault",
        name: "cloudflare",
        action: "store",
        args: { set: "next-set", holders: "2" },
        attachFrom: 1,
        attachKey: A,
      },
      {
        nodeId: C,
        kind: "vault",
        name: "cloudflare",
        action: "store",
        args: { set: "next-set", holders: "2" },
        attachFrom: 1,
        attachKey: C,
      },
    ]);
  });
});

describe("web addresses", () => {
  it("names an address after the app and the server", () => {
    expect(hostnameFor("Listmonk_App", "VM-0-10-debian", "kleavox.xyz")).toBe(
      "listmonk-app-vm-0-10-debian.kleavox.xyz",
    );
  });

  it("opens with a piece from another server, or alone when one server holds the token", () => {
    const address = {
      target: A,
      targetKey: "KA",
      project: "listmonk",
      service: "app",
      port: 9000,
      hostname: "listmonk-a.kleavox.xyz",
      mode: "path" as const,
      path: "/admin",
      zone: "kleavox.xyz",
      aud: "aud-1",
    };
    expect(exposeSteps({ ...address, releaser: B })).toEqual([
      {
        nodeId: B,
        kind: "vault",
        name: "cloudflare",
        action: "release",
        args: { to: A, key: "KA" },
      },
      {
        nodeId: A,
        kind: "compose",
        name: "listmonk",
        action: "expose",
        args: {
          service: "app",
          port: "9000",
          hostname: "listmonk-a.kleavox.xyz",
          mode: "path",
          path: "/admin",
          zone: "kleavox.xyz",
          aud: "aud-1",
        },
        attachFrom: 0,
      },
    ]);
    expect(exposeSteps({ ...address, mode: "allow", releaser: null })).toEqual([
      {
        nodeId: A,
        kind: "compose",
        name: "listmonk",
        action: "expose",
        args: {
          service: "app",
          port: "9000",
          hostname: "listmonk-a.kleavox.xyz",
          mode: "allow",
          zone: "kleavox.xyz",
          aud: "aud-1",
        },
      },
    ]);
    expect(
      unexposeSteps({
        target: A,
        targetKey: "KA",
        project: "listmonk",
        hostname: "listmonk-a.kleavox.xyz",
        zone: "kleavox.xyz",
        releaser: B,
        disposal: "purge",
      }).map((step) => step.action),
    ).toEqual(["release", "unexpose", "purge"]);
  });
});

describe("moving a stack", () => {
  it("packs on the source, creates on the target and deals with the original", () => {
    expect(
      moveSteps({
        source: A,
        target: B,
        targetKey: "KB",
        project: "listmonk",
        compose: "services: {}\n",
        access: "full",
        secrets: "sealed",
        original: "later",
      }),
    ).toEqual([
      {
        nodeId: A,
        kind: "compose",
        name: "listmonk",
        action: "export",
        args: { to: B, key: "KB" },
      },
      {
        nodeId: B,
        kind: "compose",
        name: "listmonk",
        action: "create",
        compose: "services: {}\n",
        access: "full",
        secrets: "sealed",
        attachFrom: 0,
      },
      { nodeId: A, kind: "compose", name: "listmonk", action: "remove" },
    ]);
    expect(
      moveSteps({
        source: A,
        target: B,
        targetKey: "KB",
        project: "listmonk",
        compose: "x",
        access: "contained",
        original: "keep",
      }).map((step) => step.action),
    ).toEqual(["export", "create"]);
    expect(
      moveSteps({
        source: A,
        target: B,
        targetKey: "KB",
        project: "listmonk",
        compose: "x",
        access: "contained",
        original: "now",
      }).at(-1)?.action,
    ).toBe("purge");
  });
});

const node = (
  id: string,
  over: Partial<{
    vault: { set: string; holders: number } | null;
    reachable: boolean;
    online: boolean;
    sealKey: string | null;
  }> = {},
) => ({
  id,
  name: `server-${id.slice(0, 1)}`,
  sealKey: `key-${id.slice(0, 1)}`,
  vault: { set: SET, holders: 3 },
  reachable: true,
  online: true,
  ...over,
});

describe("planning the pieces", () => {
  it("re-splits through two online holders and forgets a holder that drops out", () => {
    const plan = planSpread(
      [node(A), node(B), node(C, { reachable: false })],
      SET,
    );
    expect(plan).toEqual({
      ok: true,
      assembler: A,
      releaser: B,
      holders: [
        { nodeId: A, sealKey: "key-1" },
        { nodeId: B, sealKey: "key-2" },
      ],
      forgets: [],
    });
  });

  it("needs two online pieces unless one server holds the whole token", () => {
    expect(
      planSpread([node(A), node(B, { online: false })], SET),
    ).toMatchObject({ ok: false });
    expect(
      planSpread(
        [
          node(A, { vault: { set: SET, holders: 1 } }),
          node(B, { vault: null }),
        ],
        SET,
      ),
    ).toMatchObject({
      ok: true,
      assembler: A,
      releaser: null,
      holders: [
        { nodeId: A, sealKey: "key-1" },
        { nodeId: B, sealKey: "key-2" },
      ],
    });
    expect(planSpread([node(A, { vault: null })], SET)).toEqual({
      ok: false,
      reason: "No server holds a piece any more. Paste the token again.",
    });
  });

  it("finds a second piece for a web address", () => {
    expect(planAddress([node(A), node(B)], A, SET)).toEqual({
      ok: true,
      releaser: B,
    });
    expect(
      planAddress([node(A, { vault: { set: SET, holders: 1 } })], A, SET),
    ).toEqual({ ok: true, releaser: null });
    expect(
      planAddress([node(A, { vault: null }), node(B)], A, SET),
    ).toMatchObject({ ok: false });
    expect(
      planAddress([node(A), node(B, { online: false })], A, SET),
    ).toMatchObject({ ok: false });
  });
});

describe("removing a server that holds a piece", () => {
  it("leaves a server without a piece alone", () => {
    expect(planRemoval([node(A), node(B, { vault: null })], B, SET)).toEqual({
      ok: true,
      needed: false,
    });
    expect(planRemoval([node(A)], A, null)).toEqual({
      ok: true,
      needed: false,
    });
  });

  it("re-splits across the others, uses the leaving server last and makes it forget", () => {
    expect(planRemoval([node(A), node(B), node(C)], A, SET)).toEqual({
      ok: true,
      needed: true,
      assembler: B,
      releaser: C,
      holders: [
        { nodeId: B, sealKey: "key-2" },
        { nodeId: C, sealKey: "key-3" },
      ],
      forgets: [A],
    });
  });

  it("still needs the leaving server when only two pieces are online", () => {
    expect(
      planRemoval([node(A), node(B), node(C, { online: false })], A, SET),
    ).toMatchObject({
      ok: true,
      assembler: B,
      releaser: A,
      holders: [
        { nodeId: B, sealKey: "key-2" },
        { nodeId: C, sealKey: "key-3" },
      ],
      forgets: [A],
    });
  });

  it("says why when the token cannot move", () => {
    expect(
      planRemoval([node(A), node(B, { online: false })], A, SET),
    ).toMatchObject({ ok: false });
    expect(
      planRemoval([node(A, { vault: { set: SET, holders: 1 } })], A, SET),
    ).toEqual({
      ok: false,
      reason:
        "No other server with agent 0.5.0 that this device reaches can take the token.",
    });
  });
});
