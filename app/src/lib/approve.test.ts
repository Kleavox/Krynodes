import {
  joinFingerprint,
  networkDocumentSchema,
  type NetworkDocument,
} from "@krynodes/protocol";
import { describe, expect, it, vi } from "vitest";

import type {
  ActionRow,
  FleetNode,
  JoinRequest,
  NetworkNext,
  NetworkView,
} from "../types";
import {
  approve,
  changeNetwork,
  fingerprintOf,
  renewKeys,
  type ApproveStep,
} from "./approve";
import { withoutMember, withoutNetwork } from "./network";
import { hashOf, memoryStore, remember, type Unchecked } from "./pins";
import { open, recipient } from "./seal-test-utils";
import { buildCommand, signCommand, signDocument, type Session } from "./sign";

const S1 = "11111111-1111-4111-8111-111111111111";
const S2 = "22222222-2222-4222-8222-222222222222";
const S3 = "44444444-4444-4444-8444-444444444444";
const L1 = "33333333-3333-4333-8333-333333333333";
const HASH = "q".repeat(43);
const AT = "2026-11-22T00:00:00.000Z";

const SEAL: Record<string, Awaited<ReturnType<typeof recipient>>> = {
  [S1]: await recipient(),
  [S2]: await recipient(),
  [S3]: await recipient(),
  [L1]: await recipient(),
};

const wgKey = () =>
  btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));

const REKEYED = wgKey();

const session = {
  key: {} as CryptoKey,
  grant: {
    grant: "Z3JhbnQ",
    credentialId: "pk1",
    authenticatorData: "YQ",
    clientDataJSON: "Yw",
    signature: "cw",
  },
  expiresAt: Date.now() + 300_000,
  offset: 0,
} satisfies Session;

const fleet = (
  id: string,
  name: string,
  kind: "server" | "laptop" = "server",
) =>
  ({
    id,
    name,
    hostname: null,
    os: "linux",
    arch: "amd64",
    version: "0.7.92",
    online: true,
    lastSeenAt: AT,
    trust: { version: 1, core: ["pk1"], access: ["pk1", `only-${name}`] },
    update: null,
    kind,
    address: null,
    via: null,
    ms: null,
    request: null,
  }) satisfies FleetNode;

const live = (
  node: string,
  name: string,
  address: string,
  extra: Partial<NetworkDocument["members"][number]> = {},
): NetworkDocument["members"][number] => ({
  node,
  name,
  address,
  key: wgKey(),
  signer: wgKey(),
  sealKey: SEAL[node]!.public,
  port: 51820,
  mtu: null,
  endpoint: null,
  nat: false,
  psk: {},
  ...extra,
});

interface Setup {
  existing: boolean;
  joiner: "server" | "laptop";
  preparedKey?: string;
  found?: string | null;
  arrived?: string[];
  untrusted?: string;
}

async function setup({
  existing,
  joiner,
  preparedKey,
  found = "203.0.113.30",
  arrived = ["203.0.113.10"],
  untrusted,
}: Setup) {
  const document: NetworkDocument | null = existing
    ? networkDocumentSchema.parse({
        v: 1,
        version: 4,
        range: "10.88.37.0/24",
        port: 51820,
        mtu: 1420,
        members: [
          live(S1, "server-1", "10.88.37.14", {
            endpoint: "203.0.113.10:51820",
            psk: { [S2]: "c2VhbGVk" },
          }),
          live(S2, "server-2", "10.88.37.201", {
            endpoint: "203.0.113.20:51820",
            psk: { [S1]: "c2VhbGVk" },
          }),
        ],
        blocked: [],
        allow: [
          {
            from: { group: "laptops" },
            to: { group: "servers" },
            ports: "all",
          },
        ],
      })
    : null;
  const id = joiner === "server" ? S3 : L1;
  const name = joiner === "server" ? "server-3" : "laptop-1";
  const request: JoinRequest = {
    node: id,
    name,
    kind: joiner,
    hostname: name,
    os: "linux",
    key: wgKey(),
    signer: wgKey(),
    sealKey: SEAL[id]!.public,
    ready: true,
    reason: null,
    since: AT,
  };
  const events: string[] = [];
  const steps: ApproveStep[] = [];
  const commands: {
    nodeId: string;
    action: string;
    args?: Record<string, string>;
  }[] = [];
  const signed: NetworkDocument[] = [];
  const checked: Unchecked[][] = [];
  const store = memoryStore();
  const nextAsked: { ids: string[]; range?: string }[] = [];
  let posted: {
    signed: string;
    change: string;
    detail: string | null;
  } | null = null;
  const members = (applied: number): NetworkView["members"] =>
    (document?.members ?? []).map((one) => ({
      node: one.node,
      name: one.name,
      kind: one.kind ?? "server",
      state: "in" as const,
      address: one.address,
      key: one.key,
      signer: one.signer,
      port: one.port,
      mtu: one.mtu,
      endpoint: one.endpoint,
      nat: one.nat,
      applied,
      failure: null,
      announced: null,
      since: AT,
      joinedAt: AT,
    }));
  const view = (): NetworkView => ({
    network: document
      ? {
          range: document.range,
          port: document.port,
          mtu: document.mtu,
          version: document.version,
          dns: null,
          deleted: false,
        }
      : null,
    members: posted
      ? [
          ...members(5),
          {
            ...members(5)[0]!,
            node: id,
            name,
            kind: joiner,
            address: "10.88.37.163",
          },
        ]
      : members(4),
    requests: [request],
    rejected: [],
    allow: document?.allow ?? [],
    links: [],
  });
  const answer = (action: string, nodeId: string) =>
    action === "rekey"
      ? JSON.stringify({
          key: REKEYED,
          signer: document!.members.find((one) => one.node === nodeId)!.signer,
          fingerprint: "0000-0000-0000-0000",
          signature: "c2lnbmVk",
        })
      : action === "inspect"
        ? JSON.stringify({
            kernel: { ok: true, version: "6.8", reason: null },
            tools: false,
            iptables: true,
            used: ["10.88.0.0/17", "172.17.0.0/16"],
            others: [],
            port: 51822,
            mtu: 1500,
            public: found,
          })
        : action === "probe"
          ? JSON.stringify(
              nodeId === id
                ? { listened: true, arrived }
                : { listened: false, arrived: [] },
            )
          : JSON.stringify({
              key: preparedKey ?? request.key,
              signer: request.signer,
              port: 51822,
              mtu: 1500,
            });
  const listeners = new Set<() => void>();
  const appliedRows = () =>
    (document?.members ?? [])
      .map((one) => ({ node: one.node, name: one.name }))
      .concat(posted ? [{ node: id, name }] : [])
      .map((one) => ({
        ...one,
        applied: posted ? 5 : 4,
        failure: null,
        online: true,
      }));
  let applying = 0;
  let reads = 0;
  const waiting: (() => void)[] = [];
  const deps = {
    store,
    check: async (members: Unchecked[]) => {
      checked.push(members);
      return true;
    },
    changes: (listener: () => void) => {
      listeners.add(listener);
      for (const resolve of waiting.splice(0)) resolve();
      return () => {
        listeners.delete(listener);
      };
    },
    onStep: (step: ApproveStep) => {
      events.push(step.kind);
      steps.push(step);
    },
    random: () => 0,
    pause: async () => undefined,
    api: {
      nodes: async () =>
        [
          fleet(S1, "server-1"),
          fleet(S2, "server-2"),
          fleet(id, name, joiner),
        ].map((node) =>
          node.id === untrusted ? { ...node, trust: null } : node,
        ),
      network: async () => view(),
      applied: async () => {
        reads += 1;
        const rows = appliedRows();
        if (applying > 0) {
          applying -= 1;
          rows.at(-1)!.applied = 4;
        }
        return { version: posted ? 5 : 4, members: rows };
      },
      current: async () => (document ? { document, hash: HASH } : null),
      actions: async () => [] as ActionRow[],
      sendAction: async (body: {
        nodeId: string;
        id: string;
        action: string;
        title: string;
        signed: string;
      }): Promise<ActionRow> => {
        events.push(`send:${body.action}`);
        return {
          id: body.id,
          nodeId: body.nodeId,
          kind: "network",
          name,
          action: body.action,
          title: body.title,
          status: "done",
          message: answer(body.action, body.nodeId),
          output: null,
          createdAt: AT,
          finishedAt: AT,
        };
      },
      next: async (ids: string[], range?: string): Promise<NetworkNext> => {
        events.push("next");
        nextAsked.push({ ids, ...(range ? { range } : {}) });
        return {
          document,
          hash: document ? HASH : null,
          prepared: {
            [id]: {
              key: request.key,
              signer: request.signer,
              port: 51822,
              mtu: 1500,
            },
          },
          addresses: {
            [id]: (range ?? document!.range).replace(/0\/24$/u, "163"),
          },
          relayPorts: {},
        };
      },
      postDocument: async (body: {
        signed: string;
        change: string;
        detail: string | null;
      }) => {
        events.push("post");
        posted = body;
        return { version: 5 };
      },
    },
    sign: {
      openSession: async (access: string[]) => {
        events.push(`session:${access.join(",")}`);
        return session;
      },
      buildCommand,
      signCommand: async (_: Session, command: object) => {
        const built = command as {
          nodeId: string;
          action: string;
          args?: Record<string, string>;
        };
        events.push(`signCommand:${built.action}`);
        commands.push(built);
        return `signed-${built.action}`;
      },
      signDocument: async (_: Session, next: NetworkDocument) => {
        events.push("signDocument");
        signed.push(next);
        return "signed-document";
      },
    },
  };
  return {
    expected: await joinFingerprint(
      request.key!,
      request.signer!,
      request.sealKey!,
    ),
    emit: () => {
      for (const listener of [...listeners]) listener();
    },
    hold: (times: number) => {
      applying = times;
    },
    reads: () => reads,
    listening: () =>
      listeners.size > 0
        ? Promise.resolve()
        : new Promise<void>((resolve) => waiting.push(resolve)),
    request,
    deps,
    events,
    steps,
    commands,
    signed,
    checked,
    store,
    document,
    nextAsked,
    posted: () => posted,
  };
}

describe("approving a join request", () => {
  it("shows the line to check the fingerprint on", async () => {
    const run = await setup({ existing: true, joiner: "server" });
    expect(await fingerprintOf(run.request)).toEqual({
      fingerprint: run.expected,
      line: "Check that server-3 shows the same fingerprint: run sudo kry network fingerprint on it.",
    });
  });

  it("a request whose keys no longer give the confirmed fingerprint opens no session", async () => {
    const run = await setup({ existing: true, joiner: "server" });
    const refetched = { ...run.request, signer: wgKey() };
    await expect(approve(refetched, run.expected, run.deps)).rejects.toThrow(
      "server-3 reported different keys; nothing was changed",
    );
    expect(run.events).toEqual([]);
  });

  it("names every network command after the interface the agent checks", async () => {
    const run = await setup({ existing: true, joiner: "server" });
    await approve(run.request, run.expected, run.deps);
    expect(run.commands.length).toBeGreaterThan(0);
    for (const command of run.commands) {
      expect((command as unknown as { name: string }).name).toBe("kry0");
    }
  });

  it("signs in the order the flow says", async () => {
    const run = await setup({ existing: true, joiner: "server" });
    await approve(run.request, run.expected, run.deps);

    const signedOrSent = run.events.filter(
      (event) => event.includes(":") || event === "next",
    );
    expect(signedOrSent.slice(0, 8)).toEqual([
      "session:pk1",
      "session:pk1",
      "signCommand:inspect",
      "send:inspect",
      "next",
      "session:pk1",
      "signCommand:prepare",
      "send:prepare",
    ]);
    expect(signedOrSent.at(-1)).toBe("session:pk1");
    expect(signedOrSent.slice(8, -1).sort()).toEqual([
      "send:probe",
      "send:probe",
      "send:probe",
      "session:pk1",
      "session:pk1",
      "session:pk1",
      "signCommand:probe",
      "signCommand:probe",
      "signCommand:probe",
    ]);
    const signing = run.events.indexOf("signDocument");
    expect(run.events.slice(signing - 1, signing + 2)).toEqual([
      "session:pk1",
      "signDocument",
      "post",
    ]);
    expect(run.commands[1]!.args).toEqual({
      range: "10.88.37.0/24",
      port: "51820",
      parent: HASH,
    });
    expect(
      run.commands
        .filter((command) => command.action === "probe")
        .map(({ nodeId, args }) => ({ nodeId, args })),
    ).toEqual([
      {
        nodeId: S3,
        args: { port: "51822", peers: "203.0.113.10:51820 203.0.113.20:51820" },
      },
      { nodeId: S1, args: { port: "51820", peers: "203.0.113.30:51822" } },
      { nodeId: S2, args: { port: "51820", peers: "203.0.113.30:51822" } },
    ]);

    const document = run.signed[0]!;
    expect(networkDocumentSchema.safeParse(document).success).toBe(true);
    expect(document).toMatchObject({ version: 5, parent: HASH });
    expect(document.members.at(-1)).toMatchObject({
      node: S3,
      address: "10.88.37.163",
      key: run.request.key,
      signer: run.request.signer,
      port: 51822,
      endpoint: "203.0.113.30:51822",
      nat: false,
    });
    expect(run.posted()).toEqual({
      signed: "signed-document",
      change: "Add server-3 to the private network",
      detail: null,
    });
    expect(run.steps.at(-1)).toEqual({
      kind: "applied",
      members: [
        { name: "server-1", state: "Applied" },
        { name: "server-2", state: "Applied" },
        { name: "server-3", state: "Applied" },
      ],
    });
  });

  it("different prepared keys stop the approval and sign nothing", async () => {
    const run = await setup({
      existing: true,
      joiner: "server",
      preparedKey: wgKey(),
    });
    await expect(approve(run.request, run.expected, run.deps)).rejects.toThrow(
      "server-3 reported different keys; nothing was changed",
    );
    expect(run.signed).toEqual([]);
    expect(run.posted()).toBeNull();
    expect(run.commands.map((command) => command.action)).toEqual([
      "inspect",
      "prepare",
    ]);
  });

  it("seals the preshared keys to the seal keys in the current document", async () => {
    const run = await setup({ existing: true, joiner: "server" });
    await approve(run.request, run.expected, run.deps);
    const document = run.signed[0]!;
    const joiner = document.members.at(-1)!;
    expect(joiner.sealKey).toBe(SEAL[S3]!.public);
    for (const peer of [S1, S2]) {
      const held = document.members.find((one) => one.node === peer)!;
      expect(held.sealKey).toBe(SEAL[peer]!.public);
      expect(await open(SEAL[peer]!, held.psk[S3]!)).toEqual(
        await open(SEAL[S3]!, joiner.psk[peer]!),
      );
    }
  });

  it("waits for the applied state on the live network topic", async () => {
    const run = await setup({ existing: true, joiner: "server" });
    run.hold(1);
    const done = approve(run.request, run.expected, {
      ...run.deps,
      pause: () => new Promise<void>(() => undefined),
    });
    await vi.waitFor(() => expect(run.steps.at(-1)?.kind).toBe("applied"));
    expect(run.steps.at(-1)).toMatchObject({
      members: expect.arrayContaining([
        { name: "server-3", state: "Applying…" },
      ]),
    });
    run.emit();
    expect(await done).toBe(5);
    expect(run.steps.at(-1)).toMatchObject({
      members: expect.arrayContaining([{ name: "server-3", state: "Applied" }]),
    });
  });

  it("a burst of network changes does not end the wait before its deadline", async () => {
    vi.useFakeTimers();
    try {
      const run = await setup({ existing: true, joiner: "server" });
      run.hold(Number.POSITIVE_INFINITY);
      let settled = false;
      const done = approve(run.request, run.expected, run.deps).finally(() => {
        settled = true;
      });
      await run.listening();
      expect(run.reads()).toBe(1);
      for (let wake = 1; wake <= 60; wake += 1) {
        run.emit();
        await run.listening();
        expect(run.reads()).toBe(wake + 1);
      }
      expect(settled).toBe(false);
      await vi.advanceTimersByTimeAsync(180_000);
      expect(await done).toBe(5);
      expect(run.steps.at(-1)).toMatchObject({
        members: expect.arrayContaining([
          { name: "server-3", state: "Applying…" },
        ]),
      });
    } finally {
      vi.useRealTimers();
    }
  });

  it("a joiner the probe never reached is written behind NAT", async () => {
    for (const setting of [
      { arrived: [] },
      { arrived: ["198.51.100.9"] },
      { found: null },
    ]) {
      const run = await setup({ existing: true, joiner: "server", ...setting });
      await approve(run.request, run.expected, run.deps);
      expect(run.signed[0]!.members.at(-1)).toMatchObject({
        node: S3,
        endpoint: null,
        nat: true,
      });
      expect(run.commands.some((command) => command.action === "probe")).toBe(
        setting.found !== null,
      );
    }
  });

  it("creates the network with a random free range and the default rule", async () => {
    const run = await setup({ existing: false, joiner: "server" });
    await approve(run.request, run.expected, run.deps);
    expect(run.commands.map((command) => command.action)).toEqual([
      "inspect",
      "prepare",
    ]);
    expect(run.commands[1]!.args).toEqual({
      range: "10.88.128.0/24",
      port: "51822",
    });
    expect(run.checked).toEqual([]);
    expect(run.nextAsked).toEqual([{ ids: [S3], range: "10.88.128.0/24" }]);
    const document = run.signed[0]!;
    expect(document).toMatchObject({
      version: 1,
      range: "10.88.128.0/24",
      port: 51822,
      mtu: 1420,
      allow: [
        { from: { group: "laptops" }, to: { group: "servers" }, ports: "all" },
      ],
    });
    expect(document).not.toHaveProperty("parent");
    expect(document.members[0]).toMatchObject({
      endpoint: "203.0.113.30:51822",
      nat: false,
    });
    expect(run.posted()!.change).toBe(
      "Create the private network with server-3",
    );
  });

  it("a laptop is checked in its tray and runs no command", async () => {
    const run = await setup({ existing: true, joiner: "laptop" });
    expect((await fingerprintOf(run.request)).line).toBe(
      "Check that laptop-1 shows the same fingerprint: in the tray, Fingerprint.",
    );
    await approve(run.request, run.expected, run.deps);
    expect(run.commands).toEqual([]);
    expect(run.signed[0]!.members.at(-1)).toMatchObject({
      node: L1,
      kind: "laptop",
      endpoint: null,
    });
    expect(run.posted()!.change).toBe(
      "Add the laptop laptop-1 to the private network",
    );
  });

  it("a laptop cannot start a network", async () => {
    const run = await setup({ existing: false, joiner: "laptop" });
    await expect(approve(run.request, run.expected, run.deps)).rejects.toThrow(
      "A private network starts with a server. Approve a server first.",
    );
    expect(run.events).toEqual([]);
  });

  it("a change builds on the current document and is signed by the passkeys of the members it keeps", async () => {
    const run = await setup({ existing: true, joiner: "server" });
    const version = await changeNetwork(
      (next) => withoutMember(next, S2),
      "Remove server-2 from the private network",
      run.deps,
    );
    expect(version).toBe(5);
    expect(run.events).toEqual([
      "session:pk1,only-server-1",
      "signDocument",
      "post",
    ]);
    expect(run.signed[0]).toMatchObject({ version: 5, parent: HASH });
    expect(run.signed[0]!.members.map((one) => one.node)).toEqual([S1]);
    expect(run.posted()!.change).toBe(
      "Remove server-2 from the private network",
    );
    const lost = await setup({
      existing: true,
      joiner: "server",
      untrusted: S2,
    });
    await changeNetwork(
      (next) => withoutMember(next, S2),
      "Remove server-2 from the private network",
      lost.deps,
    );
    expect(lost.events).toEqual([
      "session:pk1,only-server-1",
      "signDocument",
      "post",
    ]);
    for (const [untrusted, access] of [
      [undefined, "pk1"],
      [S2, "pk1,only-server-1"],
    ] as const) {
      const gone = await setup({ existing: true, joiner: "server", untrusted });
      await changeNetwork(
        withoutNetwork,
        "Delete the private network",
        gone.deps,
      );
      expect(gone.events).toEqual([
        `session:${access}`,
        "signDocument",
        "post",
      ]);
      expect(gone.signed[0]).toMatchObject({ deleted: true, members: [] });
    }
    const none = await setup({ existing: false, joiner: "server" });
    await expect(
      changeNetwork((next) => next, "Delete the private network", none.deps),
    ).rejects.toThrow("There is no private network.");
  });
});

describe("a change and its detail", () => {
  it("posts the detail it was given, and none by default", async () => {
    const run = await setup({ existing: true, joiner: "server" });
    await changeNetwork(
      (next) => withoutMember(next, S2),
      "Remove server-2 from the private network",
      { ...run.deps, detail: "Was: server-1 can connect to server-2." },
    );
    expect(run.posted()).toMatchObject({
      change: "Remove server-2 from the private network",
      detail: "Was: server-1 can connect to server-2.",
    });
    const plain = await setup({ existing: true, joiner: "server" });
    await changeNetwork(
      (next) => withoutMember(next, S2),
      "Remove server-2 from the private network",
      plain.deps,
    );
    expect(plain.posted()!.detail).toBeNull();
  });
});

describe("new keys", () => {
  const ask = (run: Awaited<ReturnType<typeof setup>>, yes = true) => {
    const shown: { fingerprint: string; line: string }[] = [];
    return {
      shown,
      confirm: async (one: { fingerprint: string; line: string }) => {
        run.events.push("confirm");
        shown.push(one);
        return yes;
      },
    };
  };

  it("one passkey touch makes the key and signs the document, after the fingerprint is confirmed", async () => {
    const run = await setup({ existing: true, joiner: "server" });
    const { shown, confirm } = ask(run);
    const old = (await run.deps.api.current())!.document.members[0]!;
    expect(await renewKeys(S1, confirm, run.deps)).toBe(5);
    expect(run.events).toEqual([
      "session:pk1",
      "signCommand:rekey",
      "send:rekey",
      "confirm",
      "session:pk1",
      "signDocument",
      "post",
    ]);
    expect(shown).toEqual([
      {
        fingerprint: await joinFingerprint(REKEYED, old.signer, old.sealKey),
        line: "Check that server-1 shows the same fingerprint: run sudo kry network fingerprint on it.",
      },
    ]);
    const signed = run.signed[0]!;
    expect(signed.members[0]).toMatchObject({ node: S1, key: REKEYED });
    expect(signed.blocked).toContain(old.key);
    expect(signed.version).toBe(5);
  });

  it("a fingerprint that is not confirmed signs no document", async () => {
    const run = await setup({ existing: true, joiner: "server" });
    expect(await renewKeys(S1, ask(run, false).confirm, run.deps)).toBeNull();
    expect(run.events).not.toContain("signDocument");
    expect(run.events).not.toContain("post");
  });

  it("everything new keys need is checked before anything is signed", async () => {
    const none = await setup({ existing: false, joiner: "server" });
    await expect(renewKeys(S1, ask(none).confirm, none.deps)).rejects.toThrow(
      "There is no private network.",
    );
    expect(none.events).toEqual([]);
    const run = await setup({ existing: true, joiner: "server" });
    const offline = {
      ...run.deps,
      api: {
        ...run.deps.api,
        nodes: async () =>
          (await run.deps.api.nodes()).map((node) =>
            node.id === S1 ? { ...node, online: false } : node,
          ),
      },
    };
    await expect(renewKeys(S1, ask(run).confirm, offline)).rejects.toThrow(
      "server-1 is offline.",
    );
    await expect(renewKeys(S3, ask(run).confirm, run.deps)).rejects.toThrow(
      "That machine is not in the private network.",
    );
    expect(run.events).toEqual([]);
  });

  it("an answer with another signer or a blocked key asks nothing and signs no document", async () => {
    for (const patch of ["signer", "blocked"] as const) {
      const run = await setup({ existing: true, joiner: "server" });
      const current = (await run.deps.api.current())!;
      const old = current.document.members[0]!;
      const changed = {
        ...run.deps,
        api: {
          ...run.deps.api,
          current: async () =>
            patch === "blocked"
              ? {
                  ...current,
                  document: { ...current.document, blocked: [REKEYED] },
                }
              : current,
          sendAction: async (
            body: Parameters<typeof run.deps.api.sendAction>[0],
          ) => {
            const row = await run.deps.api.sendAction(body);
            return patch === "signer"
              ? {
                  ...row,
                  message: JSON.stringify({
                    ...(JSON.parse(row.message!) as object),
                    signer: wgKey(),
                  }),
                }
              : row;
          },
        },
      };
      await expect(renewKeys(S1, ask(run).confirm, changed)).rejects.toThrow(
        `${old.name} reported different keys; nothing was changed`,
      );
      expect(run.events).not.toContain("confirm");
      expect(run.events).not.toContain("signDocument");
    }
  });

  it("a session that expired while the fingerprint was checked signs and posts nothing", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      const run = await setup({ existing: true, joiner: "server" });
      const pair = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["sign", "verify"],
      );
      const live = {
        ...session,
        key: pair.privateKey,
        expiresAt: Date.now() + 300_000,
      };
      const real = {
        ...run.deps,
        sign: {
          ...run.deps.sign,
          openSession: async () => live,
          signCommand: async (one: Session, command: object) => {
            run.events.push("signCommand");
            return signCommand(one, command);
          },
          signDocument,
        },
      };
      await expect(
        renewKeys(
          S1,
          async () => {
            vi.setSystemTime(Date.now() + 300_001);
            return true;
          },
          real,
        ),
      ).rejects.toThrow(
        "server-1 made new keys, but the network document was not signed. Open New Keys again to finish.",
      );
      expect(run.events).toContain("signCommand");
      expect(run.events).not.toContain("post");
    } finally {
      vi.useRealTimers();
    }
  });

  it("an answer Krynodes cannot read stops before the document", async () => {
    const run = await setup({ existing: true, joiner: "server" });
    const unreadable = {
      ...run.deps,
      api: {
        ...run.deps.api,
        sendAction: async (
          body: Parameters<typeof run.deps.api.sendAction>[0],
        ) => ({
          ...(await run.deps.api.sendAction(body)),
          message: "{}",
        }),
      },
    };
    await expect(renewKeys(S1, ask(run).confirm, unreadable)).rejects.toThrow(
      "server-1 sent an answer Krynodes cannot read.",
    );
    expect(run.events).not.toContain("confirm");
    expect(run.events).not.toContain("signDocument");
  });
});

describe("the browser's own anchor in every flow", () => {
  const kept = (run: Awaited<ReturnType<typeof setup>>) =>
    JSON.parse(run.store.getItem("krynodes:network-anchor") ?? "null") as {
      pins: Record<string, string>;
      version: number;
      hash: string | null;
    } | null;
  const fingerprintOfMember = (node: string, document: NetworkDocument) => {
    const one = document.members.find((member) => member.node === node)!;
    return joinFingerprint(one.key, one.signer, one.sealKey);
  };
  const pinAll = async (run: Awaited<ReturnType<typeof setup>>) =>
    remember(
      run.store,
      await Promise.all(
        run.document!.members.map(async (one) => ({
          node: one.node,
          fingerprint: await fingerprintOfMember(one.node, run.document!),
        })),
      ),
      { version: 4, hash: HASH },
    );

  it("a fresh browser shows every member's fingerprint once before the passkey, then keeps what it signed", async () => {
    const run = await setup({ existing: true, joiner: "server" });
    const deps = {
      ...run.deps,
      check: async (members: Unchecked[]) => {
        run.events.push("check");
        return run.deps.check(members);
      },
    };
    await approve(run.request, run.expected, deps);
    expect(run.events[0]).toBe("check");
    expect(run.checked).toEqual([
      [
        {
          node: S1,
          name: "server-1",
          fingerprint: await fingerprintOfMember(S1, run.document!),
          line: "Check that server-1 shows the same fingerprint: run sudo kry network fingerprint on it.",
        },
        {
          node: S2,
          name: "server-2",
          fingerprint: await fingerprintOfMember(S2, run.document!),
          line: "Check that server-2 shows the same fingerprint: run sudo kry network fingerprint on it.",
        },
      ],
    ]);
    expect(kept(run)).toEqual({
      pins: {
        [S1]: await fingerprintOfMember(S1, run.document!),
        [S2]: await fingerprintOfMember(S2, run.document!),
        [S3]: run.expected,
      },
      version: 5,
      hash: await hashOf(run.signed[0]!),
    });
  });

  it("a browser that has checked every member asks nothing more", async () => {
    const run = await setup({ existing: true, joiner: "server" });
    await pinAll(run);
    await changeNetwork((next) => next, "Change nothing", run.deps);
    expect(run.checked).toEqual([]);
    expect(kept(run)).toMatchObject({
      version: 5,
      hash: await hashOf(run.signed[0]!),
    });
  });

  it("a check that is not confirmed opens no session and keeps nothing", async () => {
    for (const flow of ["approve", "change", "keys"] as const) {
      const run = await setup({ existing: true, joiner: "server" });
      const deps = { ...run.deps, check: async () => false };
      const done =
        flow === "approve"
          ? approve(run.request, run.expected, deps)
          : flow === "change"
            ? changeNetwork((next) => next, "Change nothing", deps)
            : renewKeys(S1, async () => true, deps);
      await expect(done).rejects.toThrow(
        "The fingerprints were not confirmed. Nothing was signed.",
      );
      expect(run.events).toEqual([]);
      expect(kept(run)).toBeNull();
    }
  });

  it("a member whose keys changed since this browser saw them is checked again, and its pin moves only after the confirm", async () => {
    for (const answer of [false, true]) {
      const run = await setup({ existing: true, joiner: "server" });
      await pinAll(run);
      remember(run.store, [{ node: S2, fingerprint: "AAAA-AAAA-AAAA-AAAA" }]);
      const deps = {
        ...run.deps,
        check: async (members: Unchecked[]) => {
          await run.deps.check(members);
          return answer;
        },
      };
      const done = changeNetwork((next) => next, "Change nothing", deps);
      if (answer) {
        expect(await done).toBe(5);
      } else {
        await expect(done).rejects.toThrow(
          "The fingerprints were not confirmed. Nothing was signed.",
        );
        expect(run.events).toEqual([]);
      }
      expect(run.checked).toEqual([
        [
          {
            node: S2,
            name: "server-2",
            fingerprint: await fingerprintOfMember(S2, run.document!),
            line: "Check that server-2 shows the same fingerprint: run sudo kry network fingerprint on it.",
            warning:
              "server-2's keys changed since this browser last saw them. Check them on server-2 before you go on.",
          },
        ],
      ]);
      expect(kept(run)!.pins[S2]).toBe(
        answer
          ? await fingerprintOfMember(S2, run.document!)
          : "AAAA-AAAA-AAAA-AAAA",
      );
    }
  });

  it("an older document, or another one of the same version, stops every flow before the passkey", async () => {
    const problems = [
      {
        keep: (run: Awaited<ReturnType<typeof setup>>) =>
          remember(run.store, [], { version: 6, hash: HASH }),
        line: "The network document is older than the one this browser last signed or checked. Nothing was signed.",
      },
      {
        keep: (run: Awaited<ReturnType<typeof setup>>) =>
          remember(run.store, [], { version: 4, hash: "r".repeat(43) }),
        line: "The network document is not the one this browser last signed or checked. Nothing was signed.",
      },
    ];
    for (const { keep, line } of problems) {
      for (const flow of ["approve", "change", "keys"] as const) {
        const run = await setup({ existing: true, joiner: "server" });
        keep(run);
        const done =
          flow === "approve"
            ? approve(run.request, run.expected, run.deps)
            : flow === "change"
              ? changeNetwork((next) => next, "Change nothing", run.deps)
              : renewKeys(S1, async () => true, run.deps);
        await expect(done, `${flow}: ${line}`).rejects.toThrow(line);
        expect(run.events).toEqual([]);
        expect(run.checked).toEqual([]);
      }
    }
  });

  it("new keys keep the new fingerprint only once the document is posted", async () => {
    const run = await setup({ existing: true, joiner: "server" });
    await pinAll(run);
    const old = run.document!.members[0]!;
    expect(await renewKeys(S1, async () => true, run.deps)).toBe(5);
    expect(kept(run)!.pins[S1]).toBe(
      await joinFingerprint(REKEYED, old.signer, old.sealKey),
    );
    const refused = await setup({ existing: true, joiner: "server" });
    await pinAll(refused);
    const before = kept(refused);
    const failing = {
      ...refused.deps,
      api: {
        ...refused.deps.api,
        postDocument: async () => {
          throw new Error("refused");
        },
      },
    };
    await expect(renewKeys(S1, async () => true, failing)).rejects.toThrow(
      "refused",
    );
    expect(kept(refused)).toEqual(before);
  });

  it("re-creating a network prepares the server for the deleted document it builds on", async () => {
    const run = await setup({ existing: true, joiner: "server" });
    const view = await run.deps.api.network();
    const deps = {
      ...run.deps,
      api: {
        ...run.deps.api,
        network: async () => ({
          ...view,
          network: { ...view.network!, deleted: true },
        }),
      },
    };
    await approve(run.request, run.expected, deps);
    expect(run.commands[1]!.args).toEqual({
      range: "10.88.128.0/24",
      port: "51822",
      parent: HASH,
    });
    expect(run.signed[0]).toMatchObject({ version: 5, parent: HASH });
    expect(run.checked).toEqual([]);
  });
});

describe("a passkey session that ends in the middle of a flow", () => {
  it("approve asks the session again right before it signs, and says what was already done when it cannot", async () => {
    const run = await setup({ existing: true, joiner: "server" });
    const deps = {
      ...run.deps,
      sign: {
        ...run.deps.sign,
        openSession: async (access: string[]) => {
          if (
            run.events.filter((one) => one.startsWith("send:")).length === 5
          ) {
            throw new Error("The passkey was not used.");
          }
          return run.deps.sign.openSession(access);
        },
      },
    };
    await expect(approve(run.request, run.expected, deps)).rejects.toThrow(
      "server-3 is prepared, but the network document was not signed. Approve it again.",
    );
    expect(run.signed).toEqual([]);
    expect(run.posted()).toBeNull();
  });

  it("new keys ask the session again after the fingerprint, and say the keys were made when it cannot", async () => {
    const run = await setup({ existing: true, joiner: "server" });
    const deps = {
      ...run.deps,
      sign: {
        ...run.deps.sign,
        openSession: async (access: string[]) => {
          if (run.events.includes("send:rekey")) {
            throw new Error("The passkey was not used.");
          }
          return run.deps.sign.openSession(access);
        },
      },
    };
    await expect(renewKeys(S1, async () => true, deps)).rejects.toThrow(
      "server-1 made new keys, but the network document was not signed. Open New Keys again to finish.",
    );
    expect(run.signed).toEqual([]);
  });
});
