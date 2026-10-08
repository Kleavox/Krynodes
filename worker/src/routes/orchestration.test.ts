import { describe, expect, it } from "vitest";

import { app } from "../app";
import type { Env } from "../env";
import { remindTokens, runRetention } from "../index";
import { hubHarness, type FakeSocket } from "../test/hub";
import { seedNode } from "../test/seed";
import { createTestDb } from "../test/sqlite-d1";

const A = "11111111-1111-4111-8111-111111111111";
const B = "22222222-2222-4222-8222-222222222222";
const C = "33333333-3333-4333-8333-333333333333";
const SET = "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a20";
const NEXT = "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a21";
const keyOf = (node: string) => `B${node.slice(0, 1).repeat(86)}`;

const b64 = (value: unknown) =>
  Buffer.from(JSON.stringify(value)).toString("base64url");
const VERIFIED = Buffer.from(
  Uint8Array.from({ length: 37 }, (_, index) => (index === 32 ? 0x05 : 0)),
).toString("base64url");

interface Step {
  nodeId: string;
  kind: string;
  name: string;
  action: string;
  args?: Record<string, string>;
  compose?: string;
  attachFrom?: number;
  attachKey?: string;
}

function step({ args, compose, ...target }: Step) {
  const id = crypto.randomUUID();
  const { attachFrom, attachKey, ...command } = target;
  return {
    id,
    ...command,
    ...(attachFrom === undefined ? {} : { attachFrom }),
    ...(attachKey === undefined ? {} : { attachKey }),
    signed: {
      grant: {
        grant: "Z3JhbnQ",
        credentialId: "ZGV2aWNlLTE",
        authenticatorData: VERIFIED,
        clientDataJSON: "Y2xpZW50",
        signature: "c2ln",
      },
      command: b64({
        v: 1,
        id,
        ...command,
        ...(args ? { args } : {}),
        ...(compose ? { compose } : {}),
      }),
      signature: "c2lnbmF0dXJl",
    },
  };
}

function routes() {
  const { db, sqlite } = createTestDb();
  for (const id of [A, B, C]) {
    seedNode(sqlite, { id });
    sqlite
      .prepare(
        "UPDATE nodes SET agent_version = '0.6.0', docker = 'ready', seal_key = ?, vault = ?, last_seen_at = datetime('now') WHERE id = ?",
      )
      .run(keyOf(id), JSON.stringify({ set: SET, holders: 3 }), id);
  }
  sqlite
    .prepare(
      "INSERT INTO stacks (node_id, project, directory, running, total, compose, rollback, updated_at, access) VALUES (?, 'listmonk', '/var/lib/kry-exec/compose/listmonk', 2, 2, 1, 0, datetime('now'), 'contained')",
    )
    .run(A);
  sqlite
    .prepare(
      "INSERT INTO stacks (node_id, project, directory, running, total, compose, rollback, updated_at) VALUES (?, 'shop', '/opt/shop', 1, 1, 1, 0, datetime('now'))",
    )
    .run(A);
  const env = {
    DB: db,
    PUBLIC_ORIGIN: "https://kry.kleavox.xyz",
  } as unknown as Env;
  const call = (method: string, path: string, body?: unknown) =>
    app.request(
      `https://kry.kleavox.xyz${path}`,
      {
        method,
        headers: { "content-type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
      },
      env,
    );
  const operate = (
    kind: string,
    steps: ReturnType<typeof step>[],
    extra = {},
  ) => call("POST", "/api/operations", { kind, steps, ...extra });
  const rows = () =>
    sqlite
      .prepare(
        "SELECT node_id AS nodeId, action, position, mode, attach_from AS attachFrom, attach_key AS attachKey, deliverable_at IS NOT NULL AS ready FROM actions ORDER BY position",
      )
      .all() as {
      nodeId: string;
      action: string;
      position: number;
      mode: string;
      attachFrom: number | null;
      attachKey: string | null;
      ready: number;
    }[];
  return { db, sqlite, env, call, operate, rows };
}

const code = async (response: Response) =>
  ((await response.json()) as { code?: string }).code;

const moveSteps = (to = B) => [
  step({
    nodeId: A,
    kind: "compose",
    name: "listmonk",
    action: "export",
    args: { to, key: keyOf(to) },
  }),
  step({
    nodeId: to,
    kind: "compose",
    name: "listmonk",
    action: "create",
    compose: "services: {}\n",
    attachFrom: 0,
  }),
  step({ nodeId: A, kind: "compose", name: "listmonk", action: "remove" }),
];

describe("operations in steps", () => {
  it("moves a stack in steps that hand the sealed files along", async () => {
    const t = routes();
    const response = await t.operate("move", moveSteps());
    expect(response.status).toBe(201);
    expect(t.rows()).toEqual([
      {
        nodeId: A,
        action: "export",
        position: 0,
        mode: "rolling",
        attachFrom: null,
        attachKey: null,
        ready: 1,
      },
      {
        nodeId: B,
        action: "create",
        position: 1,
        mode: "rolling",
        attachFrom: 0,
        attachKey: null,
        ready: 0,
      },
      {
        nodeId: A,
        action: "remove",
        position: 2,
        mode: "rolling",
        attachFrom: null,
        attachKey: null,
        ready: 0,
      },
    ]);
  });

  it("refuses a move to a name that is taken, from a stack that is gone, or to an old key", async () => {
    const t = routes();
    t.sqlite
      .prepare(
        "INSERT INTO stacks (node_id, project, directory, running, total, compose, rollback, updated_at) VALUES (?, 'listmonk', '/opt/listmonk', 1, 1, 1, 0, datetime('now'))",
      )
      .run(B);
    expect(await code(await t.operate("move", moveSteps()))).toBe(
      "STACK_EXISTS",
    );
    const gone = moveSteps(C);
    gone[0] = step({
      nodeId: A,
      kind: "compose",
      name: "ghost",
      action: "export",
      args: { to: C, key: keyOf(C) },
    });
    gone[1] = step({
      nodeId: C,
      kind: "compose",
      name: "ghost",
      action: "create",
      compose: "services: {}\n",
      attachFrom: 0,
    });
    expect(await code(await t.operate("move", gone.slice(0, 2)))).toBe(
      "UNKNOWN_TARGET",
    );
    const stale = moveSteps(C);
    stale[0] = step({
      nodeId: A,
      kind: "compose",
      name: "listmonk",
      action: "export",
      args: { to: C, key: keyOf(B) },
    });
    expect(await code(await t.operate("move", stale))).toBe("KEY_CHANGED");
  });

  it("refuses steps out of order, unsigned or signed for something else", async () => {
    const t = routes();
    const [exported, created] = moveSteps();
    expect((await t.operate("move", [created!, exported!])).status).toBe(400);
    const forged = { ...exported!, action: "create" };
    expect(await code(await t.operate("move", [forged, created!]))).toBe(
      "SIGNATURE_MISMATCH",
    );
    const unsigned = { ...exported!, signed: undefined as never };
    expect((await t.operate("move", [unsigned, created!])).status).toBe(400);
  });

  it("needs agent 0.6.0 on every server in the operation", async () => {
    const t = routes();
    t.sqlite
      .prepare("UPDATE nodes SET agent_version = '0.4.0' WHERE id = ?")
      .run(B);
    expect(await code(await t.operate("move", moveSteps()))).toBe(
      "AGENT_TOO_OLD",
    );
  });

  it("opens and closes a web address with a piece released by another server", async () => {
    const t = routes();
    const args = {
      service: "app",
      port: "9000",
      hostname: "listmonk-a.kleavox.xyz",
      mode: "path",
      path: "/admin",
      zone: "kleavox.xyz",
      aud: "aud-1",
    };
    const open = await t.operate("expose", [
      step({
        nodeId: B,
        kind: "vault",
        name: "cloudflare",
        action: "release",
        args: { to: A, key: keyOf(A), set: SET },
      }),
      step({
        nodeId: A,
        kind: "compose",
        name: "listmonk",
        action: "expose",
        args,
        attachFrom: 0,
      }),
    ]);
    expect(open.status).toBe(201);
    t.sqlite.prepare("UPDATE actions SET status = 'done'").run();
    const close = await t.operate("unexpose", [
      step({
        nodeId: B,
        kind: "vault",
        name: "cloudflare",
        action: "release",
        args: { to: A, key: keyOf(A), set: SET },
      }),
      step({
        nodeId: A,
        kind: "compose",
        name: "listmonk",
        action: "unexpose",
        args: { hostname: "listmonk-a.kleavox.xyz", zone: "kleavox.xyz" },
        attachFrom: 0,
      }),
      step({ nodeId: A, kind: "compose", name: "listmonk", action: "purge" }),
    ]);
    expect(close.status).toBe(201);
    const outside = await t.operate("expose", [
      step({
        nodeId: A,
        kind: "compose",
        name: "listmonk",
        action: "expose",
        args: { ...args, hostname: "listmonk.evil.example" },
      }),
    ]);
    expect(outside.status).toBe(400);
  });

  it("refuses a released piece from a server without one", async () => {
    const t = routes();
    t.sqlite.prepare("UPDATE nodes SET vault = NULL WHERE id = ?").run(B);
    const response = await t.operate("expose", [
      step({
        nodeId: B,
        kind: "vault",
        name: "cloudflare",
        action: "release",
        args: { to: A, key: keyOf(A), set: SET },
      }),
      step({
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
        attachFrom: 0,
      }),
    ]);
    expect(await code(response)).toBe("NO_PIECE");
  });

  it("releases a piece the server keeps from the split still in use", async () => {
    const t = routes();
    t.sqlite.prepare("UPDATE nodes SET vault = ? WHERE id = ?").run(
      JSON.stringify({
        set: NEXT,
        holders: 2,
        previous: { set: SET, holders: 3 },
      }),
      B,
    );
    const release = (set: string) =>
      t.operate("expose", [
        step({
          nodeId: B,
          kind: "vault",
          name: "cloudflare",
          action: "release",
          args: { to: A, key: keyOf(A), set },
        }),
        step({
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
            source: set,
          },
          attachFrom: 0,
        }),
      ]);
    expect((await release(SET)).status).toBe(201);
    t.sqlite.prepare("UPDATE actions SET status = 'done'").run();
    expect(
      await code(await release("0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a99")),
    ).toBe("NO_PIECE");
  });

  it("splits the token across servers at once and remembers the zone", async () => {
    const t = routes();
    const stores = [A, B, C].map((nodeId) =>
      step({
        nodeId,
        kind: "vault",
        name: "cloudflare",
        action: "store",
        args: { set: NEXT, holders: "3" },
      }),
    );
    const response = await t.operate("split", stores, { zone: "kleavox.xyz" });
    expect(response.status).toBe(201);
    expect(
      t.rows().every((row) => row.mode === "parallel" && row.ready === 1),
    ).toBe(true);
    expect(
      t.sqlite.prepare("SELECT zone, set_id FROM cloudflare").get(),
    ).toEqual({ zone: "kleavox.xyz", set_id: null });
  });

  it("allows one token change at a time", async () => {
    const t = routes();
    const split = (set: string) =>
      [A, B].map((nodeId) =>
        step({
          nodeId,
          kind: "vault",
          name: "cloudflare",
          action: "store",
          args: { set, holders: "2" },
        }),
      );
    expect(
      (await t.operate("split", split(NEXT), { zone: "kleavox.xyz" })).status,
    ).toBe(201);
    const second = await t.operate("split", split(SET), {
      zone: "kleavox.xyz",
    });
    expect(second.status).toBe(409);
    expect(await code(second)).toBe("TOKEN_BUSY");
    const open = await t.operate("expose", [
      step({
        nodeId: A,
        kind: "compose",
        name: "listmonk",
        action: "expose",
        args: {
          service: "app",
          port: "9000",
          hostname: "listmonk-a.kleavox.xyz",
          mode: "everyone",
          zone: "kleavox.xyz",
        },
      }),
    ]);
    expect(await code(open)).toBe("TOKEN_BUSY");
    t.sqlite.prepare("UPDATE actions SET status = 'done'").run();
    expect(
      (await t.operate("split", split(SET), { zone: "kleavox.xyz" })).status,
    ).toBe(201);
  });

  it("lets an expired token step go before a new change, and says when the token is only in use", async () => {
    const t = routes();
    const split = () =>
      [A, B].map((nodeId) =>
        step({
          nodeId,
          kind: "vault",
          name: "cloudflare",
          action: "store",
          args: { set: NEXT, holders: "2" },
        }),
      );
    const pending = (action: string, minutesAgo: number) => {
      const at = new Date(Date.now() - minutesAgo * 60_000).toISOString();
      t.sqlite
        .prepare(
          `INSERT INTO actions (id, batch_id, position, mode, node_id, kind, name, action,
             status, requested_by, requested_at, deliverable_at)
           VALUES (?, ?, 0, 'rolling', ?, 'vault', 'cloudflare', ?, 'queued', 'owner@example.test', ?, ?)`,
        )
        .run(crypto.randomUUID(), crypto.randomUUID(), A, action, at, at);
    };
    pending("store", 11);
    pending("release", 1);
    const busy = await t.operate("split", split(), { zone: "kleavox.xyz" });
    expect(busy.status).toBe(409);
    expect(await busy.json()).toMatchObject({
      code: "TOKEN_BUSY",
      message:
        "The Cloudflare token is in use for a web address. Try again when that finishes.",
    });
    t.sqlite
      .prepare("UPDATE actions SET status = 'done' WHERE action = 'release'")
      .run();
    expect(
      (await t.operate("split", split(), { zone: "kleavox.xyz" })).status,
    ).toBe(201);
  });

  it("re-splits and hands every remaining server its own new piece", async () => {
    const t = routes();
    const response = await t.operate("reshare", [
      step({
        nodeId: B,
        kind: "vault",
        name: "cloudflare",
        action: "release",
        args: { to: A, key: keyOf(A), set: SET },
      }),
      step({
        nodeId: A,
        kind: "vault",
        name: "cloudflare",
        action: "reshare",
        args: {
          holders: `${A}:${keyOf(A)},${C}:${keyOf(C)}`,
          set: NEXT,
          cleanup: B,
          zone: "kleavox.xyz",
        },
        attachFrom: 0,
      }),
      step({
        nodeId: A,
        kind: "vault",
        name: "cloudflare",
        action: "store",
        args: { set: NEXT, holders: "2" },
        attachFrom: 1,
        attachKey: A,
      }),
      step({
        nodeId: C,
        kind: "vault",
        name: "cloudflare",
        action: "store",
        args: { set: NEXT, holders: "2" },
        attachFrom: 1,
        attachKey: C,
      }),
    ]);
    expect(response.status).toBe(201);
    expect(
      t.rows().map((row) => [row.action, row.attachFrom, row.attachKey]),
    ).toEqual([
      ["release", null, null],
      ["reshare", 0, null],
      ["store", 1, A],
      ["store", 1, C],
    ]);
    const missing = await t.operate("reshare", [
      step({
        nodeId: B,
        kind: "vault",
        name: "cloudflare",
        action: "release",
        args: { to: A, key: keyOf(A), set: SET },
      }),
      step({
        nodeId: A,
        kind: "vault",
        name: "cloudflare",
        action: "reshare",
        args: {
          holders: `${A}:${keyOf(A)},${C}:${keyOf(C)}`,
          set: NEXT,
          zone: "kleavox.xyz",
        },
        attachFrom: 0,
      }),
      step({
        nodeId: A,
        kind: "vault",
        name: "cloudflare",
        action: "store",
        args: { set: NEXT, holders: "2" },
        attachFrom: 1,
        attachKey: A,
      }),
    ]);
    expect(missing.status).toBe(400);
  });
});

describe("single steps of agent 0.6.0", () => {
  const single = (
    t: ReturnType<typeof routes>,
    target: Step,
    signedTarget = true,
  ) => {
    const made = step(target);
    const { attachFrom: _, attachKey: __, signed, ...rest } = made;
    return t.call("POST", "/api/actions", {
      action: target.action,
      targets: [
        signedTarget
          ? { ...rest, signed }
          : { nodeId: rest.nodeId, kind: rest.kind, name: rest.name },
      ],
    });
  };

  it("installs Docker only where it is missing, signed, and pairs host verbs with their names", async () => {
    const t = routes();
    const install = (nodeId: string) =>
      single(t, { nodeId, kind: "host", name: "docker", action: "install" });
    expect(await code(await install(A))).toBe("UNKNOWN_TARGET");
    t.sqlite.prepare("UPDATE nodes SET docker = 'missing' WHERE id = ?").run(A);
    t.sqlite
      .prepare("UPDATE nodes SET docker = 'no-compose' WHERE id = ?")
      .run(B);
    expect((await install(A)).status).toBe(201);
    expect((await install(B)).status).toBe(201);
    expect(
      (
        await single(
          t,
          { nodeId: C, kind: "host", name: "docker", action: "install" },
          false,
        )
      ).status,
    ).toBe(400);
    for (const [name, action] of [
      ["docker", "apply"],
      ["server", "apply"],
      ["fail2ban", "lockdown"],
      ["fail2ban", "install"],
    ] as const) {
      expect(
        (await single(t, { nodeId: C, kind: "host", name, action })).status,
        `${name} ${action}`,
      ).toBe(400);
    }
  });

  it("removes Krynodes from a server only signed", async () => {
    const t = routes();
    const uninstall = {
      nodeId: A,
      kind: "host",
      name: "server",
      action: "uninstall",
    } as const;
    expect((await single(t, uninstall, false)).status).toBe(400);
    expect((await single(t, uninstall)).status).toBe(201);
    expect(
      (await single(t, { ...uninstall, nodeId: B, name: "fail2ban" })).status,
    ).toBe(400);
  });

  it("applies and undoes recipes, locks a server down and checks it unsigned", async () => {
    const t = routes();
    expect(
      (
        await single(t, {
          nodeId: A,
          kind: "host",
          name: "security-updates",
          action: "apply",
        })
      ).status,
    ).toBe(201);
    expect(
      (
        await single(t, {
          nodeId: B,
          kind: "host",
          name: "server",
          action: "lockdown",
        })
      ).status,
    ).toBe(201);
    expect(
      (
        await single(
          t,
          { nodeId: C, kind: "host", name: "server", action: "scan" },
          false,
        )
      ).status,
    ).toBe(201);
    t.sqlite
      .prepare("UPDATE nodes SET agent_version = '0.4.0' WHERE id = ?")
      .run(C);
    expect(
      await code(
        await single(t, {
          nodeId: C,
          kind: "host",
          name: "fail2ban",
          action: "apply",
        }),
      ),
    ).toBe("AGENT_TOO_OLD");
  });

  it("edits only stacks Krynodes made, reads any, and moves in only the others", async () => {
    const t = routes();
    expect(
      (
        await single(t, {
          nodeId: A,
          kind: "compose",
          name: "listmonk",
          action: "edit",
          compose: "services: {}\n",
        })
      ).status,
    ).toBe(201);
    t.sqlite.prepare("UPDATE actions SET status = 'done'").run();
    expect(
      await code(
        await single(t, {
          nodeId: A,
          kind: "compose",
          name: "shop",
          action: "edit",
          compose: "services: {}\n",
        }),
      ),
    ).toBe("UNKNOWN_TARGET");
    expect(
      (
        await single(t, {
          nodeId: A,
          kind: "compose",
          name: "shop",
          action: "read",
        })
      ).status,
    ).toBe(201);
    expect(
      (
        await single(t, {
          nodeId: A,
          kind: "compose",
          name: "shop",
          action: "adopt",
        })
      ).status,
    ).toBe(201);
    t.sqlite.prepare("UPDATE actions SET status = 'done'").run();
    expect(
      await code(
        await single(t, {
          nodeId: A,
          kind: "compose",
          name: "listmonk",
          action: "adopt",
        }),
      ),
    ).toBe("UNKNOWN_TARGET");
  });

  it("knows a stack Krynodes made before access levels by its folder", async () => {
    const t = routes();
    t.sqlite
      .prepare(
        "INSERT INTO stacks (node_id, project, directory, running, total, compose, rollback, updated_at) VALUES (?, 'kuma', '/var/lib/kry-exec/compose/kuma', 1, 1, 1, 0, datetime('now'))",
      )
      .run(A);
    expect(
      await code(
        await single(t, {
          nodeId: A,
          kind: "compose",
          name: "kuma",
          action: "adopt",
        }),
      ),
    ).toBe("UNKNOWN_TARGET");
    expect(
      (
        await single(t, {
          nodeId: A,
          kind: "compose",
          name: "kuma",
          action: "edit",
          compose: "services: {}\n",
        })
      ).status,
    ).toBe(201);
  });

  it("needs agent 0.6.0 for a stack with an access level or secrets", async () => {
    const t = routes();
    t.sqlite
      .prepare("UPDATE nodes SET agent_version = '0.4.0' WHERE id = ?")
      .run(B);
    const made = step({
      nodeId: B,
      kind: "compose",
      name: "kuma",
      action: "create",
      compose: "services: {}\n",
    });
    const command = JSON.parse(
      Buffer.from(made.signed.command, "base64url").toString(),
    ) as Record<string, unknown>;
    made.signed.command = b64({ ...command, access: "full" });
    const { attachFrom: _, attachKey: __, ...target } = made;
    const response = await t.call("POST", "/api/actions", {
      action: "create",
      targets: [target],
    });
    expect(await code(response)).toBe("AGENT_TOO_OLD");
  });
});

async function hub() {
  const { db, sqlite } = createTestDb();
  sqlite
    .prepare(
      "INSERT INTO cloudflare (owner_user_id, zone, set_id, updated_at) VALUES ('standalone', 'kleavox.xyz', ?, datetime('now'))",
    )
    .run(SET);
  for (const id of [A, B, C]) {
    seedNode(sqlite, { id });
    sqlite
      .prepare(
        "UPDATE nodes SET agent_version = '0.6.0', docker = 'ready', seal_key = ? WHERE id = ?",
      )
      .run(keyOf(id), id);
  }
  sqlite
    .prepare(
      "INSERT INTO stacks (node_id, project, directory, running, total, compose, rollback, updated_at, access) VALUES (?, 'listmonk', '/var/lib/kry-exec/compose/listmonk', 2, 2, 1, 0, datetime('now'), 'contained')",
    )
    .run(A);
  const harness = hubHarness({ DB: db });
  const sockets = new Map<string, FakeSocket>();
  const send = async (
    nodeId: string,
    type: string,
    fields: Record<string, unknown>,
  ) => {
    let socket = sockets.get(nodeId);
    if (!socket) {
      socket = await harness.connect(nodeId);
      sockets.set(nodeId, socket);
    }
    return (await harness.request(socket, type, fields)) ?? {};
  };
  const beat = async (nodeId: string) =>
    ((
      await send(nodeId, "heartbeat", {
        heartbeat: {
          nodeId,
          hostname: "web-01",
          operatingSystem: "Debian 12.10",
          architecture: "amd64",
          agentVersion: "0.6.0",
          metrics: {
            cpuPercent: 1,
            memoryUsedBytes: 1,
            memoryTotalBytes: 2,
            diskUsedBytes: 1,
            diskTotalBytes: 2,
            load1: 0,
            load5: 0,
            load15: 0,
            uptimeSeconds: 1,
          },
        },
      })
    ).response ?? {}) as { actions?: Record<string, unknown>[] };
  const finish = (nodeId: string, id: string, output: string, ok = true) =>
    send(nodeId, "actions", {
      report: {
        nodeId,
        results: [
          {
            id,
            ok,
            exitCode: ok ? 0 : 1,
            output,
            finishedAt: new Date().toISOString(),
          },
        ],
      },
    });
  const env = {
    DB: db,
    PUBLIC_ORIGIN: "https://kry.kleavox.xyz",
  } as unknown as Env;
  const operate = async (
    kind: string,
    steps: ReturnType<typeof step>[],
    extra = {},
  ) => {
    const response = await app.request(
      "https://kry.kleavox.xyz/api/operations",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ kind, steps, ...extra }),
      },
      env,
    );
    expect(response.status).toBe(201);
    return steps.map((made) => made.id);
  };
  return { db, sqlite, beat, finish, operate, send };
}

describe("steps that feed the next", () => {
  it("hands the sealed files to the target and forgets them", async () => {
    const t = await hub();
    const [exportId, createId] = await t.operate(
      "move",
      moveSteps().slice(0, 2),
    );
    expect((await t.beat(A)).actions?.[0]).toMatchObject({
      id: exportId,
      action: "export",
    });
    await t.finish(A, exportId!, "c2VhbGVk");
    const delivered = (await t.beat(B)).actions?.[0];
    expect(delivered).toMatchObject({
      id: createId,
      action: "create",
      attachment: "c2VhbGVk",
    });
    expect(
      t.sqlite
        .prepare("SELECT output FROM actions WHERE id = ?")
        .get(exportId!),
    ).toEqual({ output: null });
    await t.finish(B, createId!, "created");
    expect(
      t.sqlite
        .prepare("SELECT attachment FROM actions WHERE id = ?")
        .get(createId!),
    ).toEqual({ attachment: null });
  });

  it("keeps the old split until the new one can rebuild the token", async () => {
    const t = await hub();
    const current = () =>
      (
        t.sqlite.prepare("SELECT set_id FROM cloudflare").get() as {
          set_id: string;
        }
      ).set_id;
    const ids = await t.operate(
      "split",
      [A, B, C].map((nodeId) =>
        step({
          nodeId,
          kind: "vault",
          name: "cloudflare",
          action: "store",
          args: { set: NEXT, holders: "3" },
        }),
      ),
      { zone: "kleavox.xyz" },
    );
    expect(current()).toBe(SET);
    await t.beat(A);
    await t.finish(A, ids[0]!, "stored");
    expect(current()).toBe(SET);
    await t.beat(B);
    await t.finish(B, ids[1]!, "stored");
    expect(current()).toBe(NEXT);
  });

  it("switches at once when one server keeps the whole token", async () => {
    const t = await hub();
    const [id] = await t.operate(
      "split",
      [
        step({
          nodeId: A,
          kind: "vault",
          name: "cloudflare",
          action: "store",
          args: { set: NEXT, holders: "1" },
        }),
      ],
      { zone: "kleavox.xyz" },
    );
    await t.beat(A);
    await t.finish(A, id!, "stored");
    expect(t.sqlite.prepare("SELECT set_id FROM cloudflare").get()).toEqual({
      set_id: NEXT,
    });
  });

  it("gives each server its own new piece after a re-split", async () => {
    const t = await hub();
    t.sqlite
      .prepare("UPDATE nodes SET vault = ?")
      .run(JSON.stringify({ set: SET, holders: 3 }));
    const ids = await t.operate("reshare", [
      step({
        nodeId: B,
        kind: "vault",
        name: "cloudflare",
        action: "release",
        args: { to: A, key: keyOf(A), set: SET },
      }),
      step({
        nodeId: A,
        kind: "vault",
        name: "cloudflare",
        action: "reshare",
        args: {
          holders: `${A}:${keyOf(A)},${C}:${keyOf(C)}`,
          set: NEXT,
          zone: "kleavox.xyz",
        },
        attachFrom: 0,
      }),
      step({
        nodeId: A,
        kind: "vault",
        name: "cloudflare",
        action: "store",
        args: { set: NEXT, holders: "2" },
        attachFrom: 1,
        attachKey: A,
      }),
      step({
        nodeId: C,
        kind: "vault",
        name: "cloudflare",
        action: "store",
        args: { set: NEXT, holders: "2" },
        attachFrom: 1,
        attachKey: C,
      }),
    ]);
    await t.beat(B);
    await t.finish(B, ids[0]!, "cGllY2VC");
    expect((await t.beat(A)).actions?.[0]).toMatchObject({
      id: ids[1],
      attachment: "cGllY2VC",
    });
    await t.finish(
      A,
      ids[1]!,
      JSON.stringify({ [A]: "Zm9yQQ", [C]: "Zm9yQw" }),
    );
    expect((await t.beat(A)).actions?.[0]).toMatchObject({
      id: ids[2],
      attachment: "Zm9yQQ",
    });
    expect(t.sqlite.prepare("SELECT set_id FROM cloudflare").get()).toEqual({
      set_id: SET,
    });
    await t.finish(A, ids[2]!, "stored");
    expect(t.sqlite.prepare("SELECT set_id FROM cloudflare").get()).toEqual({
      set_id: SET,
    });
    expect((await t.beat(C)).actions?.[0]).toMatchObject({
      id: ids[3],
      attachment: "Zm9yQw",
    });
    await t.finish(C, ids[3]!, "stored");
    expect(t.sqlite.prepare("SELECT set_id FROM cloudflare").get()).toEqual({
      set_id: NEXT,
    });
    expect(
      t.sqlite
        .prepare(
          "SELECT COUNT(*) AS n FROM actions WHERE attachment IS NOT NULL",
        )
        .get(),
    ).toEqual({ n: 0 });
  });

  it("records a web address when it opens and forgets it when it closes", async () => {
    const t = await hub();
    const args = {
      service: "app",
      port: "9000",
      hostname: "listmonk-a.kleavox.xyz",
      mode: "path",
      path: "/admin",
      zone: "kleavox.xyz",
      aud: "aud-1",
    };
    const [exposeId] = await t.operate("expose", [
      step({
        nodeId: A,
        kind: "compose",
        name: "listmonk",
        action: "expose",
        args,
      }),
    ]);
    await t.beat(A);
    await t.finish(
      A,
      exposeId!,
      JSON.stringify({
        hostname: "listmonk-a.kleavox.xyz",
        expires: "2027-10-05T00:00:00Z",
      }),
    );
    expect(
      t.sqlite
        .prepare(
          "SELECT node_id AS nodeId, project, service, port, mode, path, expires_at AS expiresAt FROM web_addresses",
        )
        .all(),
    ).toEqual([
      {
        nodeId: A,
        project: "listmonk",
        service: "app",
        port: 9000,
        mode: "path",
        path: "/admin",
        expiresAt: "2027-10-05T00:00:00Z",
      },
    ]);
    const [closeId] = await t.operate("unexpose", [
      step({
        nodeId: A,
        kind: "compose",
        name: "listmonk",
        action: "unexpose",
        args: { hostname: "listmonk-a.kleavox.xyz", zone: "kleavox.xyz" },
      }),
    ]);
    await t.beat(A);
    await t.finish(A, closeId!, "removed");
    expect(
      t.sqlite.prepare("SELECT hostname FROM web_addresses").all(),
    ).toEqual([]);
  });

  it("skips the rest when a step fails", async () => {
    const t = await hub();
    const [exportId, createId] = await t.operate("move", moveSteps());
    await t.beat(A);
    await t.finish(A, exportId!, "nope", false);
    await t.beat(B);
    expect(
      t.sqlite
        .prepare("SELECT status FROM actions WHERE id = ?")
        .get(createId!),
    ).toEqual({ status: "skipped" });
  });
});

describe("the inventory of agent 0.6.0", () => {
  it("keeps the seal key, the security report, the vault and stack access", async () => {
    const t = await hub();
    const security = {
      checkedAt: "2026-10-05T10:00:00.000Z",
      findings: [
        {
          id: "ssh-password",
          severity: "serious",
          detail: "SSH accepts passwords",
        },
      ],
      recipes: ["fail2ban"],
      lockdown: false,
      rebootHour: 3,
    };
    await t.send(A, "actions", {
      report: {
        nodeId: A,
        inventory: {
          hash: "f".repeat(64),
          services: [],
          sealKey: keyOf(B),
          security,
          vault: { set: SET, holders: 3 },
          stacks: [
            {
              project: "listmonk",
              directory: "/var/lib/kry-exec/compose/listmonk",
              running: 2,
              total: 2,
              compose: true,
              rollback: false,
              access: "full",
              public: ["53/udp"],
            },
          ],
        },
      },
    });
    const node = t.sqlite
      .prepare("SELECT seal_key, security, vault FROM nodes WHERE id = ?")
      .get(A) as Record<string, string>;
    expect(node.seal_key).toBe(keyOf(B));
    expect(JSON.parse(node.security!)).toEqual(security);
    expect(JSON.parse(node.vault!)).toEqual({ set: SET, holders: 3 });
    expect(
      t.sqlite
        .prepare("SELECT access, public FROM stacks WHERE node_id = ?")
        .get(A),
    ).toEqual({ access: "full", public: '["53/udp"]' });
    await t.send(A, "actions", {
      report: {
        nodeId: A,
        inventory: { hash: "e".repeat(64), services: [], vault: null },
      },
    });
    expect(
      t.sqlite.prepare("SELECT vault, seal_key FROM nodes WHERE id = ?").get(A),
    ).toEqual({ vault: null, seal_key: keyOf(B) });
  });

  it("shows the new parts with each server", async () => {
    const t = routes();
    t.sqlite
      .prepare(
        "INSERT INTO web_addresses (hostname, node_id, project, service, port, mode, path, created_by, created_at) VALUES ('listmonk-a.kleavox.xyz', ?, 'listmonk', 'app', 9000, 'allow', NULL, 'owner@example.test', datetime('now'))",
      )
      .run(A);
    t.sqlite.prepare("UPDATE nodes SET security = ? WHERE id = ?").run(
      JSON.stringify({
        checkedAt: "2026-10-05T10:00:00.000Z",
        findings: [],
        recipes: [],
        lockdown: false,
        rebootHour: null,
      }),
      A,
    );
    const body = (await (await t.call("GET", "/api/services")).json()) as {
      nodes: {
        id: string;
        sealKey: string;
        vault: unknown;
        security: unknown;
        webAddresses: unknown[];
        stacks: { project: string; access: string | null }[];
      }[];
    };
    const node = body.nodes.find((item) => item.id === A)!;
    expect(node.sealKey).toBe(keyOf(A));
    expect(node.vault).toEqual({ set: SET, holders: 3 });
    expect(node.security).toMatchObject({ lockdown: false });
    expect(node.webAddresses).toEqual([
      {
        hostname: "listmonk-a.kleavox.xyz",
        project: "listmonk",
        service: "app",
        port: 9000,
        mode: "allow",
        path: null,
      },
    ]);
    expect(
      node.stacks.find((stack) => stack.project === "listmonk")?.access,
    ).toBe("contained");
    const cloudflare = (await (
      await t.call("GET", "/api/cloudflare")
    ).json()) as { zone: string };
    expect(cloudflare.zone).toBe("kleavox.xyz");
  });

  it("hides sealed outputs and keeps a read compose for one day", async () => {
    const t = routes();
    const insert = t.sqlite.prepare(
      "INSERT INTO actions (id, batch_id, position, mode, node_id, kind, name, action, status, requested_by, requested_at, finished_at, output) VALUES (?, ?, 0, 'parallel', ?, ?, ?, ?, 'done', 'owner@example.test', datetime('now', '-3 days'), datetime('now', '-2 days'), ?)",
    );
    insert.run(
      crypto.randomUUID(),
      crypto.randomUUID(),
      A,
      "compose",
      "listmonk",
      "read",
      '{"compose":"x"}',
    );
    insert.run(
      crypto.randomUUID(),
      crypto.randomUUID(),
      A,
      "vault",
      "cloudflare",
      "release",
      "c2VhbGVk",
    );
    const body = (await (await t.call("GET", "/api/history")).json()) as {
      actions: { action: string; output: string | null }[];
    };
    expect(
      body.actions.find((row) => row.action === "release")?.output,
    ).toBeNull();
    await runRetention(t.env);
    expect(
      t.sqlite
        .prepare("SELECT output FROM actions WHERE action = 'read'")
        .get(),
    ).toEqual({ output: null });
  });
});

describe("the Cloudflare token", () => {
  it("is mailed about once, 30 days before it expires", async () => {
    const t = routes();
    const mail: { subject: string }[] = [];
    const env = {
      ...t.env,
      ALERT_EMAIL: "owner@example.test",
      FROM_EMAIL: "kry@example.test",
      EMAIL: {
        send: async (message: { subject: string }) => void mail.push(message),
      },
    } as unknown as Env;
    t.sqlite
      .prepare(
        "INSERT INTO cloudflare (owner_user_id, zone, set_id, updated_at) VALUES ('standalone', 'kleavox.xyz', ?, datetime('now'))",
      )
      .run(SET);
    const address = t.sqlite.prepare(
      "INSERT INTO web_addresses (hostname, node_id, project, service, port, mode, created_by, created_at, expires_at) VALUES ('listmonk-a.kleavox.xyz', ?, 'listmonk', 'app', 9000, 'allow', 'owner@example.test', datetime('now'), ?)",
    );
    const now = Date.parse("2026-10-05T10:00:00.000Z");
    address.run(A, "2026-12-01T00:00:00Z");
    await remindTokens(env, now);
    expect(mail).toEqual([]);
    t.sqlite
      .prepare("UPDATE web_addresses SET expires_at = '2026-10-25T00:00:00Z'")
      .run();
    await remindTokens(env, now);
    await remindTokens(env, now + 86_400_000);
    expect(mail.map((message) => message.subject)).toEqual([
      "[Krynodes] The Cloudflare token expires on 25 Oct 2026",
    ]);
  });
});
