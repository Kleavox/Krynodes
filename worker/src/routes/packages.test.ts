import type { AgentActionsRequest } from "@krynodes/protocol";
import { describe, expect, it } from "vitest";

import { receiveReport } from "../actions/report";
import { sweepStatements } from "../actions/store";
import type { AgentNode } from "../agent/ingest";
import { app } from "../app";
import type { Env } from "../env";
import { seedNode } from "../test/seed";
import { createTestDb } from "../test/sqlite-d1";

const A = "11111111-1111-4111-8111-111111111111";
const OLD = "22222222-2222-4222-8222-222222222222";
const FEDORA = "33333333-3333-4333-8333-333333333333";
const FOREIGN = "44444444-4444-4444-8444-444444444444";
const NOW = Date.parse("2026-10-26T09:00:00.000Z");

const b64 = (value: unknown) =>
  Buffer.from(JSON.stringify(value)).toString("base64url");

const signedFor = (target: Record<string, string>) => ({
  grant: {
    grant: "Z3JhbnQ",
    credentialId: "ZGV2aWNlLTE",
    authenticatorData: Buffer.from(
      Uint8Array.from({ length: 37 }, (_, index) => (index === 32 ? 5 : 0)),
    ).toString("base64url"),
    clientDataJSON: "Y2xpZW50",
    signature: "c2ln",
  },
  command: b64({ v: 1, ...target }),
  signature: "c2lnbmF0dXJl",
});

type Packages = NonNullable<
  NonNullable<AgentActionsRequest["inventory"]>["packages"]
>;

const report = (over: Partial<Extract<Packages, { apt: true }>> = {}) =>
  ({
    apt: true,
    system: "Debian 12 bookworm",
    codename: "bookworm",
    readAt: "2026-10-26T08:58:00.000Z",
    checkedAt: "2026-10-26T06:00:00.000Z",
    installed: 3,
    packages: [
      {
        name: "nginx",
        version: "1.22.1-9",
        from: "debian",
        by: "root",
        feature: null,
        more: 1,
        held: false,
      },
      {
        name: "nodejs",
        version: "20.18.0",
        from: "nodesource",
        by: "root",
        feature: null,
        more: 0,
        held: true,
      },
      {
        name: "openssl",
        version: "3.0.14-1~deb12u2",
        from: "debian",
        by: null,
        feature: null,
        more: 0,
        held: false,
      },
    ],
    updates: [
      {
        name: "openssl",
        from: "3.0.14-1~deb12u2",
        to: "3.0.15-1~deb12u1",
        source: "debian-security",
        security: true,
        held: false,
        back: null,
      },
      {
        name: "nodejs",
        from: "20.18.0",
        to: "20.19.1",
        source: "nodesource",
        security: false,
        held: true,
        back: null,
      },
      {
        name: "nginx",
        from: "1.22.1-9",
        to: "1.22.1-10",
        source: "debian",
        security: false,
        held: false,
        back: null,
      },
    ],
    sources: [],
    security: { on: true, lastRan: null },
    restart: null,
    ...over,
  }) as Packages;

function setup() {
  const { db, sqlite } = createTestDb();
  for (const [id, version, owner] of [
    [A, "0.7.0", undefined],
    [OLD, "0.6.14", undefined],
    [FEDORA, "0.7.0", undefined],
    [FOREIGN, "0.7.0", "someone-else"],
  ] as const) {
    seedNode(sqlite, { id, owner });
    sqlite
      .prepare(
        "UPDATE nodes SET agent_version = ?, last_seen_at = datetime('now') WHERE id = ?",
      )
      .run(version, id);
  }
  const names = new Map(
    (
      sqlite.prepare("SELECT id, name FROM nodes").all() as {
        id: string;
        name: string;
      }[]
    ).map((row) => [row.id, row.name]),
  );
  const env = {
    DB: db,
    PUBLIC_ORIGIN: "https://kry.example.test",
  } as unknown as Env;
  const call = (method: string, path: string, body?: unknown) =>
    app.request(
      `https://kry.example.test${path}`,
      {
        method,
        headers: { "content-type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
      },
      env,
    );
  const change = (
    nodeId: string,
    kind: string,
    name: string,
    action: string,
  ) => {
    const target = { id: crypto.randomUUID(), nodeId, kind, name };
    return call("POST", "/api/actions", {
      action,
      targets: [{ ...target, signed: signedFor({ ...target, action }) }],
    });
  };
  const ask = (
    nodeId: string,
    name: string,
    action: string,
    args?: Record<string, string>,
  ) =>
    call("POST", "/api/actions", {
      action,
      targets: [{ nodeId, kind: "apt", name, ...(args ? { args } : {}) }],
    });
  const agent = (id: string) =>
    ({
      id,
      inventory_hash: null,
      refresh_requested_at: null,
      security: null,
    }) as unknown as AgentNode;
  const inventory = (
    id: string,
    extra: Partial<NonNullable<AgentActionsRequest["inventory"]>>,
    hash = "a",
  ) =>
    receiveReport(
      db,
      agent(id),
      {
        nodeId: id,
        inventory: { hash: hash.repeat(64), services: [], ...extra },
      },
      NOW,
    );
  return { db, sqlite, call, change, ask, inventory, agent, names };
}

const json = async (response: Response | Promise<Response>) =>
  (await (await response).json()) as Record<string, unknown>;

describe("apt actions", () => {
  it("are refused below 0.7.0, where apt is missing, and for removing openssh-server", async () => {
    const { change, inventory, names } = setup();
    const old = await change(OLD, "apt", "nginx", "install");
    expect(old.status).toBe(422);
    expect(await json(old)).toEqual({
      code: "AGENT_TOO_OLD",
      message: `Update the agent on ${names.get(OLD)} to 0.7.0 or newer.`,
    });
    expect((await change(OLD, "host", "tailscale", "signin")).status).toBe(422);
    await inventory(FEDORA, {
      packages: { apt: false, system: "Fedora Linux 41" },
    });
    const fedora = await change(FEDORA, "apt", "nginx", "install");
    expect(fedora.status).toBe(422);
    expect((await json(fedora)).code).toBe("NO_APT");
    for (const verb of ["remove", "purge"]) {
      const ssh = await change(A, "apt", "openssh-server", verb);
      expect(ssh.status).toBe(422);
      expect((await json(ssh)).code).toBe("PROTECTED_TARGET");
    }
    expect((await change(A, "apt", "nginx", "install")).status).toBe(201);
  });

  it("carry an unsigned question's words as its attachment, and only a question's", async () => {
    const { ask, change, sqlite } = setup();
    const found = await ask(A, "system", "find", { term: "nginx" });
    expect(found.status).toBe(201);
    const row = sqlite
      .prepare("SELECT attachment, signed FROM actions WHERE action = 'find'")
      .get() as {
      attachment: string;
      signed: string | null;
    };
    expect(
      JSON.parse(Buffer.from(row.attachment, "base64url").toString()),
    ).toEqual({ term: "nginx" });
    expect(row.signed).toBeNull();
    expect(
      (await ask(A, "system", "find", { term: "x".repeat(4100) })).status,
    ).toBe(400);
    expect((await ask(A, "nginx", "install")).status).toBe(400);
    expect((await ask(A, "nginx", "preview", { what: "install" })).status).toBe(
      201,
    );
    expect((await ask(A, "nginx", "preview", { what: "install" })).status).toBe(
      201,
    );
    expect((await ask(A, "system", "refresh")).status).toBe(201);
    expect((await change(A, "apt", "nginx", "install")).status).toBe(201);
    expect((await change(A, "apt", "nginx", "remove")).status).toBe(409);
  });

  it("sign in only where tailscale is installed", async () => {
    const { change, inventory } = setup();
    expect((await change(A, "host", "tailscale", "signin")).status).toBe(422);
    await inventory(A, {
      tailscale: {
        state: "needs-login",
        addresses: [],
        name: null,
        keyExpiry: null,
      },
    });
    expect((await change(A, "host", "tailscale", "signin")).status).toBe(201);
  });
});

describe("the packages report", () => {
  it("is kept once per change with a summary on the server", async () => {
    const { inventory, sqlite, call } = setup();
    await inventory(A, { packages: report() });
    const node = sqlite
      .prepare("SELECT updates FROM nodes WHERE id = ?")
      .get(A) as { updates: string };
    expect(JSON.parse(node.updates)).toEqual({
      waiting: 3,
      security: 1,
      held: 1,
      checkedAt: "2026-10-26T06:00:00.000Z",
      restart: null,
    });
    const before = (
      sqlite.prepare("SELECT total_changes() AS n").get() as { n: number }
    ).n;
    await inventory(A, { packages: report() }, "b");
    const writes =
      (sqlite.prepare("SELECT total_changes() AS n").get() as { n: number }).n -
      before;
    expect(writes).toBe(1);
    await inventory(A, {}, "c");
    expect(sqlite.prepare("SELECT COUNT(*) AS n FROM packages").get()).toEqual({
      n: 1,
    });
    const body = await json(call("GET", `/api/nodes/${A}/packages`));
    expect(body.report).toEqual(report());
    expect(typeof body.readAt).toBe("string");
    expect((await call("GET", `/api/nodes/${FOREIGN}/packages`)).status).toBe(
      404,
    );
  });

  it("lists package names only for the owner's servers", async () => {
    const { inventory, call } = setup();
    await inventory(A, { packages: report() });
    await inventory(FOREIGN, { packages: report() });
    expect(await json(call("GET", "/api/packages"))).toEqual({
      servers: [{ nodeId: A, names: ["nginx", "nodejs", "openssl"] }],
    });
  });

  it("keeps Tailscale until a full inventory says it is gone", async () => {
    const { db, inventory, sqlite, agent } = setup();
    const running = {
      state: "running" as const,
      addresses: ["100.101.7.12"],
      name: "vps-2.tail0000.ts.net",
      keyExpiry: null,
    };
    await inventory(A, { tailscale: running });
    await receiveReport(
      db,
      agent(A),
      { nodeId: A, inventory: { hash: "b".repeat(64) } },
      NOW,
    );
    expect(
      JSON.parse(
        (
          sqlite.prepare("SELECT tailscale FROM nodes WHERE id = ?").get(A) as {
            tailscale: string;
          }
        ).tailscale,
      ),
    ).toEqual(running);
    await inventory(A, {}, "c");
    expect(
      sqlite.prepare("SELECT tailscale FROM nodes WHERE id = ?").get(A),
    ).toEqual({ tailscale: null });
  });
});

describe("a running job's progress", () => {
  it("is kept on the action and written only when it moves", async () => {
    const { db, sqlite, change, agent, call } = setup();
    const created = await json(change(A, "apt", "system", "upgrade"));
    const id = (created.actions as { id: string }[])[0]!.id;
    sqlite
      .prepare("UPDATE actions SET status = 'sent', sent_at = ? WHERE id = ?")
      .run(new Date(NOW - 70 * 60_000).toISOString(), id);
    const step = {
      id,
      at: new Date(NOW - 60_000).toISOString(),
      done: 6,
      total: 14,
      line: "unpacking docker-ce",
    };
    await receiveReport(db, agent(A), { nodeId: A, progress: [step] }, NOW);
    const before = (
      sqlite.prepare("SELECT total_changes() AS n").get() as { n: number }
    ).n;
    await receiveReport(db, agent(A), { nodeId: A, progress: [step] }, NOW);
    expect(
      (sqlite.prepare("SELECT total_changes() AS n").get() as { n: number }).n,
    ).toBe(before);
    await db.batch(sweepStatements(db, NOW));
    const action = (await json(call("GET", `/api/actions/${id}`)))
      .action as Record<string, unknown>;
    expect(action.status).toBe("sent");
    expect(action.progress).toEqual({
      at: step.at,
      done: 6,
      total: 14,
      line: "unpacking docker-ce",
    });
  });
});

describe("History", () => {
  it("leaves out searches and dry runs but keeps Check for Updates", async () => {
    const { ask, call } = setup();
    await ask(A, "system", "find", { term: "nginx" });
    await ask(A, "nginx", "preview", { what: "install" });
    await ask(A, "system", "refresh");
    const body = await json(call("GET", "/api/history"));
    const verbs = (body.entries as { action: { action: string } }[]).map(
      (entry) => entry.action.action,
    );
    expect(verbs).toEqual(["refresh"]);
  });
});
