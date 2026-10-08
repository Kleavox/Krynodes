import { describe, expect, it } from "vitest";

import { app } from "../app";
import type { Env } from "../env";
import { fromB64url, toB64url } from "../lib/b64url";
import { fingerprint } from "../lib/webauthn";
import {
  testPassphrase,
  testPasskey,
  type TestPasskey,
} from "../test/passkeys";
import { seedNode } from "../test/seed";
import { createTestDb } from "../test/sqlite-d1";

const A = "11111111-1111-4111-8111-111111111111";
const B = "22222222-2222-4222-8222-222222222222";
const C = "33333333-3333-4333-8333-333333333333";
const ORIGIN = "https://kry.example.test";
const RP = "kry.example.test";

interface Reply {
  id?: string;
  status?: string;
  missing?: string;
  code?: string;
  queued?: number;
  proposals?: {
    id: string;
    status: string;
    missing: string | null;
    approvals: string[];
    openedBy: string;
  }[];
  devices?: {
    id: string;
    core: boolean;
    fingerprint: string;
    verifies: boolean | null;
  }[];
  passphrase?: { salt: string; iterations: number; publicKey: string } | null;
}

const reply = async (response: Response | Promise<Response>) =>
  (await (await response).json()) as Reply;

const sha256 = async (bytes: Uint8Array<ArrayBuffer>) =>
  new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));

const encode = (value: unknown) =>
  toB64url(new TextEncoder().encode(JSON.stringify(value)));

function setup(agent = "0.6.0") {
  const { db, sqlite } = createTestDb();
  for (const id of [A, B, C]) {
    seedNode(sqlite, { id });
    sqlite
      .prepare(
        "UPDATE nodes SET agent_version = ?, last_seen_at = datetime('now') WHERE id = ?",
      )
      .run(agent, id);
  }
  const mail: { subject: string; text: string }[] = [];
  const pokes: string[][] = [];
  const env = {
    FLEET: {
      idFromName: (name: string) => ({ name }),
      get: () => ({
        fetch: async (input: string, init?: RequestInit) => {
          if (new URL(input).pathname === "/poke") {
            pokes.push(
              (JSON.parse(String(init?.body)) as { nodeIds: string[] }).nodeIds,
            );
          }
          return Response.json({});
        },
      }),
    },
    DB: db,
    PUBLIC_ORIGIN: ORIGIN,
    ALERT_EMAIL: "owner@example.test",
    FROM_EMAIL: "kry@example.test",
    EMAIL: {
      send: async (message: { subject: string; text: string }) => {
        mail.push(message);
      },
    },
  } as unknown as Env;
  const call = (method: string, path: string, body?: unknown) =>
    app.request(
      `${ORIGIN}${path}`,
      {
        method,
        headers: { "content-type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
      },
      env,
    );
  const touchOnly = (passkey: TestPasskey) =>
    sqlite
      .prepare(
        "INSERT INTO devices (id, owner_user_id, name, alg, public_key, created_at, verifies) VALUES (?, 'standalone', ?, -7, ?, ?, 0)",
      )
      .run(
        passkey.id,
        passkey.name,
        passkey.publicKey,
        new Date().toISOString(),
      );
  const register = (passkey: TestPasskey, verifies = true) =>
    call("POST", "/api/devices", {
      id: passkey.id,
      name: passkey.name,
      alg: passkey.alg,
      publicKey: passkey.publicKey,
      verifies,
    });
  const report = async (
    nodeId: string,
    core: TestPasskey[],
    access: TestPasskey[],
    version = 1,
    passphrase = false,
    requireUv = false,
  ) => {
    const prints = async (list: TestPasskey[]) =>
      Promise.all(list.map((key) => fingerprint(key.publicKey)));
    sqlite.prepare("UPDATE nodes SET trust_report = ? WHERE id = ?").run(
      JSON.stringify({
        version,
        core: await prints(core),
        access: await prints(access),
        passphrase,
        ...(requireUv ? { requireUv } : {}),
      }),
      nodeId,
    );
  };
  const change = (input: {
    version?: number;
    core?: TestPasskey[] | null;
    access: Record<string, TestPasskey[]>;
    passphrase?: unknown;
    requireUv?: true;
    origin?: string;
    hours?: number;
  }) => {
    const now = Date.now();
    return encode({
      v: 2,
      origin: input.origin ?? ORIGIN,
      rpId: new URL(input.origin ?? ORIGIN).hostname,
      version: input.version ?? 2,
      issuedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + (input.hours ?? 24) * 3_600_000).toISOString(),
      core:
        input.core === undefined || input.core === null
          ? null
          : input.core.map((key) => ({
              id: key.id,
              name: key.name,
              alg: key.alg,
              publicKey: key.publicKey,
            })),
      passphrase: input.passphrase ?? null,
      ...(input.requireUv ? { requireUv: true } : {}),
      access: Object.fromEntries(
        Object.entries(input.access).map(([nodeId, keys]) => [
          nodeId,
          keys.map((key) => key.id),
        ]),
      ),
    });
  };
  const approval = async (
    passkey: TestPasskey,
    text: string,
    options: { verified?: boolean; proof?: string } = {},
  ) => ({
    ...(await passkey.sign({
      challenge: await sha256(fromB64url(text)),
      origin: ORIGIN,
      rpId: RP,
      verified: options.verified ?? true,
    })),
    ...(options.proof ? { proof: options.proof } : {}),
  });
  const open = async (text: string, by: Awaited<ReturnType<typeof approval>>) =>
    call("POST", "/api/proposals", { change: text, approval: by });
  const trustActions = () =>
    sqlite
      .prepare(
        "SELECT node_id AS nodeId, signed FROM actions WHERE kind = 'trust' ORDER BY node_id",
      )
      .all() as { nodeId: string; signed: string }[];
  return {
    db,
    sqlite,
    env,
    mail,
    touchOnly,
    pokes,
    call,
    register,
    report,
    change,
    approval,
    open,
    trustActions,
  };
}

async function fleet(count: number) {
  const names = ["Laptop", "Phone", "Tablet", "Helper", "Spare"];
  return Promise.all(
    names
      .slice(0, count)
      .map((name) =>
        testPasskey(toB64url(new TextEncoder().encode(name)), name),
      ),
  );
}

describe("proposals", () => {
  it("lets the first device admit the second on its own and gives it access (founding)", async () => {
    const t = setup();
    const [laptop, phone] = await fleet(2);
    await t.register(laptop!);
    await t.register(phone!);
    await t.report(A, [laptop!], [laptop!]);
    await t.report(B, [laptop!], [laptop!]);
    const text = t.change({
      core: [laptop!, phone!],
      access: { [A]: [laptop!, phone!], [B]: [laptop!, phone!] },
    });
    const response = await t.open(text, await t.approval(laptop!, text));
    expect(response.status).toBe(201);
    expect(await reply(response)).toMatchObject({ status: "applied" });
    const actions = t.trustActions();
    expect(actions.map((action) => action.nodeId)).toEqual([A, B]);
    expect(
      (JSON.parse(actions[0]!.signed) as { approvals: unknown[] }).approvals,
    ).toHaveLength(1);
    expect(t.mail).toEqual([]);
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(t.pokes).toEqual([[A, B]]);
    await t.report(A, [laptop!, phone!], [laptop!, phone!], 2);
    const listed = (await (await t.call("GET", "/api/proposals")).json()) as {
      proposals: { status: string; title: string }[];
    };
    expect(listed.proposals).toMatchObject([
      { status: "applied", title: "Admit Phone" },
    ]);
  });

  it("names the device and the server an access change gives", async () => {
    const t = setup();
    const [laptop, phone] = await fleet(2);
    await t.register(laptop!);
    await t.register(phone!);
    await t.report(A, [laptop!, phone!], [laptop!]);
    const text = t.change({ access: { [A]: [laptop!, phone!] } });
    const response = await t.open(text, await t.approval(phone!, text));
    expect(await reply(response)).toMatchObject({
      status: "open",
      missing: "needs approval from another device that reaches this server",
    });
    const listed = (await (await t.call("GET", "/api/proposals")).json()) as {
      proposals: { status: string; title: string }[];
    };
    expect(listed.proposals).toMatchObject([
      { status: "open", title: `Give Phone access to ${A}` },
    ]);
  });

  it("keeps an open change in view after a busy month", async () => {
    const t = setup();
    const insert = t.sqlite.prepare(
      `INSERT INTO proposals (id, owner_user_id, change, title, version, approvals, status, opened_by, opened_at, expires_at, closed_at)
       VALUES (?, 'standalone', 'e30', 'Refresh servers', 2, '[]', ?, 'd1', ?, ?, ?)`,
    );
    for (let index = 0; index < 55; index += 1) {
      const at = new Date(
        Date.now() - (20 - index / 3) * 86_400_000,
      ).toISOString();
      insert.run(`closed-${index}`, "applied", at, at, at);
    }
    insert.run(
      "waiting",
      "open",
      new Date().toISOString(),
      new Date(Date.now() + 3_600_000).toISOString(),
      null,
    );
    const listed = (await (await t.call("GET", "/api/proposals")).json()) as {
      proposals: { id: string }[];
    };
    const ids = listed.proposals.map((proposal) => proposal.id);
    expect(ids).toContain("waiting");
    expect(ids).toContain("closed-54");
    expect(ids.at(-1)).toBe("waiting");
  });

  it("lists closed changes newest first with device names, twenty at a time", async () => {
    const t = setup();
    const [laptop, phone, tablet] = await fleet(3);
    await t.register(laptop!);
    await t.register(phone!);
    t.sqlite
      .prepare("UPDATE devices SET removed_at = ? WHERE id = ?")
      .run(new Date().toISOString(), phone!.id);
    const text = t.change({
      core: [laptop!, tablet!],
      access: { [A]: [laptop!, tablet!] },
    });
    const insert = t.sqlite.prepare(
      `INSERT INTO proposals (id, owner_user_id, change, title, version, approvals, status, opened_by, opened_at, expires_at, closed_at)
       VALUES (?, 'standalone', ?, ?, 2, ?, ?, ?, ?, ?, ?)`,
    );
    const approvals = JSON.stringify([
      { credentialId: phone!.id },
      { credentialId: tablet!.id },
    ]);
    for (let index = 0; index < 25; index += 1) {
      const at = new Date(Date.UTC(2026, 8, 1, 10, index)).toISOString();
      insert.run(
        `c-${String(index).padStart(2, "0")}`,
        text,
        `Change ${index}`,
        approvals,
        index % 2 === 0 ? "applied" : "expired",
        laptop!.id,
        at,
        at,
        at,
      );
    }
    insert.run(
      "open",
      text,
      "Waiting",
      "[]",
      "open",
      laptop!.id,
      new Date().toISOString(),
      new Date(Date.now() + 3_600_000).toISOString(),
      null,
    );
    const first = (await (
      await t.call("GET", "/api/proposals/history")
    ).json()) as {
      changes: {
        id: string;
        title: string;
        status: string;
        targets: string[];
        openedBy: string;
        approvedBy: string[];
      }[];
      next: string | null;
    };
    expect(first.changes).toHaveLength(20);
    expect(first.changes[0]).toMatchObject({
      id: "c-24",
      title: "Change 24",
      status: "applied",
      targets: [A],
      openedBy: "Laptop",
      approvedBy: ["Phone", "Tablet"],
    });
    expect(first.next).not.toBeNull();
    const second = (await (
      await t.call(
        "GET",
        `/api/proposals/history?before=${encodeURIComponent(first.next!)}`,
      )
    ).json()) as { changes: { id: string }[]; next: string | null };
    expect(second.changes.map((change) => change.id)).toEqual([
      "c-04",
      "c-03",
      "c-02",
      "c-01",
      "c-00",
    ]);
    expect(second.next).toBeNull();
  });

  it("with two devices, one approval admits a third at once", async () => {
    const t = setup();
    const [laptop, phone, tablet] = await fleet(3);
    for (const key of [laptop!, phone!, tablet!]) await t.register(key);
    await t.report(A, [laptop!, phone!], [laptop!, phone!]);
    const text = t.change({
      core: [laptop!, phone!, tablet!],
      access: { [A]: [laptop!, phone!] },
    });
    expect(
      await reply(t.open(text, await t.approval(phone!, text))),
    ).toMatchObject({ status: "applied" });
    expect(t.mail).toEqual([]);
  });

  it("with three devices, keeps a fourth waiting until a second device approves", async () => {
    const t = setup();
    const [laptop, phone, spare, tablet] = await fleet(5).then((keys) => [
      keys[0],
      keys[1],
      keys[4],
      keys[2],
    ]);
    for (const key of [laptop!, phone!, spare!, tablet!]) await t.register(key);
    await t.report(A, [laptop!, phone!, spare!], [laptop!, phone!]);
    const text = t.change({
      core: [laptop!, phone!, spare!, tablet!],
      access: { [A]: [laptop!, phone!] },
    });
    const opened = await reply(t.open(text, await t.approval(laptop!, text)));
    expect(opened).toMatchObject({
      status: "open",
      missing: "needs 1 more approval",
    });
    expect(t.trustActions()).toHaveLength(0);
    const again = await t.call(
      "POST",
      `/api/proposals/${opened.id}/approvals`,
      { approval: await t.approval(laptop!, text) },
    );
    expect(again.status).toBe(409);
    const done = await t.call("POST", `/api/proposals/${opened.id}/approvals`, {
      approval: await t.approval(phone!, text),
    });
    expect(await reply(done)).toMatchObject({ status: "applied" });
    expect(
      (JSON.parse(t.trustActions()[0]!.signed) as { approvals: unknown[] })
        .approvals,
    ).toHaveLength(2);
    expect(t.mail.map((message) => message.subject)).toEqual([
      "[Krynodes] Waiting for approval: Admit Tablet",
    ]);
  });

  it("sends nothing when the change is cancelled while its last approval arrives", async () => {
    const t = setup();
    const [laptop, phone, spare] = await fleet(5).then((keys) => [
      keys[0],
      keys[1],
      keys[4],
    ]);
    for (const key of [laptop!, phone!, spare!]) await t.register(key);
    await t.report(A, [laptop!, phone!, spare!], [laptop!]);
    const text = t.change({
      core: [laptop!, phone!],
      access: { [A]: [laptop!] },
    });
    const opened = await reply(t.open(text, await t.approval(phone!, text)));
    expect(opened).toMatchObject({ status: "open" });
    const batch = t.db.batch.bind(t.db);
    let cancelled = false;
    t.db.batch = (async (statements: D1PreparedStatement[]) => {
      if (!cancelled) {
        cancelled = true;
        t.sqlite
          .prepare("UPDATE proposals SET status = 'cancelled' WHERE id = ?")
          .run(String(opened.id));
      }
      return batch(statements);
    }) as typeof t.db.batch;
    const late = await t.call("POST", `/api/proposals/${opened.id}/approvals`, {
      approval: await t.approval(laptop!, text),
    });
    expect(late.status).toBe(410);
    expect(t.trustActions()).toHaveLength(0);
    expect(
      t.sqlite
        .prepare("SELECT status FROM proposals WHERE id = ?")
        .get(String(opened.id)),
    ).toEqual({ status: "cancelled" });
    expect(
      t.sqlite
        .prepare(
          "SELECT COUNT(*) AS n FROM devices WHERE removed_at IS NOT NULL",
        )
        .get(),
    ).toEqual({ n: 0 });
  });

  it("keeps both approvals that arrive together", async () => {
    const t = setup();
    const [laptop, phone, spare] = await fleet(5).then((keys) => [
      keys[0],
      keys[1],
      keys[4],
    ]);
    for (const key of [laptop!, phone!, spare!]) await t.register(key);
    await t.report(A, [laptop!, phone!, spare!], [laptop!]);
    const text = t.change({ access: { [A]: [laptop!, phone!] } });
    const opened = await reply(t.open(text, await t.approval(spare!, text)));
    expect(opened).toMatchObject({ status: "open" });
    const prepare = t.db.prepare.bind(t.db);
    let raced = false;
    t.db.prepare = ((sql: string) => {
      if (!raced && sql.startsWith("UPDATE proposals SET approvals")) {
        raced = true;
        const row = t.sqlite
          .prepare("SELECT approvals FROM proposals WHERE id = ?")
          .get(String(opened.id)) as { approvals: string };
        const approvals = JSON.parse(row.approvals) as unknown[];
        approvals.push({ credentialId: "someone-else" });
        t.sqlite
          .prepare("UPDATE proposals SET approvals = ? WHERE id = ?")
          .run(JSON.stringify(approvals), String(opened.id));
      }
      return prepare(sql);
    }) as typeof t.db.prepare;
    const second = await t.call(
      "POST",
      `/api/proposals/${opened.id}/approvals`,
      { approval: await t.approval(phone!, text) },
    );
    expect(raced).toBe(true);
    expect(second.status).toBe(409);
    const stored = t.sqlite
      .prepare("SELECT approvals FROM proposals WHERE id = ?")
      .get(String(opened.id)) as { approvals: string };
    expect(JSON.parse(stored.approvals)).toHaveLength(2);
  });

  it("refuses approvals from devices outside the core and forged ones", async () => {
    const t = setup();
    const [laptop, phone, tablet] = await fleet(3);
    for (const key of [laptop!, phone!, tablet!]) await t.register(key);
    await t.report(A, [laptop!, phone!], [laptop!, phone!]);
    const text = t.change({ access: { [A]: [laptop!, phone!, tablet!] } });
    const outsider = await t.open(text, await t.approval(tablet!, text));
    expect(outsider.status).toBe(403);
    const forged = {
      ...(await t.approval(laptop!, text)),
      credentialId: phone!.id,
    };
    expect((await t.open(text, forged)).status).toBe(400);
  });

  it("checks the origin, the version, the window and the agents", async () => {
    const t = setup();
    const [laptop] = await fleet(1);
    await t.register(laptop!);
    await t.report(A, [laptop!], [laptop!], 3);
    const wrongOrigin = t.change({
      origin: "https://evil.test",
      version: 4,
      access: { [A]: [laptop!] },
    });
    expect(
      (await t.open(wrongOrigin, await t.approval(laptop!, wrongOrigin)))
        .status,
    ).toBe(400);
    const stale = t.change({ version: 3, access: { [A]: [laptop!] } });
    const staleReply = await t.open(stale, await t.approval(laptop!, stale));
    expect(staleReply.status).toBe(409);
    expect((await reply(staleReply)).code).toBe("STALE_VERSION");
    const long = t.change({
      version: 4,
      hours: 25,
      access: { [A]: [laptop!] },
    });
    expect((await t.open(long, await t.approval(laptop!, long))).status).toBe(
      400,
    );
    t.sqlite
      .prepare("UPDATE nodes SET agent_version = '0.2.4' WHERE id = ?")
      .run(A);
    const old = t.change({ version: 4, access: { [A]: [laptop!] } });
    const oldReply = await t.open(old, await t.approval(laptop!, old));
    expect(oldReply.status).toBe(422);
    expect((await reply(oldReply)).code).toBe("NEEDS_AGENT");
  });

  it("lists, cancels, expires and supersedes proposals", async () => {
    const t = setup();
    const [laptop, phone, tablet, helper, spare] = await fleet(5);
    for (const key of [laptop!, phone!, tablet!, helper!, spare!])
      await t.register(key);
    await t.report(A, [laptop!, phone!, spare!], [laptop!, phone!]);
    const admitTablet = t.change({
      core: [laptop!, phone!, spare!, tablet!],
      access: { [A]: [laptop!, phone!] },
    });
    const first = await reply(
      t.open(admitTablet, await t.approval(laptop!, admitTablet)),
    );
    const admitHelper = t.change({
      core: [laptop!, phone!, spare!, helper!],
      access: { [A]: [laptop!, phone!] },
    });
    const second = await reply(
      t.open(admitHelper, await t.approval(laptop!, admitHelper)),
    );
    const listed = await reply(t.call("GET", "/api/proposals"));
    expect(listed.proposals!.map((proposal) => proposal.status)).toEqual([
      "open",
      "open",
    ]);
    expect(listed.proposals![0]!.approvals).toEqual([laptop!.id]);
    expect(listed.proposals![0]!.missing).toBe("needs 1 more approval");

    expect(
      (await t.call("POST", `/api/proposals/${second.id}/cancel`)).status,
    ).toBe(200);

    await t.call("POST", `/api/proposals/${first.id}/approvals`, {
      approval: await t.approval(phone!, admitTablet),
    });
    const extra = t.change({
      version: 3,
      core: [laptop!, phone!, spare!, helper!],
      access: { [A]: [laptop!, phone!] },
    });
    const late = await reply(t.open(extra, await t.approval(laptop!, extra)));
    t.sqlite
      .prepare("UPDATE proposals SET expires_at = ? WHERE id = ?")
      .run(new Date(Date.now() - 60_000).toISOString(), late.id!);
    const after = await reply(t.call("GET", "/api/proposals"));
    const status = Object.fromEntries(
      after.proposals!.map((proposal) => [proposal.id, proposal.status]),
    );
    expect(status).toEqual({
      [first.id!]: "applied",
      [second.id!]: "cancelled",
      [late.id!]: "expired",
    });
    expect(
      t.mail.filter((message) => !message.subject.includes("Waiting")),
    ).toEqual([]);
  });

  it("marks a device removed when a removal applies", async () => {
    const t = setup();
    const [laptop, phone, tablet] = await fleet(3);
    for (const key of [laptop!, phone!, tablet!]) await t.register(key);
    await t.report(A, [laptop!, phone!, tablet!], [laptop!, phone!, tablet!]);
    const text = t.change({
      core: [laptop!, phone!],
      access: { [A]: [laptop!, phone!] },
    });
    const opened = await reply(t.open(text, await t.approval(laptop!, text)));
    await t.call("POST", `/api/proposals/${opened.id}/approvals`, {
      approval: await t.approval(phone!, text),
    });
    const devices = await reply(t.call("GET", "/api/devices"));
    expect(devices.devices!.map((device) => device.id)).toEqual([
      laptop!.id,
      phone!.id,
    ]);
  });
});

describe("first trust", () => {
  it("lets the first device trust itself on a server that trusts nobody", async () => {
    const t = setup();
    const [laptop] = await fleet(1);
    await t.register(laptop!);
    const text = t.change({
      version: 1,
      requireUv: true,
      core: [laptop!],
      access: { [A]: [laptop!] },
    });
    const response = await t.call("POST", "/api/trust", { changes: [text] });
    expect(response.status).toBe(202);
    expect(
      JSON.parse(t.trustActions()[0]!.signed) as { approvals: unknown[] },
    ).toMatchObject({ approvals: [] });
  });

  it("gives a later server the core with no access, and nothing else", async () => {
    const t = setup();
    const [laptop, phone, tablet] = await fleet(3);
    for (const key of [laptop!, phone!, tablet!]) await t.register(key);
    await t.report(A, [laptop!, phone!], [laptop!, phone!]);
    const good = t.change({
      version: 1,
      requireUv: true,
      core: [laptop!, phone!],
      access: { [C]: [] },
    });
    expect(
      (await t.call("POST", "/api/trust", { changes: [good] })).status,
    ).toBe(202);
    const withAccess = t.change({
      version: 1,
      requireUv: true,
      core: [laptop!, phone!],
      access: { [B]: [laptop!] },
    });
    expect(
      (await t.call("POST", "/api/trust", { changes: [withAccess] })).status,
    ).toBe(400);
    const extraKey = t.change({
      version: 1,
      requireUv: true,
      core: [laptop!, phone!, tablet!],
      access: { [B]: [] },
    });
    expect(
      (await t.call("POST", "/api/trust", { changes: [extraKey] })).status,
    ).toBe(400);
    const trusted = t.change({
      version: 1,
      requireUv: true,
      core: [laptop!, phone!],
      access: { [A]: [] },
    });
    const exists = await t.call("POST", "/api/trust", { changes: [trusted] });
    expect(exists.status).toBe(409);
  });
});

describe("devices", () => {
  it("lists devices with their fingerprint, role and verification", async () => {
    const t = setup();
    const [laptop, phone] = await fleet(2);
    t.touchOnly(laptop!);
    await t.register(phone!);
    await t.report(A, [laptop!], [laptop!]);
    const body = await reply(t.call("GET", "/api/devices"));
    expect(body.devices).toEqual([
      expect.objectContaining({
        id: laptop!.id,
        core: true,
        verifies: false,
        fingerprint: await fingerprint(laptop!.publicKey),
      }),
      expect.objectContaining({ id: phone!.id, core: false, verifies: true }),
    ]);
  });

  it("forgets a device that never joined the core, never a core device", async () => {
    const t = setup();
    const [laptop, phone] = await fleet(2);
    await t.register(laptop!);
    await t.register(phone!);
    await t.report(A, [laptop!], [laptop!]);
    expect((await t.call("DELETE", `/api/devices/${laptop!.id}`)).status).toBe(
      409,
    );
    expect((await t.call("DELETE", `/api/devices/${phone!.id}`)).status).toBe(
      200,
    );
    const body = await reply(t.call("GET", "/api/devices"));
    expect(body.devices!.map((device) => device.id)).toEqual([laptop!.id]);
  });

  it("refuses the same passkey twice, even under another id", async () => {
    const t = setup();
    const [phone] = await fleet(1);
    expect((await t.register(phone!)).status).toBe(201);
    const again = await t.call("POST", "/api/devices", {
      id: "c2FtZS1waG9uZQ",
      name: "Phone again",
      alg: phone!.alg,
      publicKey: phone!.publicKey,
      verifies: true,
    });
    expect(again.status).toBe(409);
    expect(await reply(again)).toMatchObject({
      code: "DEVICE_EXISTS",
      message: `This passkey is already registered as ${phone!.name}.`,
    });
  });

  it("renames a device", async () => {
    const t = setup();
    const [laptop] = await fleet(1);
    await t.register(laptop!);
    const path = `/api/devices/${laptop!.id}`;
    expect((await t.call("PATCH", path, { name: " " })).status).toBe(400);
    expect((await t.call("PATCH", path, { name: "Work laptop" })).status).toBe(
      200,
    );
    expect(
      (await t.call("PATCH", "/api/devices/bm9uZQ", { name: "X" })).status,
    ).toBe(404);
    const body = (await (await t.call("GET", "/api/devices")).json()) as {
      devices: { name: string }[];
    };
    expect(body.devices.map((device) => device.name)).toEqual(["Work laptop"]);
  });
});

describe("fingerprint, always", () => {
  async function unruled() {
    const t = setup();
    const [laptop, phone] = await fleet(2);
    await t.register(laptop!);
    await t.register(phone!);
    for (const id of [A, B, C]) {
      await t.report(id, [laptop!, phone!], [laptop!, phone!]);
    }
    return { t, laptop: laptop!, phone: phone! };
  }

  it("refuses a touch approval even where no server asked for fingerprints", async () => {
    const { t, laptop, phone } = await unruled();
    const text = t.change({ access: { [A]: [laptop], [B]: [laptop, phone] } });
    const response = await t.open(
      text,
      await t.approval(phone, text, { verified: false }),
    );
    expect(response.status).toBe(400);
    expect((await reply(response)).code).toBe("FINGERPRINT_NEEDED");
  });

  it("refuses a change that carries a passphrase", async () => {
    const { t, laptop, phone } = await unruled();
    const text = t.change({
      access: {
        [A]: [laptop, phone],
        [B]: [laptop, phone],
        [C]: [laptop, phone],
      },
      passphrase: (await testPassphrase()).key,
    });
    const response = await t.open(text, await t.approval(phone, text));
    expect(response.status).toBe(400);
    expect((await reply(response)).code).toBe("NO_PASSPHRASE");
  });

  it("refuses to register a passkey that only takes a touch", async () => {
    const { t } = await unruled();
    const [, , tablet] = await fleet(3);
    const response = await t.register(tablet!, false);
    expect(response.status).toBe(422);
    expect((await reply(response)).code).toBe("CANNOT_VERIFY");
  });

  it("lists devices without a passphrase", async () => {
    const { t } = await unruled();
    const body = (await (await t.call("GET", "/api/devices")).json()) as Record<
      string,
      unknown
    >;
    expect("passphrase" in body).toBe(false);
  });
});

describe("fingerprint rule", () => {
  const everywhere = (keys: TestPasskey[]) => ({
    [A]: keys,
    [B]: keys,
    [C]: keys,
  });

  async function touchAndPhone(agent = "0.6.0", requireUv = false) {
    const t = setup(agent);
    const [laptop, phone] = await fleet(2);
    t.touchOnly(laptop!);
    await t.register(phone!);
    for (const id of [A, B, C]) {
      await t.report(
        id,
        [laptop!, phone!],
        [laptop!, phone!],
        1,
        false,
        requireUv,
      );
    }
    return { t, laptop: laptop!, phone: phone! };
  }

  it("needs agent 0.6.0 on every server to change the devices or the rule", async () => {
    const { t, phone } = await touchAndPhone("0.4.1");
    const text = t.change({
      core: [phone],
      requireUv: true,
      access: everywhere([phone]),
    });
    const response = await t.open(text, await t.approval(phone, text));
    expect(response.status).toBe(422);
    expect(await reply(response)).toMatchObject({
      code: "NEEDS_AGENT",
      message: expect.stringContaining("0.6.0"),
    });
  });

  it("does not change which servers a device reaches on older agents either", async () => {
    const { t, laptop, phone } = await touchAndPhone("0.4.1");
    const text = t.change({
      access: { [A]: [phone], [B]: [laptop, phone], [C]: [laptop, phone] },
    });
    const response = await t.open(text, await t.approval(phone, text));
    expect(response.status).toBe(422);
    expect((await reply(response)).code).toBe("NEEDS_AGENT");
  });

  it("refuses a passphrase once fingerprints are required", async () => {
    const { t, phone, laptop } = await touchAndPhone("0.6.0", true);
    const passphrase = await testPassphrase();
    const text = t.change({
      access: everywhere([laptop, phone]),
      passphrase: passphrase.key,
    });
    const response = await t.open(text, await t.approval(phone, text));
    expect(response.status).toBe(400);
    expect((await reply(response)).code).toBe("NO_PASSPHRASE");
  });

  it("refuses to admit or register a device without a fingerprint once required", async () => {
    const { t, phone } = await touchAndPhone("0.6.0", true);
    for (const id of [A, B, C])
      await t.report(id, [phone], [phone], 1, false, true);
    const [, , tablet, helper] = await fleet(4);
    t.sqlite
      .prepare(
        "INSERT INTO devices (id, owner_user_id, name, alg, public_key, created_at, verifies) VALUES (?, 'standalone', ?, -7, ?, ?, 0)",
      )
      .run(
        tablet!.id,
        tablet!.name,
        tablet!.publicKey,
        new Date().toISOString(),
      );
    const text = t.change({
      core: [phone, tablet!],
      access: everywhere([phone, tablet!]),
    });
    const admit = await t.open(text, await t.approval(phone, text));
    expect(admit.status).toBe(422);
    expect((await reply(admit)).code).toBe("CANNOT_VERIFY");
    const touchOnly = await t.register(helper!, false);
    expect(touchOnly.status).toBe(422);
    expect((await t.register(helper!, true)).status).toBe(201);
  });

  it("gives a new server the rule with its first trust", async () => {
    const { t, phone } = await touchAndPhone("0.6.0", true);
    for (const id of [A, B])
      await t.report(id, [phone], [phone], 1, false, true);
    t.sqlite
      .prepare("UPDATE nodes SET trust_report = NULL WHERE id = ?")
      .run(C);
    const plain = t.change({
      version: 1,
      core: [phone],
      access: { [C]: [phone] },
    });
    expect(
      (await t.call("POST", "/api/trust", { changes: [plain] })).status,
    ).toBe(400);
    const ruled = t.change({
      version: 1,
      core: [phone],
      requireUv: true,
      access: { [C]: [phone] },
    });
    expect(
      (await t.call("POST", "/api/trust", { changes: [ruled] })).status,
    ).toBe(202);
  });
});
