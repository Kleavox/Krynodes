import { codeOf, releaseText } from "@krynodes/protocol";
import { describe, expect, it, vi } from "vitest";

import { actionResultStatements } from "../actions/store";
import { app } from "../app";
import type { Env } from "../env";
import { sha256 } from "../lib/crypto";
import { fingerprint } from "../lib/webauthn";
import { IO, keyOf, queued, seedFleet, V1, V2, V3 } from "../test/fleet";
import { testPasskey } from "../test/passkeys";
import { seedCheck } from "../test/seed";
import { createTestDb } from "../test/sqlite-d1";
import { quarantine } from "./quarantine";

const ORIGIN = "https://kry.example.test";
const EMAIL = "standalone@localhost";
const DEVICE = "ZGV2aWNlLTE";
const TAILNET = "100.101.7.10 fd7a:115c:a1e0::7";

const b64 = (value: unknown) =>
  Buffer.from(JSON.stringify(value)).toString("base64url");

const grant = {
  grant: "Z3JhbnQ",
  credentialId: DEVICE,
  authenticatorData: Buffer.from(
    Uint8Array.from({ length: 37 }, (_, index) => (index === 32 ? 5 : 0)),
  ).toString("base64url"),
  clientDataJSON: "Y2xpZW50",
  signature: "c2ln",
};

function step(
  nodeId: string,
  kind: string,
  name: string,
  action: string,
  args?: Record<string, string>,
) {
  const id = crypto.randomUUID();
  return {
    id,
    nodeId,
    kind,
    name,
    action,
    signed: {
      grant,
      command: b64({ v: 1, id, nodeId, kind, name, action, args }),
      signature: "c2lnbmF0dXJl",
    },
  };
}

const sshKey = {
  user: "root",
  item: "root:/root/.ssh/authorized_keys:SHA256:x",
};

const pending = (expires: number) => ({
  key: keyOf(9),
  signer: keyOf(19),
  seal: "c2VhbA",
  token: "a".repeat(64),
  expires: new Date(expires).toISOString(),
});

const codeFor = async (release: ReturnType<typeof pending>) =>
  codeOf(
    new Uint8Array(
      await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(releaseText(release)),
      ),
    ),
  );

function setup() {
  const { db, sqlite } = createTestDb();
  seedFleet(sqlite);
  const mail = vi.fn(async () => ({ messageId: "m" }));
  const env = {
    DB: db,
    PUBLIC_ORIGIN: ORIGIN,
    EMAIL: { send: mail },
    ALERT_EMAIL: "owner@example.test",
    FROM_EMAIL: "kry@example.test",
  } as unknown as Env;
  const call = (
    method: string,
    path: string,
    body?: unknown,
    headers: Record<string, string> = {},
  ) =>
    app.request(
      `${ORIGIN}${path}`,
      {
        method,
        headers: { "content-type": "application/json", ...headers },
        body: body === undefined ? undefined : JSON.stringify(body),
      },
      env,
    );
  const warn = (kind: string, detail: Record<string, string>, id = "w1") =>
    sqlite
      .prepare(
        "INSERT INTO warnings (node_id, id, kind, detail, at, cut_at) VALUES (?, ?, ?, ?, ?, ?)",
      )
      .run(
        V1,
        id,
        kind,
        JSON.stringify(detail),
        new Date().toISOString(),
        new Date(Date.now() + 15 * 60_000).toISOString(),
      );
  const answer = (id = "w1") =>
    sqlite
      .prepare(
        "SELECT answer, answered_by AS answeredBy FROM warnings WHERE id = ?",
      )
      .get(id);
  const changes = () =>
    sqlite
      .prepare(
        "SELECT change, requested_by AS requestedBy, device_id AS deviceId FROM network_changes ORDER BY rowid",
      )
      .all();
  const core = async () => {
    const phone = await testPasskey("phone");
    await call("POST", "/api/devices", {
      id: phone.id,
      name: phone.name,
      alg: phone.alg,
      publicKey: phone.publicKey,
      verifies: true,
    });
    const print = await fingerprint(phone.publicKey);
    sqlite.prepare("UPDATE nodes SET trust_report = ?").run(
      JSON.stringify({
        version: 1,
        core: [print],
        access: [print],
        passphrase: false,
        requireUv: false,
      }),
    );
  };
  return { db, sqlite, call, warn, answer, changes, core, mail };
}

const json = async (response: Response) =>
  (await response.json()) as Record<string, unknown>;

describe("a warning's answers", () => {
  it("Cut Off Now quarantines at once without a fingerprint", async () => {
    const { sqlite, call, warn, answer, changes, mail } = setup();
    warn("ssh-key", sshKey);
    const cut = await call("POST", `/api/nodes/${V1}/warnings/w1/cut`);
    expect(cut.status).toBe(200);
    expect(mail).not.toHaveBeenCalled();
    expect(answer()).toEqual({ answer: "cut", answeredBy: EMAIL });
    expect(
      sqlite.prepare("SELECT node_id AS node, why FROM quarantines").all(),
    ).toEqual([
      { node: V1, why: "You cut it off after a new SSH key for root" },
    ]);
    expect(changes()).toEqual([
      { change: "Cut off vps-1", requestedBy: EMAIL, deviceId: null },
    ]);
    const again = await call("POST", `/api/nodes/${V1}/warnings/w1/cut`);
    expect(again.status).toBe(409);
    expect(await json(again)).toMatchObject({ code: "ANSWERED" });
  });

  it("It Was Me queues the signed accept of that one item and answers the warning", async () => {
    const { sqlite, call, warn, answer, changes, mail } = setup();
    warn("ssh-key", sshKey);
    const other = step(V1, "host", "server", "accept", {
      kind: "ssh-key",
      item: "root:/root/.ssh/authorized_keys:SHA256:other",
    });
    expect(
      (
        await call("POST", `/api/nodes/${V1}/warnings/w1/me`, {
          target: other,
        })
      ).status,
    ).toBe(400);
    const me = await call("POST", `/api/nodes/${V1}/warnings/w1/me`, {
      target: step(V1, "host", "server", "accept", {
        kind: "ssh-key",
        item: sshKey.item,
      }),
    });
    expect(me.status).toBe(201);
    expect(mail).not.toHaveBeenCalled();
    expect(answer()).toEqual({ answer: "me", answeredBy: EMAIL });
    expect(
      queued(sqlite).map((row) => [row.nodeId, row.action, row.status]),
    ).toEqual([[V1, "accept", "queued"]]);
    expect(changes()).toEqual([
      {
        change: "It was me: the new key on vps-1",
        requestedBy: EMAIL,
        deviceId: DEVICE,
      },
    ]);
  });

  it("It Was Me on a warning the agent cannot accept asks only for the confirmation", async () => {
    const { sqlite, call, warn, answer, core } = setup();
    warn("rule", {});
    await core();
    const bare = await call("POST", `/api/nodes/${V1}/warnings/w1/me`, {});
    expect(bare.status).toBe(403);
    expect(await json(bare)).toMatchObject({
      code: "PROOF_NEEDED",
      op: "warning.me",
      target: `${V1}/w1`,
    });
    expect(answer()).toEqual({ answer: null, answeredBy: null });
    sqlite.exec("UPDATE nodes SET trust_report = NULL");
    expect(
      (await call("POST", `/api/nodes/${V1}/warnings/w1/me`, {})).status,
    ).toBe(200);
    expect(answer()).toEqual({ answer: "me", answeredBy: EMAIL });
  });
});

describe("a quarantined server", () => {
  it("refuses every action there except reading", async () => {
    const { db, call } = setup();
    await quarantine(db, { nodeId: V1, why: "why", now: Date.now() });
    const target = step(V1, "systemd", "nginx.service", "restart");
    const refused = await call("POST", "/api/actions", {
      action: "restart",
      targets: [target],
    });
    expect(refused.status).toBe(409);
    expect(await json(refused)).toEqual({
      code: "QUARANTINED",
      message: "vps-1 is quarantined. Only reading works there.",
    });
    const reading = await call("POST", "/api/actions", {
      action: "logs",
      targets: [step(V1, "systemd", "nginx.service", "logs")],
    });
    expect(await json(reading)).toMatchObject({ code: "UNKNOWN_TARGET" });
  });

  it("lets a fingerprinted unblock reach the other servers, for a quarantined server being deleted", async () => {
    const { db, sqlite, call } = setup();
    await quarantine(db, { nodeId: V1, why: "why", now: Date.now() });
    sqlite.exec(
      `UPDATE actions SET status = 'done' WHERE action = 'block' AND node_id = '${V2}'`,
    );
    const lifted = await call("POST", "/api/actions", {
      action: "unblock",
      mode: "parallel",
      targets: [
        step(V2, "host", "tailscale", "unblock", { addresses: TAILNET }),
        step(V3, "host", "tailscale", "unblock", { addresses: TAILNET }),
      ],
    });
    expect(await json(lifted)).toMatchObject({ batchId: expect.any(String) });
    expect(lifted.status).toBe(201);
    expect(
      queued(sqlite)
        .filter((row) => row.action === "unblock")
        .map((row) => row.nodeId),
    ).toEqual([V2, V3]);
  });

  it("reads as quarantined in the overview, with open warnings and Not Trusted checks", async () => {
    const { db, sqlite, call, warn } = setup();
    seedCheck(sqlite, {
      id: "c1111111-1111-4111-8111-111111111111",
      nodeId: V1,
    });
    seedCheck(sqlite, {
      id: "c2222222-2222-4222-8222-222222222222",
      nodeId: V2,
    });
    warn("ssh-key", sshKey);
    warn("wrong-port", { from: "10.88.0.2", target: "x" }, "w2");
    await quarantine(db, { nodeId: V1, why: "why", now: Date.now() });
    const overview = (await json(await call("GET", "/api/overview"))) as {
      nodes: { id: string; quarantine: unknown; warnings: unknown[] }[];
      checks: { node_id: string; status: string }[];
    };
    const node = (id: string) =>
      overview.nodes.find((entry) => entry.id === id)!;
    expect(node(V1).quarantine).toMatchObject({
      why: "why",
      tailnet: TAILNET.split(" "),
    });
    expect(node(V1).warnings).toEqual([
      expect.objectContaining({ id: "w1", kind: "ssh-key", detail: sshKey }),
    ]);
    expect(node(V2)).toMatchObject({ quarantine: null, warnings: [] });
    const status = (id: string) =>
      overview.checks.find((check) => check.node_id === id)!.status;
    expect(status(V1)).toBe("UNTRUSTED");
    expect(status(V2)).not.toBe("UNTRUSTED");
  });

  it("shows why, the blocks it caused and what to change", async () => {
    const { db, sqlite, call } = setup();
    sqlite.exec(
      `INSERT INTO stacks (node_id, project, directory, running, total, compose, rollback, updated_at)
       VALUES ('${V1}', 'app', '/srv/app', 1, 1, 1, 0, 'now'),
              ('${V2}', 'db', '/srv/db', 1, 1, 1, 0, 'now')`,
    );
    sqlite.prepare("UPDATE stacks SET network = ? WHERE project = 'db'").run(
      JSON.stringify({
        serves: [{ port: "5432/tcp", to: [V1] }],
        reaches: [],
        private: [],
      }),
    );
    sqlite.exec(
      `INSERT INTO web_addresses (hostname, node_id, project, service, port, mode, created_by, created_at)
       VALUES ('app.example.com', '${V1}', 'app', 'web', 80, 'everyone', 'owner', 'now')`,
    );
    await quarantine(db, { nodeId: V1, why: "why", now: Date.now() });
    const read = await json(await call("GET", `/api/nodes/${V1}/quarantine`));
    expect(read.quarantine).toMatchObject({
      why: "why",
      releasedAt: null,
      tailnet: ["100.101.7.10", "fd7a:115c:a1e0::7"],
    });
    expect(
      (
        read.quarantine as { steps: { nodeName: string; action: string }[] }
      ).steps.map((entry) => `${entry.action} ${entry.nodeName}`),
    ).toEqual([
      "lockdown vps-1",
      "drop vps-2",
      "drop vps-3",
      "block vps-2",
      "block vps-3",
      "block io",
    ]);
    expect(read.changeThese).toEqual({
      stacks: ["app"],
      vault: null,
      tailscaleVault: null,
      webAddresses: [{ hostname: "app.example.com", project: "app" }],
      trusted: [
        { nodeId: V2, nodeName: "vps-2", project: "db", port: "5432/tcp" },
      ],
    });
    expect(
      (await json(await call("GET", `/api/nodes/${V3}/quarantine`))).quarantine,
    ).toBeNull();
  });

  it("names the Tailscale credential's pieces and when it left the tailnet", async () => {
    const { db, sqlite, call } = setup();
    sqlite
      .prepare("UPDATE nodes SET tailscale_vault = ? WHERE id = ?")
      .run(JSON.stringify({ set: "t1", holders: 3 }), V1);
    await quarantine(db, { nodeId: V1, why: "why", now: Date.now() });
    sqlite
      .prepare(
        `UPDATE quarantines SET timeline = json_set(timeline, '$.removed', json(?)) WHERE node_id = ?`,
      )
      .run(JSON.stringify({ at: "2026-10-27T14:40:12Z", by: "dev-1" }), V1);
    const read = await json(await call("GET", `/api/nodes/${V1}/quarantine`));
    expect(read.quarantine).toMatchObject({
      removed: { at: "2026-10-27T14:40:12Z", by: "dev-1" },
    });
    expect(read.changeThese).toMatchObject({
      tailscaleVault: { set: "t1", holders: 3 },
    });
  });

  it("names the knocks that led to it, the address they came from and a stopped stack's count", async () => {
    const { db, sqlite, call } = setup();
    const now = Date.now();
    const at = (ms: number) => new Date(ms).toISOString();
    sqlite
      .prepare(
        "INSERT INTO knocks (suspect, reporter, at, count) VALUES (?, ?, ?, ?), (?, ?, ?, ?)",
      )
      .run(V1, V2, at(now - 20_000), 23, V1, V3, at(now - 30 * 60_000), 18);
    sqlite
      .prepare(
        "INSERT INTO stopped_stacks (node_id, project, at, tried, count) VALUES (?, 'app', ?, ?, 14)",
      )
      .run(V1, at(now), JSON.stringify(["10.88.0.2:22/tcp"]));
    await quarantine(db, { nodeId: V1, why: "why", now });
    const read = await json(await call("GET", `/api/nodes/${V1}/quarantine`));
    expect(read.quarantine).toMatchObject({
      address: "10.88.0.1",
      knocks: [{ reporter: "vps-2", at: at(now - 20_000), count: 23 }],
    });
    expect(read.stopped).toEqual([
      { project: "app", at: at(now), tried: ["10.88.0.2:22/tcp"], count: 14 },
    ]);
  });

  it("forgets a stopped stack once its signed start ran", async () => {
    const { db, sqlite } = setup();
    sqlite.exec(
      `INSERT INTO stopped_stacks (node_id, project, at, tried) VALUES ('${V1}', 'app', 'now', '[]');
       INSERT INTO actions (id, batch_id, position, mode, node_id, kind, name, action, status,
         requested_by, requested_at, deliverable_at, sent_at)
       VALUES ('s1', 's1', 0, 'parallel', '${V1}', 'compose', 'app', 'start', 'sent', 'owner', 'now', 'now', 'now')`,
    );
    await db.batch(
      await actionResultStatements(
        db,
        V1,
        [
          {
            id: "s1",
            ok: true,
            exitCode: 0,
            output: "",
            finishedAt: new Date().toISOString(),
          },
        ],
        Date.now(),
      ),
    );
    expect(sqlite.prepare("SELECT * FROM stopped_stacks").all()).toEqual([]);
  });

  it("forgets a quarantined server's web addresses once a reshare cleaned them out of Cloudflare", async () => {
    const { db, sqlite } = setup();
    const reshare = step(V2, "vault", "cloudflare", "reshare", {
      holders: "x",
      set: "s2",
      source: "s1",
      cleanup: V1,
      zone: "kleavox.xyz",
    });
    sqlite.exec(
      `INSERT INTO web_addresses (hostname, node_id, project, service, port, mode, created_by, created_at)
       VALUES ('app.kleavox.xyz', '${V1}', 'app', 'web', 80, 'everyone', 'owner', 'now'),
              ('db.kleavox.xyz', '${V2}', 'db', 'web', 80, 'everyone', 'owner', 'now')`,
    );
    sqlite
      .prepare(
        `INSERT INTO actions (id, batch_id, position, mode, node_id, kind, name, action, status,
           requested_by, requested_at, deliverable_at, sent_at, signed)
         VALUES ('r1', 'r1', 0, 'rolling', ?, 'vault', 'cloudflare', 'reshare', 'sent', 'owner', 'now', 'now', 'now', ?)`,
      )
      .run(V2, JSON.stringify(reshare.signed));
    await db.batch(
      await actionResultStatements(
        db,
        V2,
        [
          {
            id: "r1",
            ok: true,
            exitCode: 0,
            output: "{}",
            finishedAt: new Date().toISOString(),
          },
        ],
        Date.now(),
      ),
    );
    expect(sqlite.prepare("SELECT hostname FROM web_addresses").all()).toEqual([
      { hostname: "db.kleavox.xyz" },
    ]);
  });
});

describe("Release", () => {
  async function released() {
    const t = setup();
    await quarantine(t.db, { nodeId: V1, why: "why", now: Date.now() });
    const release = pending(Date.now() + 10 * 60_000);
    t.sqlite
      .prepare("UPDATE nodes SET release = ? WHERE id = ?")
      .run(JSON.stringify(release), V1);
    const code = await codeFor(release);
    const steps = (typed = code) => [
      step(V1, "host", "server", "release", {
        key: release.key,
        signer: release.signer,
        seal: release.seal,
        token: release.token,
        code: typed,
      }),
      step(V1, "host", "server", "unlock"),
      ...[V2, V3, IO].map((nodeId) =>
        step(nodeId, "host", "tailscale", "unblock", { addresses: TAILNET }),
      ),
    ];
    const post = (body: unknown) =>
      t.call("POST", `/api/nodes/${V1}/release`, body);
    return { ...t, release, code, steps, post };
  }

  it("refuses a wrong code, an ended one and a batch that leaves a block", async () => {
    const { sqlite, steps, post, code } = await released();
    const wrong = await post({
      code: "AAAAA-AAAAA",
      steps: steps("AAAAA-AAAAA"),
    });
    expect(wrong.status).toBe(422);
    expect(await json(wrong)).toEqual({
      code: "RELEASE_CODE",
      message: "That is not the code vps-1 showed. Type it again.",
    });
    expect((await post({ code, steps: steps().slice(0, -1) })).status).toBe(
      400,
    );
    const ended = pending(Date.now() - 1000);
    sqlite
      .prepare("UPDATE nodes SET release = ? WHERE id = ?")
      .run(JSON.stringify(ended), V1);
    const old = await post({ code: await codeFor(ended), steps: steps() });
    expect(old.status).toBe(422);
    expect(await json(old)).toEqual({
      code: "RELEASE_CODE",
      message: "That code has ended. Run sudo kry release-code on vps-1 again.",
    });
    expect(sqlite.prepare("SELECT released_at FROM quarantines").get()).toEqual(
      { released_at: null },
    );
  });

  it("releases with one fingerprinted batch and keeps the old key blocked", async () => {
    const { sqlite, steps, post, code, changes, mail } = await released();
    sqlite.exec("DELETE FROM network_changes");
    const before = queued(sqlite).length;
    const done = await post({ code, steps: steps() });
    expect(done.status).toBe(201);
    expect(mail).not.toHaveBeenCalled();
    expect(
      sqlite
        .prepare(
          "SELECT released_at IS NOT NULL AS released, released_by AS device FROM quarantines",
        )
        .get(),
    ).toEqual({ released: 1, device: DEVICE });
    expect(
      queued(sqlite)
        .slice(before)
        .map(
          (row) => `${row.action} ${row.nodeId === V1 ? "vps-1" : row.name}`,
        ),
    ).toEqual([
      "release vps-1",
      "unlock vps-1",
      "unblock tailscale",
      "unblock tailscale",
      "unblock tailscale",
    ]);
    expect(sqlite.prepare("SELECT key FROM network_blocked").all()).toEqual([
      { key: keyOf(1) },
    ]);
    expect(changes()).toEqual([
      { change: "Release vps-1", requestedBy: EMAIL, deviceId: DEVICE },
    ]);
    expect((await post({ code, steps: steps() })).status).toBe(409);
  });

  it("lets the agent sign in with its new token once released, and only then", async () => {
    const { sqlite, call, steps, post, code, release } = await released();
    const token = "new-token";
    const fresh = { ...release, token: await sha256(token) };
    sqlite
      .prepare("UPDATE nodes SET release = ? WHERE id = ?")
      .run(JSON.stringify(fresh), V1);
    const signIn = () =>
      call("GET", "/api/agent/address", undefined, {
        authorization: `Bearer ${token}`,
      });
    expect((await signIn()).status).toBe(401);
    const freshCode = await codeFor(fresh);
    const batch = steps(freshCode);
    batch[0] = step(V1, "host", "server", "release", {
      key: fresh.key,
      signer: fresh.signer,
      seal: fresh.seal,
      token: fresh.token,
      code: freshCode,
    });
    expect((await post({ code: freshCode, steps: batch })).status).toBe(201);
    expect((await signIn()).status).toBe(200);
    expect(
      sqlite
        .prepare(
          `SELECT agent_token_hash AS hash, release FROM nodes WHERE id = '${V1}'`,
        )
        .get(),
    ).toEqual({ hash: fresh.token, release: null });
    expect(code).not.toBe(freshCode);
  });
});

describe("Settings → Quarantine", () => {
  it("reads the defaults and tightens without a fingerprint, queuing tighten to every member", async () => {
    const { sqlite, call, core } = setup();
    await core();
    expect(await json(await call("GET", "/api/settings/quarantine"))).toEqual({
      settings: { cutoff: 15, scan: 10, agree: 2, stop: true },
    });
    const stricter = await call("PUT", "/api/settings/quarantine", {
      cutoff: 5,
      scan: 5,
      agree: 1,
      stop: true,
    });
    expect(stricter.status).toBe(200);
    expect(
      queued(sqlite).map((row) => [
        row.nodeId,
        row.action,
        row.signed,
        JSON.parse(Buffer.from(row.attachment!, "base64url").toString()),
      ]),
    ).toEqual(
      [V1, V2, V3].map((nodeId) => [
        nodeId,
        "tighten",
        null,
        { scan: "5", stop: "true" },
      ]),
    );
    expect(
      (await json(await call("GET", "/api/settings/quarantine"))).settings,
    ).toEqual({ cutoff: 5, scan: 5, agree: 1, stop: true });
  });

  it("asks for the fingerprint to loosen any row", async () => {
    const { sqlite, call, core } = setup();
    await core();
    for (const looser of [
      { cutoff: null, scan: 10, agree: 2, stop: true },
      { cutoff: 15, scan: 20, agree: 2, stop: true },
      { cutoff: 15, scan: 10, agree: 3, stop: true },
      { cutoff: 15, scan: 10, agree: 2, stop: false },
    ]) {
      const refused = await call("PUT", "/api/settings/quarantine", looser);
      expect(refused.status).toBe(403);
      expect(await json(refused)).toMatchObject({
        code: "PROOF_NEEDED",
        op: "quarantine.settings",
      });
    }
    expect(sqlite.prepare("SELECT * FROM quarantine_settings").all()).toEqual(
      [],
    );
    expect(queued(sqlite)).toEqual([]);
  });
});
