import { afterEach, describe, expect, it, vi } from "vitest";

import { sendCheckDownEmail } from "../lib/mail";
import { loadStatus } from "../stats/data";
import { freshDb } from "../test/db";
import { addNode, ORIGIN, testEnv } from "../test/env";
import { hubHarness } from "../test/hub";

const START = Date.parse("2026-11-22T08:00:00.000Z");
const at = (minutes: number) => vi.setSystemTime(START + minutes * 60_000);
const iso = (minutes: number) =>
  new Date(START + minutes * 60_000).toISOString();

const hello = {
  type: "hello",
  v: 1,
  version: "0.7.94",
  hostname: "server-1",
  os: "linux",
  arch: "amd64",
  kernel: "6.8.0-45-generic",
  kind: "server",
  sealKey:
    "BKjpRA_slHw4x3NdGJcyQ75R9_DQQtbaWv1M8JLZI1Y0jhyDrnX9kl3a9IjqweVG1-weFpLFHMr0nXfvK_uB2Iw",
  trust: null,
  network: null,
};

const check = (
  state: "up" | "down" | "gone",
  minutes: number,
  cause: "owner" | null = null,
  name = "web-app-1",
) => ({
  type: "check",
  name,
  state,
  cause,
  at: iso(minutes),
  detail: "",
});

async function addCheck(db: D1Database, id: string, container = "web-app-1") {
  await db
    .prepare(
      "INSERT INTO checks (id, node_id, container, name, created_at) VALUES (?1, 'n1', ?2, ?2, ?3)",
    )
    .bind(id, container, iso(0))
    .run();
}

async function mailSetup(mail: Record<string, unknown> = {}) {
  const db = freshDb();
  await addNode(db, "n1");
  await addCheck(db, "c1");
  const writes: string[] = [];
  const failing = { sql: null as string | null };
  const counted = {
    prepare: (sql: string) => {
      if (failing.sql && sql.includes(failing.sql)) {
        failing.sql = null;
        throw new Error("D1 is unavailable");
      }
      if (/^\s*(INSERT|UPDATE|DELETE)/iu.test(sql)) writes.push(sql);
      return db.prepare(sql);
    },
    batch: db.batch.bind(db),
  } as unknown as D1Database;
  const send = vi.fn(async (_message: { subject: string; text: string }) => {});
  const harness = hubHarness(counted, {
    PUBLIC_ORIGIN: ORIGIN,
    EMAIL: { send } as unknown as SendEmail,
    ALERT_EMAIL: "owner@example.test",
    FROM_EMAIL: "kry@example.test",
    ...mail,
  });
  const row = () =>
    db
      .prepare(
        "SELECT state, cause, since, mailed_at FROM checks WHERE id = 'c1'",
      )
      .first();
  const transitions = () =>
    db
      .prepare(
        "SELECT state, cause, at FROM check_transitions WHERE check_id = 'c1' ORDER BY id",
      )
      .all()
      .then((result) => result.results);
  return { db, writes, failing, send, row, transitions, ...harness };
}

afterEach(() => vi.useRealTimers());

describe("checks", () => {
  it("a check change tells the server which containers to watch", async () => {
    const { db, env, hub, send } = testEnv();
    await addNode(db, "n1");
    const created = await send("POST", "/api/checks", {
      nodeId: "n1",
      container: "web-app-1",
      name: "Web",
    });
    expect(created.status).toBe(201);
    const { id } = (await created.json()) as { id: string };
    expect(
      (await send("PATCH", `/api/checks/${id}`, { public: true })).status,
    ).toBe(200);
    expect((await send("DELETE", `/api/checks/${id}`)).status).toBe(204);
    expect(hub.calls.filter((call) => call.path === "/checks")).toEqual([
      { path: "/checks", body: { nodeId: "n1" } },
      { path: "/checks", body: { nodeId: "n1" } },
      { path: "/checks", body: { nodeId: "n1" } },
    ]);

    await addCheck(env.DB, "c1", "web-db-1");
    await addCheck(env.DB, "c2", "web-app-1");
    const fleet = hubHarness(env.DB);
    const ws = fleet.connect("n1");
    await fleet.settled();
    await fleet.say(ws, hello);
    expect(ws.replies()).toEqual([
      { type: "checks", names: ["web-app-1", "web-db-1"] },
    ]);
    await env.DB.prepare("DELETE FROM checks WHERE id = 'c1'").run();
    const pushed = await fleet.hub.fetch(
      new Request("https://fleet/checks", {
        method: "POST",
        body: JSON.stringify({ nodeId: "n1" }),
      }),
    );
    expect(pushed.status).toBe(204);
    expect(ws.replies().at(-1)).toEqual({
      type: "checks",
      names: ["web-app-1"],
    });
  });

  it("a transition updates the check and adds one row", async () => {
    vi.useFakeTimers({ now: START });
    const { connect, settled, say, row, transitions, writes } =
      await mailSetup();
    const ws = connect("n1");
    await settled();
    await say(ws, check("down", 0));
    expect(await row()).toEqual({
      state: "down",
      cause: null,
      since: iso(0),
      mailed_at: null,
    });
    expect(await transitions()).toEqual([
      { state: "down", cause: null, at: iso(0) },
    ]);
    const before = writes.length;
    await say(ws, check("down", 0));
    expect(writes.length).toBe(before);
    expect(await transitions()).toHaveLength(1);
  });

  it("a repeated state writes nothing and keeps the owner's pause", async () => {
    vi.useFakeTimers({ now: START });
    const { connect, settled, say, row, transitions, writes } =
      await mailSetup();
    const ws = connect("n1");
    await settled();
    await say(ws, check("down", 0, "owner"));
    const before = writes.length;
    await say(ws, check("down", 0));
    expect(writes.length).toBe(before);
    expect(await row()).toMatchObject({ state: "down", cause: "owner" });
    expect(await transitions()).toHaveLength(1);
  });

  it("a check for a container with no check row is ignored", async () => {
    const { connect, settled, say, writes, db } = await mailSetup();
    const ws = connect("n1");
    await settled();
    const before = writes.length;
    await say(ws, check("down", 0, null, "other-1"));
    expect(writes.length).toBe(before);
    expect(
      await db.prepare("SELECT COUNT(*) AS n FROM check_transitions").first(),
    ).toEqual({ n: 0 });
  });

  it("a down check mails once after five minutes and not again within the hour", async () => {
    vi.useFakeTimers({ now: START });
    const { connect, settled, say, ping, fire, send, row } = await mailSetup();
    const ws = connect("n1");
    await settled();
    await say(ws, check("down", 0));
    at(4);
    ping(ws);
    await fire();
    expect(send).not.toHaveBeenCalled();
    at(5);
    ping(ws);
    await fire();
    expect(send).toHaveBeenCalledTimes(1);
    const mail = send.mock.calls[0]![0];
    expect(mail.subject).toBe("[Krynodes] server-1: 1 check down");
    expect(mail.text).toContain("web-app-1 · down since 2026-11-22 08:00 UTC");
    expect(await row()).toMatchObject({ mailed_at: iso(5) });
    at(6);
    await say(ws, check("up", 6));
    at(10);
    await say(ws, check("down", 10));
    for (const minute of [15, 30, 64]) {
      at(minute);
      ping(ws);
      await fire();
    }
    expect(send).toHaveBeenCalledTimes(1);
  });

  it("a second down episode still down at minute 65 mails again", async () => {
    vi.useFakeTimers({ now: START });
    const { connect, settled, say, ping, fire, send, alarmAt } =
      await mailSetup();
    const ws = connect("n1");
    await settled();
    await say(ws, check("down", 0));
    at(5);
    ping(ws);
    await fire();
    at(6);
    await say(ws, check("up", 6));
    at(10);
    await say(ws, check("down", 10));
    at(64);
    ping(ws);
    await fire();
    expect(alarmAt()).toBe(START + 65 * 60_000);
    at(65);
    ping(ws);
    await fire();
    expect(send).toHaveBeenCalledTimes(2);
    expect(send.mock.calls[1]![0].text).toContain(
      "web-app-1 · down since 2026-11-22 08:10 UTC",
    );
  });

  it("a check going down while mail is being sent is still mailed later", async () => {
    vi.useFakeTimers({ now: START });
    const { db, connect, settled, say, ping, fire, send } = await mailSetup();
    await addCheck(db, "c2", "web-db-1");
    const ws = connect("n1");
    await settled();
    await say(ws, check("down", 0));
    send.mockImplementationOnce(async () => {
      await say(ws, check("down", 5, null, "web-db-1"));
    });
    at(5);
    ping(ws);
    await fire();
    expect(send).toHaveBeenCalledTimes(1);
    at(10);
    ping(ws);
    await fire();
    expect(send).toHaveBeenCalledTimes(2);
    expect(send.mock.calls[1]![0].text).toContain("web-db-1 · down since");
  });

  it("a check whose five minutes already passed arrives during the pass and is still mailed", async () => {
    vi.useFakeTimers({ now: START });
    const { db, connect, settled, say, ping, fire, send, alarmAt } =
      await mailSetup();
    await addCheck(db, "c2", "web-db-1");
    const ws = connect("n1");
    await settled();
    at(15);
    await say(ws, check("down", 15));
    send.mockImplementationOnce(async () => {
      await say(ws, check("down", 10, null, "web-db-1"));
    });
    at(20);
    ping(ws);
    await fire();
    expect(send).toHaveBeenCalledTimes(1);
    expect(alarmAt()).toBeLessThanOrEqual(START + 20 * 60_000);
    await fire();
    expect(send).toHaveBeenCalledTimes(2);
    expect(send.mock.calls[1]![0].text).toContain(
      "web-db-1 · down since 2026-11-22 08:10 UTC",
    );
  });

  it("a check due at the same time as the pass it arrives in is still mailed", async () => {
    vi.useFakeTimers({ now: START });
    const { db, connect, settled, say, ping, fire, send } = await mailSetup();
    await addCheck(db, "c2", "web-db-1");
    const ws = connect("n1");
    await settled();
    await say(ws, check("down", 0));
    await say(ws, check("down", 0, null, "web-db-1"));
    at(5);
    ping(ws);
    await fire();
    expect(send).toHaveBeenCalledTimes(1);
    at(6);
    await say(ws, check("up", 6));
    await say(ws, check("up", 6, null, "web-db-1"));
    at(10);
    await say(ws, check("down", 10));
    send.mockImplementationOnce(async () => {
      await say(ws, check("down", 10, null, "web-db-1"));
    });
    at(65);
    ping(ws);
    await fire();
    expect(send).toHaveBeenCalledTimes(2);
    await fire();
    expect(send).toHaveBeenCalledTimes(3);
    expect(send.mock.calls[2]![0].text).toContain(
      "web-db-1 · down since 2026-11-22 08:55 UTC",
    );
  });

  it("a mail pass that fails is tried again for the same due time", async () => {
    vi.useFakeTimers({ now: START });
    const { connect, settled, say, fire, send, failing, alarmAt } =
      await mailSetup();
    const ws = connect("n1");
    await settled();
    await say(ws, hello);
    await say(ws, check("down", 0));
    failing.sql = "c.mailed_at IS NULL";
    at(5);
    await expect(fire()).rejects.toThrow("D1 is unavailable");
    expect(ws.closed?.code).toBe(4408);
    expect(alarmAt()).toBeLessThanOrEqual(START + 6 * 60_000);
    at(6);
    await fire();
    expect(send.mock.calls.map(([mail]) => mail.subject)).toEqual([
      "[Krynodes] server-1: 1 check down",
    ]);
  });

  it("a D1 error in the offline pass is thrown without resetting the hub", async () => {
    vi.useFakeTimers({ now: START });
    const { connect, settled, say, ping, fire, send, failing, resets } =
      await mailSetup();
    const ws = connect("n1");
    await settled();
    await say(ws, hello);
    await say(ws, check("down", 0));
    failing.sql = "SELECT n.id, n.last_seen_at";
    at(5);
    ping(ws);
    await expect(fire()).rejects.toThrow("D1 is unavailable");
    expect(resets()).toBe(0);
    at(6);
    ping(ws);
    await fire();
    expect(send).toHaveBeenCalledTimes(1);
  });

  it("a failed send is retried at the next alarm and mails once", async () => {
    vi.useFakeTimers({ now: START });
    const { connect, settled, say, ping, fire, send, row, alarmAt } =
      await mailSetup();
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    const ws = connect("n1");
    await settled();
    await say(ws, hello);
    await say(ws, check("down", 0));
    send.mockRejectedValueOnce(new Error("mail refused"));
    at(5);
    ping(ws);
    await fire();
    expect(send).toHaveBeenCalledTimes(1);
    expect(await row()).toMatchObject({ mailed_at: null });
    expect(alarmAt()).toBeLessThanOrEqual(START + 6 * 60_000);
    at(6);
    ping(ws);
    await fire();
    expect(send).toHaveBeenCalledTimes(2);
    expect(await row()).toMatchObject({ mailed_at: iso(6) });
    for (const minute of [7, 8, 30]) {
      at(minute);
      ping(ws);
      await fire();
    }
    expect(send).toHaveBeenCalledTimes(2);
    expect(errors).toHaveBeenCalledTimes(1);
    errors.mockRestore();
  });

  it("a mail due in the same alarm that finds a silent server goes at once", async () => {
    vi.useFakeTimers({ now: START });
    const { connect, settled, say, fire, send } = await mailSetup();
    const ws = connect("n1");
    await settled();
    await say(ws, hello);
    await say(ws, check("down", 0));
    at(5);
    await fire();
    expect(ws.closed?.code).toBe(4408);
    expect(send.mock.calls.map(([mail]) => mail.subject)).toEqual([
      "[Krynodes] server-1: 1 check down",
    ]);
    at(10);
    await fire();
    expect(send.mock.calls.map(([mail]) => mail.subject)).toEqual([
      "[Krynodes] server-1: 1 check down",
      "[Krynodes] server-1 is offline",
    ]);
  });

  it("two silent servers closed in one sweep leave no agent recorded", async () => {
    vi.useFakeTimers({ now: START });
    const { db, connect, settled, fire, ping, stored } = await mailSetup();
    await addNode(db, "n2", "server-2");
    const first = connect("n1");
    await settled();
    const second = connect("n2");
    await settled();
    expect(stored("agents")).toEqual(["n1", "n2"]);
    at(1);
    ping(first);
    ping(second);
    await fire();
    expect(stored("agents")).toEqual(["n1", "n2"]);
    at(3);
    await fire();
    expect(first.closed?.code).toBe(4408);
    expect(second.closed?.code).toBe(4408);
    expect(stored("agents")).toEqual([]);
  });

  it("one failed send does not stop the other mails", async () => {
    vi.useFakeTimers({ now: START });
    const { db, connect, settled, say, hub, fire, send, ping } =
      await mailSetup();
    await addNode(db, "n2", "server-2");
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    const ws = connect("n1");
    const other = connect("n2");
    await settled();
    await say(ws, hello);
    await say(other, { ...hello, hostname: "server-2" });
    await say(ws, check("down", 0));
    other.close(1006, "gone");
    await hub.webSocketClose(other as unknown as WebSocket);
    send.mockRejectedValueOnce(new Error("mail refused"));
    at(5);
    ping(ws);
    await fire();
    expect(send.mock.calls.map(([mail]) => mail.subject)).toEqual([
      "[Krynodes] server-2 is offline",
      "[Krynodes] server-1: 1 check down",
    ]);
    expect(errors).toHaveBeenCalledTimes(1);
    errors.mockRestore();
  });

  it("a check time is held within ten minutes before now", async () => {
    vi.useFakeTimers({ now: START });
    const { connect, settled, say, row, transitions } = await mailSetup();
    const ws = connect("n1");
    await settled();
    at(60);
    await say(ws, check("down", 0));
    expect(await row()).toMatchObject({ since: iso(50) });
    await say(ws, check("up", 90));
    expect(await transitions()).toEqual([
      { state: "down", cause: null, at: iso(50) },
      { state: "up", cause: null, at: iso(60) },
    ]);
  });

  it("logs once that mail is not configured", async () => {
    vi.useFakeTimers({ now: START });
    const logs = vi.spyOn(console, "log").mockImplementation(() => {});
    const { connect, settled, say } = await mailSetup({ EMAIL: undefined });
    const ws = connect("n1");
    await settled();
    await say(ws, check("down", 0));
    await say(ws, check("up", 1));
    await say(ws, check("down", 2));
    expect(
      logs.mock.calls.filter(([line]) =>
        String(line).startsWith("[kry email] not configured"),
      ),
    ).toHaveLength(1);
    logs.mockRestore();
  });

  it("a server lost in a hub restart still gets its offline mail", async () => {
    vi.useFakeTimers({ now: START });
    const { connect, settled, say, forget, fire, send } = await mailSetup();
    const ws = connect("n1");
    await settled();
    await say(ws, hello);
    ws.close(1006, "restart");
    forget();
    at(1);
    await fire();
    expect(send).not.toHaveBeenCalled();
    at(6);
    await fire();
    expect(send).toHaveBeenCalledTimes(1);
    expect(send.mock.calls[0]![0].subject).toBe(
      "[Krynodes] server-1 is offline",
    );
  });

  it("a server's hello gets its checks even when the network step fails", async () => {
    const db = freshDb();
    await addNode(db, "n1");
    await addCheck(db, "c1");
    const failing = {
      prepare: (sql: string) => {
        if (sql.includes("network")) throw new Error("D1 is unavailable");
        return db.prepare(sql);
      },
      batch: db.batch.bind(db),
    } as unknown as D1Database;
    const { connect, settled, say } = hubHarness(failing);
    const ws = connect("n1");
    await settled();
    const key = Buffer.alloc(32, 1).toString("base64");
    await expect(
      say(ws, {
        ...hello,
        network: {
          version: 0,
          key,
          signer: key,
          ready: true,
          reason: null,
        },
      }),
    ).rejects.toThrow("D1 is unavailable");
    expect(ws.replies()).toEqual([{ type: "checks", names: ["web-app-1"] }]);
  });

  it("a check on an offline server reads unknown and keeps its last state", async () => {
    const { db, hub, call } = testEnv();
    await addNode(db, "n1");
    await addCheck(db, "c1");
    await db.prepare("UPDATE checks SET state = 'up' WHERE id = 'c1'").run();
    const states = async () =>
      (
        (await (await call("/api/checks")).json()) as {
          checks: { state: string; lastState: string; online: boolean }[];
        }
      ).checks.map(({ state, lastState, online }) => ({
        state,
        lastState,
        online,
      }));
    expect(await states()).toEqual([
      { state: "unknown", lastState: "up", online: false },
    ]);
    hub.online = ["n1"];
    expect(await states()).toEqual([
      { state: "up", lastState: "up", online: true },
    ]);
  });

  it("refuses a check past 64 on one server and names it", async () => {
    const { db, send } = testEnv();
    await addNode(db, "n1");
    for (let index = 0; index < 64; index += 1) {
      await addCheck(db, `c${index}`, `app-${index}`);
    }
    const full = await send("POST", "/api/checks", {
      nodeId: "n1",
      container: "app-64",
      name: "One More",
    });
    expect(full.status).toBe(409);
    expect(await full.json()).toEqual({
      code: "TOO_MANY",
      message: "server-1 already has 64 checks.",
    });
    expect(
      await db.prepare("SELECT COUNT(*) AS n FROM checks").first(),
    ).toEqual({ n: 64 });
  });

  it("the owner's stop never mails", async () => {
    vi.useFakeTimers({ now: START });
    const { connect, settled, say, ping, fire, send } = await mailSetup();
    const ws = connect("n1");
    await settled();
    await say(ws, check("down", 0, "owner"));
    await say(ws, check("gone", 1, "owner"));
    for (const minute of [6, 30, 120]) {
      at(minute);
      ping(ws);
      await fire();
    }
    expect(send).not.toHaveBeenCalled();
  });

  it("a recovery never mails", async () => {
    vi.useFakeTimers({ now: START });
    const { connect, settled, say, ping, fire, send } = await mailSetup();
    const ws = connect("n1");
    await settled();
    await say(ws, check("up", 0));
    await say(ws, check("down", 1));
    await say(ws, check("up", 3));
    for (const minute of [6, 30, 120]) {
      at(minute);
      ping(ws);
      await fire();
    }
    expect(send).not.toHaveBeenCalled();
  });

  it("a server offline for five minutes mails once", async () => {
    vi.useFakeTimers({ now: START });
    const { connect, settled, say, hub, fire, send, alarmAt } =
      await mailSetup();
    const ws = connect("n1");
    await settled();
    await say(ws, hello);
    ws.close(1006, "gone");
    await hub.webSocketClose(ws as unknown as WebSocket);
    expect(alarmAt()).toBe(START + 60_000);
    at(1);
    await fire();
    expect(alarmAt()).toBe(START + 5 * 60_000);
    at(5);
    await fire();
    expect(send).toHaveBeenCalledTimes(1);
    expect(send.mock.calls[0]![0].subject).toBe(
      "[Krynodes] server-1 is offline",
    );
    expect(send.mock.calls[0]![0].text).toContain(
      "Last report: 2026-11-22 08:00 UTC",
    );
    expect(alarmAt()).toBeNull();
    at(30);
    await fire();
    const again = connect("n1");
    await settled();
    at(31);
    again.close(1006, "gone");
    await hub.webSocketClose(again as unknown as WebSocket);
    for (const minute of [36, 50]) {
      at(minute);
      await fire();
    }
    expect(send).toHaveBeenCalledTimes(1);
  });

  it("mail without ALERT_EMAIL sends nothing and does not throw", async () => {
    vi.useFakeTimers({ now: START });
    const { connect, settled, say, fire, send, row, hub, alarmAt } =
      await mailSetup({ ALERT_EMAIL: undefined });
    const ws = connect("n1");
    await settled();
    await say(ws, check("down", 0));
    at(6);
    ws.close(1006, "gone");
    await hub.webSocketClose(ws as unknown as WebSocket);
    await fire();
    expect(alarmAt()).toBe(START + 11 * 60_000);
    at(12);
    await fire();
    expect(alarmAt()).toBeNull();
    expect(send).not.toHaveBeenCalled();
    expect(await row()).toMatchObject({
      state: "unknown",
      cause: "offline",
      mailed_at: null,
    });
    await expect(
      sendCheckDownEmail(
        {
          PUBLIC_ORIGIN: ORIGIN,
          EMAIL: { send },
          FROM_EMAIL: "kry@example.test",
        } as never,
        {
          nodeName: "server-1",
          checks: [{ name: "Web", container: "web-app-1", since: iso(0) }],
        },
      ),
    ).resolves.toBeUndefined();
    expect(send).not.toHaveBeenCalled();
  });

  it("an offline server's checks turn unknown at its last report after five minutes and not before", async () => {
    vi.useFakeTimers({ now: START });
    const { connect, settled, say, hub, fire, row, transitions } =
      await mailSetup({ ALERT_EMAIL: undefined });
    const ws = connect("n1");
    await settled();
    await say(ws, hello);
    await say(ws, check("up", 0));
    at(2);
    ws.close(1006, "gone");
    await hub.webSocketClose(ws as unknown as WebSocket);
    at(6);
    await fire();
    expect(await transitions()).toEqual([
      { state: "up", cause: null, at: iso(0) },
    ]);
    at(7);
    await fire();
    expect(await transitions()).toEqual([
      { state: "up", cause: null, at: iso(0) },
      { state: "unknown", cause: "offline", at: iso(2) },
    ]);
    expect(await row()).toMatchObject({
      state: "unknown",
      cause: "offline",
      since: iso(2),
    });
    at(20);
    await fire();
    expect(await transitions()).toHaveLength(2);
  });

  it("a reconnect within five minutes writes nothing", async () => {
    vi.useFakeTimers({ now: START });
    const { connect, settled, say, hub, fire, ping, row, transitions } =
      await mailSetup();
    const ws = connect("n1");
    await settled();
    await say(ws, hello);
    await say(ws, check("up", 0));
    at(2);
    ws.close(1006, "gone");
    await hub.webSocketClose(ws as unknown as WebSocket);
    at(4);
    const again = connect("n1");
    await settled();
    await say(again, hello);
    await say(again, check("up", 0));
    at(7);
    ping(again);
    await fire();
    expect(await transitions()).toHaveLength(1);
    expect(await row()).toMatchObject({ state: "up", cause: null });
  });

  it("on return the up re-statement writes one transition back", async () => {
    vi.useFakeTimers({ now: START });
    const { connect, settled, say, hub, fire, row, transitions } =
      await mailSetup();
    const ws = connect("n1");
    await settled();
    await say(ws, hello);
    await say(ws, check("up", 0));
    at(2);
    ws.close(1006, "gone");
    await hub.webSocketClose(ws as unknown as WebSocket);
    at(7);
    await fire();
    at(30);
    const again = connect("n1");
    await settled();
    await say(again, hello);
    await say(again, check("up", 0));
    expect(await transitions()).toEqual([
      { state: "up", cause: null, at: iso(0) },
      { state: "unknown", cause: "offline", at: iso(2) },
      { state: "up", cause: null, at: iso(30) },
    ]);
    expect(await row()).toMatchObject({ state: "up", since: iso(30) });
  });

  it("a down check on a server gone offline is not mailed as down", async () => {
    vi.useFakeTimers({ now: START });
    const { connect, settled, say, hub, fire, send } = await mailSetup();
    const ws = connect("n1");
    await settled();
    await say(ws, hello);
    await say(ws, check("down", 0));
    ws.close(1006, "gone");
    await hub.webSocketClose(ws as unknown as WebSocket);
    for (const minute of [5, 70]) {
      at(minute);
      await fire();
    }
    expect(send.mock.calls.map(([mail]) => mail.subject)).toEqual([
      "[Krynodes] server-1 is offline",
    ]);
  });

  it("a paused check stays paused when its server returns", async () => {
    vi.useFakeTimers({ now: START });
    const { connect, settled, say, hub, fire, send, row, ping } =
      await mailSetup();
    const ws = connect("n1");
    await settled();
    await say(ws, hello);
    await say(ws, check("down", 0, "owner"));
    at(1);
    ws.close(1006, "gone");
    await hub.webSocketClose(ws as unknown as WebSocket);
    at(6);
    await fire();
    expect(await row()).toMatchObject({ state: "unknown", cause: "offline" });
    at(8);
    const again = connect("n1");
    await settled();
    await say(again, hello);
    await say(again, check("down", 0));
    expect(await row()).toMatchObject({ state: "down", cause: "owner" });
    for (const minute of [20, 70]) {
      at(minute);
      ping(again);
      await fire();
    }
    expect(send.mock.calls.map(([mail]) => mail.subject)).toEqual([
      "[Krynodes] server-1 is offline",
    ]);
  });

  it("a check paused 100 days ago survives an outage still paused and never mails", async () => {
    vi.useFakeTimers({ now: START });
    const { connect, settled, say, hub, fire, ping, send, row, transitions } =
      await mailSetup();
    const day = 24 * 60;
    at(-100 * day);
    const ws = connect("n1");
    await settled();
    await say(ws, hello);
    await say(ws, check("down", -100 * day, "owner"));
    at(0);
    ws.close(1006, "gone");
    await hub.webSocketClose(ws as unknown as WebSocket);
    at(5);
    await fire();
    expect(await transitions()).toEqual([
      { state: "down", cause: "owner", at: iso(-100 * day) },
      { state: "unknown", cause: "offline", at: iso(0) },
    ]);
    at(8);
    const again = connect("n1");
    await settled();
    await say(again, hello);
    await say(again, check("down", -100 * day));
    expect(await row()).toMatchObject({ state: "down", cause: "owner" });
    for (const minute of [20, 70, 130]) {
      at(minute);
      ping(again);
      await fire();
    }
    expect(send.mock.calls.map(([mail]) => mail.subject)).toEqual([
      "[Krynodes] server-1 is offline",
    ]);
  });

  it("the status page still reads a check up since before the window after a later write", async () => {
    vi.useFakeTimers({ now: START });
    const { db, connect, settled, say, transitions } = await mailSetup();
    await db.prepare("UPDATE checks SET public = 1 WHERE id = 'c1'").run();
    const day = 24 * 60;
    at(-100 * day);
    const ws = connect("n1");
    await settled();
    await say(ws, check("up", -100 * day));
    at(0);
    await say(ws, check("down", 0));
    expect(await transitions()).toHaveLength(2);
    const [service] = (await loadStatus(db, START + 60_000)).services;
    expect(service!.days[0]!.state).toBe("up");
    expect(service!.uptime).toBeGreaterThan(99);
  });

  it("a re-statement that arrives during the offline batch is applied after it", async () => {
    vi.useFakeTimers({ now: START });
    const db = freshDb();
    await addNode(db, "n1");
    await addCheck(db, "c1");
    const hold: { during: (() => void) | null } = { during: null };
    const gated = {
      prepare: db.prepare.bind(db),
      batch: (statements: D1PreparedStatement[]) => {
        const during = hold.during;
        hold.during = null;
        during?.();
        return db.batch(statements);
      },
    } as unknown as D1Database;
    const { connect, settled, say, hub, fire } = hubHarness(gated);
    const ws = connect("n1");
    await settled();
    await say(ws, hello);
    await say(ws, check("up", 0));
    at(2);
    ws.close(1006, "gone");
    await hub.webSocketClose(ws as unknown as WebSocket);
    at(7);
    let late: Promise<void> | null = null;
    hold.during = () => {
      late = say(ws, check("up", 0));
    };
    await fire();
    await late;
    expect(
      await db.prepare("SELECT state FROM checks WHERE id = 'c1'").first(),
    ).toEqual({ state: "up" });
  });

  it("transitions older than 90 days are removed, except the last one before the cutoff", async () => {
    vi.useFakeTimers({ now: START });
    const { connect, settled, say, db, transitions } = await mailSetup();
    const day = 24 * 60;
    await db
      .prepare(
        "INSERT INTO check_transitions (check_id, state, cause, at) VALUES ('c1', 'down', NULL, ?1), ('c1', 'up', NULL, ?2), ('c1', 'down', NULL, ?3)",
      )
      .bind(iso(-95 * day), iso(-91 * day), iso(-89 * day))
      .run();
    const ws = connect("n1");
    await settled();
    await say(ws, check("up", 0));
    expect(await transitions()).toEqual([
      { state: "up", cause: null, at: iso(-91 * day) },
      { state: "down", cause: null, at: iso(-89 * day) },
      { state: "up", cause: null, at: iso(0) },
    ]);
  });

  it("a check for a container that does not exist on that server is allowed and shows unknown", async () => {
    const { db, hub, send, call } = testEnv();
    await addNode(db, "n1");
    hub.online = ["n1"];
    const created = await send("POST", "/api/checks", {
      nodeId: "n1",
      container: "later-app-1",
      name: "Later",
    });
    expect(created.status).toBe(201);
    expect(await created.json()).toMatchObject({
      nodeId: "n1",
      nodeName: "server-1",
      online: true,
      container: "later-app-1",
      name: "Later",
      public: false,
      note: null,
      state: "unknown",
      cause: null,
      since: null,
    });
    const listed = (await (await call("/api/checks")).json()) as {
      checks: { state: string }[];
    };
    expect(listed.checks.map((one) => one.state)).toEqual(["unknown"]);
  });

  it("names the status page only when one is configured", async () => {
    const listed = async (overrides: Parameters<typeof testEnv>[0]) =>
      (await (await testEnv(overrides).call("/api/checks")).json()) as {
        statusPage: string | null;
      };
    expect((await listed({})).statusPage).toBeNull();
    expect((await listed({ STATUS_PAGE_URL: "" })).statusPage).toBeNull();
    expect(
      (await listed({ STATUS_PAGE_URL: "https://stats.example.test" }))
        .statusPage,
    ).toBe("https://stats.example.test");
  });

  it("refuses a missing server, a duplicate and a bad name", async () => {
    const { db, send } = testEnv();
    await addNode(db, "n1");
    const missing = await send("POST", "/api/checks", {
      nodeId: "n9",
      container: "web-app-1",
      name: "Web",
    });
    expect(missing.status).toBe(404);
    expect(await missing.json()).toEqual({
      code: "NOT_FOUND",
      message: "The server was not found.",
    });
    const body = { nodeId: "n1", container: "web-app-1", name: "Web" };
    expect((await send("POST", "/api/checks", body)).status).toBe(201);
    const twice = await send("POST", "/api/checks", body);
    expect(twice.status).toBe(409);
    expect(await twice.json()).toEqual({
      code: "CHECK_EXISTS",
      message: "server-1 already has a check for web-app-1.",
    });
    for (const bad of [
      { ...body, container: "x" },
      { ...body, container: "web-app-2", name: " Web" },
      { ...body, container: "web-app-2", name: "W".repeat(65) },
    ]) {
      expect((await send("POST", "/api/checks", bad)).status).toBe(400);
    }
  });

  it("edits a name, the public flag and a note, and clears the note", async () => {
    const { db, send } = testEnv();
    await addNode(db, "n1");
    const created = await send("POST", "/api/checks", {
      nodeId: "n1",
      container: "web-app-1",
      name: "Web",
    });
    const { id } = (await created.json()) as { id: string };
    const edited = await send("PATCH", `/api/checks/${id}`, {
      name: "Website",
      public: true,
      note: "Moved to a new host.",
    });
    expect(await edited.json()).toMatchObject({
      name: "Website",
      public: true,
      note: "Moved to a new host.",
    });
    const cleared = await send("PATCH", `/api/checks/${id}`, { note: null });
    expect(await cleared.json()).toMatchObject({
      name: "Website",
      public: true,
      note: null,
    });
    expect(
      (await send("PATCH", `/api/checks/${id}`, { note: "n".repeat(281) }))
        .status,
    ).toBe(400);
    expect(
      (await send("PATCH", "/api/checks/nope", { public: false })).status,
    ).toBe(404);
    expect((await send("DELETE", "/api/checks/nope")).status).toBe(404);
  });
});
