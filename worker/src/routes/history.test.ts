import { describe, expect, it } from "vitest";

import { LATER_DONE_SQL } from "../actions/attention";
import { app } from "../app";
import type { Env } from "../env";
import { seedNode } from "../test/seed";
import { createTestDb } from "../test/sqlite-d1";

const A = "11111111-1111-4111-8111-111111111111";
const B = "22222222-2222-4222-8222-222222222222";
const C = "33333333-3333-4333-8333-333333333333";
const FOREIGN = "44444444-4444-4444-8444-444444444444";

interface Entry {
  type: "action" | "incident";
  at: string;
  event?: "opened" | "resolved";
  action?: { id: string; action: string; output: string | null };
  incident?: {
    id: string;
    checkName: string;
    nodeId: string;
    nodeName: string;
    summary: string | null;
  };
}

interface Page {
  entries: Entry[];
  next: string | null;
}

const at = (minute: number) =>
  new Date(Date.UTC(2026, 9, 24, 9, minute)).toISOString();

function setup() {
  const { db, sqlite } = createTestDb();
  for (const id of [A, B, C]) seedNode(sqlite, { id });
  seedNode(sqlite, { id: FOREIGN, owner: "someone-else" });
  sqlite.prepare("UPDATE nodes SET name = 'pivox' WHERE id = ?").run(A);
  const env = {
    DB: db,
    PUBLIC_ORIGIN: "https://kry.example.test",
  } as unknown as Env;
  const call = (method: string, path: string) =>
    app.request(`https://kry.example.test${path}`, { method }, env);
  const page = async (query = "") =>
    (await (await call("GET", `/api/history${query}`)).json()) as Page;
  const act = (
    id: string,
    values: {
      node?: string;
      kind?: string;
      name?: string;
      action?: string;
      status?: string;
      at: string;
      output?: string | null;
      batch?: string;
      position?: number;
    },
  ) =>
    sqlite
      .prepare(
        `INSERT INTO actions (id, batch_id, position, mode, node_id, kind, name, action, status,
           requested_by, requested_at, output)
         VALUES (?, ?, ?, 'rolling', ?, ?, ?, ?, ?, 'owner@example.test', ?, ?)`,
      )
      .run(
        id,
        values.batch ?? id,
        values.position ?? 0,
        values.node ?? A,
        values.kind ?? "docker",
        values.name ?? "adguard",
        values.action ?? "restart",
        values.status ?? "done",
        values.at,
        values.output ?? null,
      );
  const check = (id: string, name: string, kind: string, target: string) =>
    sqlite
      .prepare(
        "INSERT INTO checks (id, node_id, name, kind, target) VALUES (?, ?, ?, ?, ?)",
      )
      .run(id, A, name, kind, target);
  const incident = (
    id: string,
    checkId: string,
    startedAt: string,
    resolvedAt: string | null,
    summary: string,
  ) =>
    sqlite
      .prepare(
        `INSERT INTO incidents (id, check_id, status, started_at, resolved_at, summary)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .run(
        id,
        checkId,
        resolvedAt ? "RESOLVED" : "OPEN",
        startedAt,
        resolvedAt,
        summary,
      );
  return { sqlite, call, page, act, check, incident };
}

const keys = (body: Page) =>
  body.entries.map((entry) =>
    entry.type === "action"
      ? entry.action!.id
      : `${entry.incident!.id}:${entry.event}`,
  );

describe("GET /api/history", () => {
  it("merges actions and incident events, newest first", async () => {
    const t = setup();
    t.act("a1", { at: at(0) });
    t.check("c1", "Blog", "HTTP", "https://blog.example.test");
    t.incident("i1", "c1", at(10), at(30), "Blog is down: HTTP 502");
    t.act("a2", { at: at(20) });
    const body = await t.page();
    expect(keys(body)).toEqual(["i1:resolved", "a2", "i1:opened", "a1"]);
    expect(body.entries[0]).toMatchObject({
      at: at(30),
      incident: {
        id: "i1",
        checkName: "Blog",
        nodeId: A,
        nodeName: "pivox",
        summary: "Blog is down: HTTP 502",
      },
    });
  });

  it("leaves out logs and reads from everything, shows them under actions", async () => {
    const t = setup();
    t.act("restart", { at: at(0) });
    t.act("logs", { at: at(1), action: "logs", output: "secret lines" });
    t.act("read", { at: at(2), kind: "compose", name: "shop", action: "read" });
    t.check("c1", "Blog", "HTTP", "https://blog.example.test");
    t.incident("i1", "c1", at(3), null, "Blog is down");
    expect(keys(await t.page())).toEqual(["i1:opened", "restart"]);
    const actions = await t.page("?show=actions");
    expect(keys(actions)).toEqual(["read", "logs", "restart"]);
    expect(actions.entries[1]!.action!.output).toBeNull();
    expect(keys(await t.page("?show=incidents"))).toEqual(["i1:opened"]);
  });

  it("shows only failed and expired actions under failed", async () => {
    const t = setup();
    t.act("done", { at: at(0) });
    t.act("failed", { at: at(1), status: "failed" });
    t.act("expired", { at: at(2), status: "expired" });
    t.check("c1", "Blog", "HTTP", "https://blog.example.test");
    t.incident("i1", "c1", at(3), null, "Blog is down");
    expect(keys(await t.page("?show=failed"))).toEqual(["expired", "failed"]);
  });

  it("searches the verb, the name, the server, the output, the check and the summary", async () => {
    const t = setup();
    t.act("port", {
      at: at(0),
      status: "failed",
      output: "Error: port 53 is already allocated",
    });
    t.act("named", { at: at(1), kind: "compose", name: "listmonk" });
    t.act("elsewhere", { at: at(2), node: B });
    t.check("c1", "Umami", "HTTP", "https://umami.example.test");
    t.incident("i1", "c1", at(3), null, "Umami is down: HTTP 502");
    const find = async (q: string) =>
      keys(await t.page(`?q=${encodeURIComponent(q)}`));
    expect(await find("port 53")).toEqual(["port"]);
    expect(await find("LISTMONK")).toEqual(["named"]);
    expect(await find("pivox")).toEqual(["i1:opened", "named", "port"]);
    expect(await find("umami")).toEqual(["i1:opened"]);
    expect(await find("HTTP 502")).toEqual(["i1:opened"]);
  });

  it("finds a package by name in an upgrade and in a hold", async () => {
    const t = setup();
    t.act("upgrade", {
      at: at(0),
      kind: "apt",
      name: "system",
      action: "upgrade",
      output: JSON.stringify({
        upgraded: ["nodejs", "openssl"],
        moved: [{ name: "nodejs", from: "20.17.0", to: "20.18.0" }],
      }),
    });
    t.act("hold", {
      at: at(1),
      kind: "apt",
      name: "nodejs",
      action: "hold",
      output: "hold nodejs 20.18.0",
    });
    t.act("find", {
      at: at(2),
      kind: "apt",
      name: "system",
      action: "find",
      output: JSON.stringify({ matches: [{ name: "nodejs" }] }),
    });
    expect(keys(await t.page("?q=nodejs"))).toEqual(["hold", "upgrade"]);
    expect(keys(await t.page("?q=openssl"))).toEqual(["upgrade"]);
  });

  it("treats % and _ in a search literally", async () => {
    const t = setup();
    t.act("five-hundred", { at: at(0), status: "failed", output: "HTTP 500" });
    t.act("half", { at: at(1), status: "failed", output: "50% done" });
    t.act("under", { at: at(2), status: "failed", output: "a_b" });
    t.act("other", { at: at(3), status: "failed", output: "axb" });
    expect(keys(await t.page("?q=50%25"))).toEqual(["half"]);
    expect(keys(await t.page("?q=a_b"))).toEqual(["under"]);
  });

  it("pages newest first without losing a batch at the edge", async () => {
    const t = setup();
    const minute = (value: number) =>
      new Date(Date.UTC(2026, 8, 29, 10, value)).toISOString();
    const ids: string[] = [];
    for (let value = 0; value < 5; value += 1) {
      t.act(`old-${value}`, { at: minute(value) });
      ids.push(`old-${value}`);
    }
    for (let position = 0; position < 3; position += 1) {
      t.act(`batch-${position}`, {
        at: minute(10),
        batch: "batch",
        position,
        node: [A, B, C][position]!,
      });
      ids.push(`batch-${position}`);
    }
    for (let value = 20; value < 68; value += 1) {
      t.act(`new-${value}`, { at: minute(value), node: B });
      ids.push(`new-${value}`);
    }
    const first = await t.page();
    expect(first.entries).toHaveLength(50);
    expect(keys(first)[0]).toBe("new-67");
    expect(first.next).not.toBeNull();
    const second = await t.page(`?before=${encodeURIComponent(first.next!)}`);
    expect(second.next).toBeNull();
    const seen = [...keys(first), ...keys(second)];
    expect(new Set(seen).size).toBe(seen.length);
    expect([...seen].sort()).toEqual([...ids].sort());
  });

  it("filters by server and leaves out other owners and trust updates", async () => {
    const t = setup();
    t.act("on-a", { at: at(0), output: "restarted" });
    t.act("on-b", { at: at(1), node: B });
    t.act("foreign", { at: at(2), node: FOREIGN });
    t.act("trust-a", {
      at: at(3),
      kind: "trust",
      name: "devices",
      action: "trust",
    });
    const all = await t.page();
    expect(keys(all)).toEqual(["on-b", "on-a"]);
    expect(all.entries[1]!.action!.output).toBe("restarted");
    expect(keys(await t.page(`?node=${B}`))).toEqual(["on-b"]);
  });
});

describe("failed, not fixed", () => {
  function umami() {
    const t = setup();
    t.sqlite
      .prepare(
        `INSERT INTO stacks (node_id, project, directory, running, total, compose, rollback, updated_at, containers)
         VALUES (?, 'umami', '/var/lib/kry-exec/compose/umami', 1, 2, 1, 1, datetime('now'), '["umami-app-1","umami-db-1"]')`,
      )
      .run(A);
    t.sqlite
      .prepare(
        `INSERT INTO web_addresses (hostname, node_id, project, service, port, mode, created_by, created_at)
         VALUES ('umami.example.test', ?, 'umami', 'app', 3000, 'allow', 'o', '2026-10-01')`,
      )
      .run(A);
    t.act("deploy", {
      at: at(24),
      kind: "compose",
      name: "umami",
      action: "deploy",
      status: "failed",
      output: "exit 1\nport 3000 is already allocated",
    });
    t.check("web", "Umami", "HTTP", "https://umami.example.test/");
    t.incident("i1", "web", at(26), null, "Umami is down: HTTP 502");
    const attention = async () =>
      (await (await t.call("GET", "/api/history/attention")).json()) as {
        items: {
          action: { id: string };
          incident: { id: string; checkName: string } | null;
        }[];
      };
    return { ...t, attention };
  }

  it("lists a failed deploy with the open incident on the stack's address", async () => {
    const t = umami();
    expect((await t.attention()).items).toEqual([
      expect.objectContaining({
        action: expect.objectContaining({ id: "deploy" }),
        incident: {
          id: "i1",
          checkName: "Umami",
          summary: "Umami is down: HTTP 502",
          startedAt: at(26),
        },
      }),
    ]);
  });

  it("counts a later done action on the same target as the fix, never one on another target", async () => {
    const t = setup();
    for (const name of ["adguard", "nginx"]) {
      t.sqlite
        .prepare(
          "INSERT INTO services (node_id, kind, name, state) VALUES (?, 'docker', ?, 'stopped')",
        )
        .run(A, name);
    }
    t.act("f1", { at: at(10), name: "adguard", status: "failed" });
    t.act("d1", { at: at(11), name: "adguard", status: "done" });
    t.act("f2", { at: at(12), name: "nginx", status: "failed" });
    t.act("d2", { at: at(13), name: "adguard", status: "done" });
    t.act("d3", { at: at(9), name: "nginx", status: "done" });
    const items = (
      (await (await t.call("GET", "/api/history/attention")).json()) as {
        items: { action: { id: string } }[];
      }
    ).items;
    expect(items.map((item) => item.action.id)).toEqual(["f2"]);
  });

  it("looks for a fix only among later actions on the failed target", () => {
    const t = setup();
    const plan = (
      t.sqlite
        .prepare(`EXPLAIN QUERY PLAN ${LATER_DONE_SQL.replace(/\?\d/gu, "?")}`)
        .all("owner", "2026-07-01T00:00:00.000Z") as { detail: string }[]
    ).map((row) => row.detail);
    const searches = plan.filter(
      (step) => step.startsWith("SEARCH f") || step.startsWith("SEARCH d"),
    );
    expect(searches[0]).toMatch(
      /^SEARCH f USING INDEX idx_actions_status_node/u,
    );
    expect(searches[1]).toMatch(/^SEARCH d USING INDEX idx_actions_target/u);
    expect(plan.filter((step) => step.startsWith("SCAN"))).toEqual([]);
  });

  it("counts a one-shot unit that ran to the end after a failed restart as fixed", async () => {
    const t = setup();
    t.sqlite
      .prepare(
        "INSERT INTO services (node_id, kind, name, state, since, system) VALUES (?, 'systemd', 'kdump-tools.service', 'boot', NULL, 0)",
      )
      .run(A);
    t.act("restart", {
      at: at(24),
      kind: "systemd",
      name: "kdump-tools.service",
      status: "failed",
    });
    const items = (
      (await (await t.call("GET", "/api/history/attention")).json()) as {
        items: unknown[];
      }
    ).items;
    expect(items).toEqual([]);
  });

  it("answers 404 when hiding another owner's action and leaves it alone", async () => {
    const t = umami();
    t.act("theirs", { at: at(30), node: FOREIGN, status: "failed" });
    expect((await t.call("POST", "/api/history/theirs/hide")).status).toBe(404);
    expect(
      t.sqlite
        .prepare("SELECT hidden_at, hidden_by FROM actions WHERE id = 'theirs'")
        .get(),
    ).toEqual({ hidden_at: null, hidden_by: null });
  });

  it("hides an action, recording who and when, and it leaves the list", async () => {
    const t = umami();
    expect((await t.call("POST", "/api/history/deploy/hide")).status).toBe(204);
    const row = t.sqlite
      .prepare("SELECT hidden_at, hidden_by FROM actions WHERE id = 'deploy'")
      .get() as { hidden_at: string | null; hidden_by: string | null };
    expect(row.hidden_at).not.toBeNull();
    expect(row.hidden_by).not.toBeNull();
    expect((await t.attention()).items).toEqual([]);
  });
});
