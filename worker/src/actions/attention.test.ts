import { describe, expect, it } from "vitest";

import { notFixed, type Health } from "./attention";
import type { ActionRow } from "./store";

const NOW = Date.parse("2026-10-24T12:00:00Z");
const NODE = "n1";
const AFTER = "2026-10-24T09:30:00.000Z";

function action(id: string, values: Partial<ActionRow> = {}): ActionRow {
  return {
    id,
    batch_id: id,
    position: 0,
    mode: "rolling",
    node_id: NODE,
    kind: "compose",
    name: "umami",
    action: "deploy",
    status: "failed",
    requested_by: "owner@example.test",
    requested_at: "2026-10-24T09:24:00.000Z",
    deliverable_at: null,
    sent_at: null,
    finished_at: null,
    exit_code: 1,
    output: "port 53 is already allocated",
    signed: null,
    device_id: null,
    hidden_at: null,
    ...values,
  };
}

const stopped: Health = new Map([[`${NODE}|compose|umami`, false]]);
const running: Health = new Map([[`${NODE}|compose|umami`, true]]);
const ids = (rows: ActionRow[]) => rows.map((row) => row.id);

describe("not fixed", () => {
  it("keeps a failed deploy that nothing came after", () => {
    expect(ids(notFixed([action("a")], [], stopped, NOW))).toEqual(["a"]);
  });

  it("is fixed by a later done deploy of the same stack, nothing else", () => {
    const failed = [action("a")];
    expect(
      notFixed(
        failed,
        [action("b", { status: "done", requested_at: AFTER })],
        stopped,
        NOW,
      ),
    ).toEqual([]);
    const others = [
      action("c", { status: "done", requested_at: AFTER, name: "blog" }),
      action("d", { status: "done", requested_at: "2026-10-24T09:00:00.000Z" }),
      action("e", { status: "done", requested_at: AFTER, action: "logs" }),
      action("f", { status: "done", requested_at: AFTER, node_id: "n2" }),
    ];
    expect(ids(notFixed(failed, others, stopped, NOW))).toEqual(["a"]);
  });

  it("is fixed by a stack now running every container, but not a failed stop", () => {
    expect(notFixed([action("a")], [], running, NOW)).toEqual([]);
    expect(
      ids(notFixed([action("s", { action: "stop" })], [], running, NOW)),
    ).toEqual(["s"]);
  });

  it("drops what the server no longer lists", () => {
    expect(notFixed([action("a")], [], new Map(), NOW)).toEqual([]);
  });

  it("keeps a failed create while the stack it was making is missing", () => {
    expect(
      ids(notFixed([action("c", { action: "create" })], [], new Map(), NOW)),
    ).toEqual(["c"]);
  });

  it("counts an action that expired", () => {
    expect(
      ids(notFixed([action("x", { status: "expired" })], [], stopped, NOW)),
    ).toEqual(["x"]);
  });

  it("never counts a verb that changes nothing", () => {
    for (const verb of ["logs", "read", "scan", "export"] as const) {
      expect(
        notFixed([action(verb, { action: verb })], [], stopped, NOW),
      ).toEqual([]);
    }
  });

  it("never counts one somebody hid", () => {
    expect(
      notFixed(
        [action("h", { hidden_at: "2026-10-24T10:00:00.000Z" })],
        [],
        stopped,
        NOW,
      ),
    ).toEqual([]);
  });

  it("keeps a failed reboot of the server until a later done reboot", () => {
    const reboot = { kind: "host", name: "server", action: "reboot" } as const;
    const failed = [action("r", reboot)];
    expect(ids(notFixed(failed, [], new Map(), NOW))).toEqual(["r"]);
    expect(
      notFixed(
        failed,
        [action("r2", { ...reboot, status: "done", requested_at: AFTER })],
        new Map(),
        NOW,
      ),
    ).toEqual([]);
  });

  it("forgets a failure older than 90 days", () => {
    expect(
      notFixed(
        [action("old", { requested_at: "2026-07-20T09:00:00.000Z" })],
        [],
        stopped,
        NOW,
      ),
    ).toEqual([]);
  });
});
