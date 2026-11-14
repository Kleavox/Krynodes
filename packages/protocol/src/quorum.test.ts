import { describe, expect, it } from "vitest";

import quorum from "./fixtures/quorum.json";
import { evaluateQuorum, type QuorumInput } from "./quorum";

const cases = quorum.cases as (QuorumInput & { name: string; ok: boolean })[];

const U1 = "user1@example.com";
const U2 = "user2@example.com";
const abc = ["a", "b", "c"];
const stored = { core: abc, access: abc, accounts: { a: U1, b: U1, c: U2 } };
const fourth = {
  core: [...abc, "d"],
  access: abc,
  accounts: { ...stored.accounts, d: U1 },
};

describe("quorum", () => {
  for (const item of cases) {
    it(item.name, () => {
      const result = evaluateQuorum({
        current: item.current,
        change: item.change,
        approvals: item.approvals,
        unsynced: item.unsynced,
      });
      expect(result.ok, JSON.stringify(result)).toBe(item.ok);
    });
  }

  it("says what is missing", () => {
    const result = evaluateQuorum({
      current: { core: ["a", "b", "c"], access: ["a", "b", "c"] },
      change: { core: ["a", "b", "c", "d"], access: ["a", "b", "c"] },
      approvals: ["a"],
    });
    expect(result).toEqual({ ok: false, reason: "needs 1 more approval" });
    expect(
      evaluateQuorum({
        current: { core: ["a", "b", "c"], access: ["a", "b", "c"] },
        change: { core: ["b", "c"], access: ["b", "c"] },
        approvals: [],
      }),
    ).toEqual({ ok: false, reason: "needs an approval" });
  });

  it("says which approval two accounts still need", () => {
    expect(
      evaluateQuorum({ current: stored, change: fourth, approvals: ["a"] }),
    ).toEqual({
      ok: false,
      reason:
        "needs 1 more approval, from another account or a passkey that is not synced",
    });
    expect(
      evaluateQuorum({
        current: stored,
        change: fourth,
        approvals: ["a"],
        unsynced: ["a"],
      }),
    ).toEqual({ ok: false, reason: "needs 1 more approval" });
    expect(
      evaluateQuorum({
        current: stored,
        change: fourth,
        approvals: ["a", "b"],
      }),
    ).toEqual({
      ok: false,
      reason:
        "needs approval from another account's passkey, or from one that is not synced",
    });
  });

  it("says when the accounts are left out or a move lacks its owner", () => {
    expect(
      evaluateQuorum({
        current: stored,
        change: { core: [...abc, "d"], access: abc },
        approvals: ["a", "c"],
      }),
    ).toEqual({ ok: false, reason: "every passkey needs its account" });
    expect(
      evaluateQuorum({
        current: stored,
        change: {
          core: abc,
          access: abc,
          accounts: { a: U1, b: U1, c: U1 },
        },
        approvals: ["a", "b"],
        unsynced: ["a"],
      }),
    ).toEqual({
      ok: false,
      reason: "needs approval from a passkey of the account it leaves",
    });
  });
});
