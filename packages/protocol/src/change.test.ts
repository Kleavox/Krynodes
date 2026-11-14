import { describe, expect, it } from "vitest";

import { trustChangeSchema } from "./change";
import { summarizeChange } from "./summary";

const names = { a: "Laptop", b: "Phone", c: "Tablet", d: "Key", e: "Spare" };
const N1 = "11111111-1111-4111-8111-111111111111";
const N2 = "22222222-2222-4222-8222-222222222222";
const N3 = "33333333-3333-4333-8333-333333333333";
const servers = { [N1]: "server-1", [N2]: "vps", [N3]: "europa" };

describe("change summaries", () => {
  it("names an admission", () => {
    const summary = summarizeChange({
      names,
      servers,
      currentCore: ["a"],
      currentAccess: { [N1]: ["a"], [N2]: ["a"] },
      change: {
        core: ["a", "b"],
        access: { [N1]: ["a", "b"], [N2]: ["a", "b"] },
      },
    });
    expect(summary.title).toBe("Admit Phone");
    expect(summary.admitted).toEqual(["b"]);
    expect(summary.access).toEqual([
      { nodeId: N1, added: ["b"], removed: [] },
      { nodeId: N2, added: ["b"], removed: [] },
    ]);
  });

  it("calls a passkey with no name an unknown passkey", () => {
    expect(
      summarizeChange({
        names,
        servers,
        currentCore: ["a"],
        currentAccess: {},
        change: { core: ["a", "z"], access: {} },
      }).title,
    ).toBe("Admit an unknown passkey");
  });

  it("names a removal and an access change", () => {
    expect(
      summarizeChange({
        names,
        servers,
        currentCore: ["a", "b", "c"],
        currentAccess: { [N1]: ["a", "c"] },
        change: {
          core: ["a", "b"],
          access: { [N1]: ["a"] },
        },
      }).title,
    ).toBe("Remove Tablet");
    expect(
      summarizeChange({
        names,
        servers,
        currentCore: ["a", "b"],
        currentAccess: { [N1]: ["a"], [N2]: ["a"] },
        change: {
          core: null,
          access: { [N1]: ["a", "b"], [N2]: ["a", "b"] },
        },
      }).title,
    ).toBe("Give Phone access to server-1 and vps");
  });

  it("names who gets or loses which server", () => {
    const title = (
      currentAccess: Record<string, string[]>,
      access: Record<string, string[]>,
    ) =>
      summarizeChange({
        names,
        servers,
        currentCore: ["a", "b", "c", "d", "e"],
        currentAccess,
        change: { core: null, access },
      }).title;
    expect(title({ [N1]: ["a"] }, { [N1]: ["a", "c"] })).toBe(
      "Give Tablet access to server-1",
    );
    expect(title({ [N1]: ["a", "c"] }, { [N1]: ["a"] })).toBe(
      "Take server-1 from Tablet",
    );
    expect(title({ [N3]: ["a", "b", "c"] }, { [N3]: [] })).toBe(
      "Take europa from Laptop, Phone and Tablet",
    );
    expect(title({ [N3]: ["a", "b", "c", "d"] }, { [N3]: [] })).toBe(
      "Take europa from 4 devices",
    );
    expect(
      title(
        { [N1]: ["a"], [N2]: ["a", "c"] },
        { [N1]: ["a", "c"], [N2]: ["a"] },
      ),
    ).toBe("Give Tablet access to server-1 · Take vps from Tablet");
    expect(
      title({ [N1]: [], [N2]: [] }, { [N1]: ["a", "b"], [N2]: ["b", "c"] }),
    ).toBe("Change access on 2 servers");
    expect(
      summarizeChange({
        names,
        servers: {},
        currentCore: ["a", "b"],
        currentAccess: { [N1]: ["a"] },
        change: { core: null, access: { [N1]: ["a", "b"] } },
      }).title,
    ).toBe("Give Phone access to an unknown server");
  });

  it("parses a change and refuses one of the old format", () => {
    const change = {
      v: 2,
      origin: "https://kry.example.test",
      rpId: "kry.example.test",
      version: 3,
      issuedAt: "2026-09-30T10:00:00.000Z",
      expiresAt: "2026-10-01T10:00:00.000Z",
      core: null,
      passphrase: null,
      access: { [N1]: ["YQ"] },
    };
    expect(trustChangeSchema.safeParse(change).success).toBe(true);
    expect(
      trustChangeSchema.safeParse({ ...change, v: 1, nodeIds: [N1] }).success,
    ).toBe(false);
    expect(
      trustChangeSchema.safeParse({ ...change, requireUv: true }).success,
    ).toBe(true);
    expect(
      trustChangeSchema.safeParse({ ...change, requireUv: false }).success,
    ).toBe(false);
    const owned = (account: string) =>
      trustChangeSchema.safeParse({
        ...change,
        core: [{ id: "YQ", name: "Laptop", alg: -7, publicKey: "YQ", account }],
      }).success;
    expect(owned("user1@example.com")).toBe(true);
    expect(owned("")).toBe(false);
    expect(owned("user1 @example.com")).toBe(false);
    expect(owned("user1@example.com\n")).toBe(false);
    expect(owned("usér1@example.com")).toBe(true);
    expect(owned(`${"a".repeat(250)}@b.cc`)).toBe(false);
  });
});

describe("owners in a change summary", () => {
  const U1 = "user1@example.com";
  const U2 = "user2@example.com";
  const base = {
    names,
    servers,
    currentCore: ["a", "b", "c"],
    currentAccess: { [N1]: ["a", "b", "c"] },
  };

  it("names a move by the handle of the account it goes to", () => {
    const summary = summarizeChange({
      ...base,
      currentAccounts: { a: U1, b: U1, c: U2 },
      change: {
        core: ["a", "b", "c"],
        access: { [N1]: ["a", "b", "c"] },
        accounts: { a: U1, b: U2, c: U2 },
      },
    });
    expect(summary.title).toBe("Move Phone to user2");
    expect(summary.moved).toEqual([{ id: "b", from: U1, to: U2 }]);
    expect(summary.recorded).toEqual([]);
  });

  it("says when a change only records who owns each passkey", () => {
    const summary = summarizeChange({
      ...base,
      change: {
        core: ["a", "b", "c"],
        access: { [N1]: ["a", "b", "c"] },
        accounts: { a: U1, b: U1, c: U2 },
      },
    });
    expect(summary.title).toBe("Record Passkey Owners");
    expect(summary.recorded).toEqual(["a", "b", "c"]);
    expect(summary.moved).toEqual([]);
  });

  it("keeps the title of an admission that also records owners", () => {
    const summary = summarizeChange({
      ...base,
      change: {
        core: ["a", "b", "c", "d"],
        access: { [N1]: ["a", "b", "c"] },
        accounts: { a: U1, b: U1, c: U2, d: U1 },
      },
    });
    expect(summary.title).toBe("Admit Key");
    expect(summary.recorded).toEqual(["a", "b", "c"]);
  });

  it("reports no owners when the change names none", () => {
    const summary = summarizeChange({
      ...base,
      currentAccounts: { a: U1, b: U1, c: U2 },
      change: { core: null, access: { [N1]: ["a", "b", "c"] } },
    });
    expect(summary.title).toBe("Refresh servers");
    expect(summary.moved).toEqual([]);
    expect(summary.recorded).toEqual([]);
  });
});
