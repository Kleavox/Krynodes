import type { TrustChange } from "@krynodes/protocol";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { DeviceRecord, NodeRecord, NodeTrust } from "@/types";

import { ChangeDetails } from "./change-details";
import { accountProblem } from "./move-dialog";
import type { Fleet } from "./use-fleet";

const ME = "user1@example.com";
const FRIEND = "user2@example.com";
const N1 = "11111111-1111-4111-8111-111111111111";

const device = (id: string, owner: string, core = true): DeviceRecord => ({
  id,
  name: id[0]!.toUpperCase() + id.slice(1),
  alg: -7,
  publicKey: "AQID",
  createdAt: "2026-11-01T09:00:00.000Z",
  lastUsedAt: null,
  verifies: true,
  fingerprint: `${id}-print`.padEnd(16, "0").slice(0, 16),
  core,
  owner,
  mine: owner === ME,
});

const alpha = device("alpha", ME);
const bravo = device("bravo", ME);
const charlie = device("charlie", FRIEND);
const delta = device("delta", ME, false);
const trusted = [alpha, bravo, charlie];

function fleet(accounts: string[] | null): Fleet {
  const trust: NodeTrust = {
    version: 1,
    core: trusted.map((entry) => entry.fingerprint),
    access: trusted.map((entry) => entry.fingerprint),
    accounts,
  };
  const servers = [
    {
      node: { id: N1, name: "server-1", agent_version: "0.7.22" } as NodeRecord,
      trust,
    },
  ];
  const devices = [...trusted, delta];
  return {
    view: { origin: "https://kry.example.test", devices, servers },
    devices,
    servers,
    name: (id: string) =>
      devices.find((entry) => entry.id === id)?.name ?? "An unknown passkey",
  } as unknown as Fleet;
}

const change = (keys: DeviceRecord[], owners: string[]): TrustChange => ({
  v: 2,
  origin: "https://kry.example.test",
  rpId: "kry.example.test",
  version: 2,
  issuedAt: "2026-11-14T10:00:00.000Z",
  expiresAt: "2026-11-15T10:00:00.000Z",
  core: keys.map((key, index) => ({
    id: key.id,
    name: key.name,
    alg: -7,
    publicKey: key.publicKey,
    account: owners[index]!,
  })),
  passphrase: null,
  access: { [N1]: trusted.map((entry) => entry.id) },
});

const text = (html: string) =>
  html
    .replace(/<[^>]+>/gu, " ")
    .replace(/\s+/gu, " ")
    .trim();

describe("what a change shows about owners", () => {
  it("names the account a new passkey belongs to, in full", () => {
    const html = renderToStaticMarkup(
      <ChangeDetails
        fleet={fleet([ME, ME, FRIEND])}
        change={change([...trusted, delta], [ME, ME, FRIEND, ME])}
      />,
    );
    expect(text(html)).toContain("Belongs to user1@example.com");
  });

  it("names both accounts of a move and what it means", () => {
    const html = renderToStaticMarkup(
      <ChangeDetails
        fleet={fleet([ME, ME, FRIEND])}
        change={change(trusted, [ME, FRIEND, FRIEND])}
      />,
    );
    expect(text(html)).toContain(
      "Bravo goes from user1@example.com to user2@example.com. Only user2@example.com signs with it afterwards.",
    );
    expect(text(html)).not.toContain("Nothing changes");
  });

  it("lists every owner when a change records them", () => {
    const html = renderToStaticMarkup(
      <ChangeDetails
        fleet={fleet(null)}
        change={change(trusted, [ME, ME, FRIEND])}
      />,
    );
    const seen = text(html);
    expect(seen).toContain("Owners");
    expect(seen).toContain("Alpha user1@example.com");
    expect(seen).toContain("Charlie user2@example.com");
    expect(seen).toContain(
      "Your servers store who owns each passkey from now on.",
    );
    expect(seen).not.toContain("Nothing changes");
  });
});

describe("the account a passkey moves to", () => {
  it("must be another address", () => {
    expect(accountProblem("", bravo)).toBe("");
    expect(accountProblem("user2@example.com", bravo)).toBeNull();
    expect(accountProblem(" user2@example.com ", bravo)).toBeNull();
    expect(accountProblem("user1@example.com", bravo)).toBe(
      "Bravo already belongs to this account.",
    );
    expect(accountProblem("user2", bravo)).toBe(
      "Enter the address that account signs in with.",
    );
    expect(accountProblem("user 2@example.com", bravo)).toBe(
      "Enter the address that account signs in with.",
    );
    expect(accountProblem(`${"a".repeat(250)}@b.cc`, bravo)).toBe(
      "Enter the address that account signs in with.",
    );
  });
});
