import { joinFingerprint, type NetworkDocument } from "@krynodes/protocol";
import { describe, expect, it } from "vitest";

import {
  checkAnchor,
  checkBase,
  hashOf,
  memoryStore,
  remember,
  type PinStore,
} from "./pins";

const S1 = "11111111-1111-4111-8111-111111111111";
const L1 = "33333333-3333-4333-8333-333333333333";
const SEAL = "s".repeat(87);
const HASH = "q".repeat(43);

const wgKey = () =>
  btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));

const member = (
  node: string,
  name: string,
  extra: Partial<NetworkDocument["members"][number]> = {},
): NetworkDocument["members"][number] => ({
  node,
  name,
  address: "10.88.37.14",
  key: wgKey(),
  signer: wgKey(),
  sealKey: SEAL,
  port: 51820,
  mtu: null,
  endpoint: null,
  nat: false,
  psk: {},
  ...extra,
});

const documentOf = (
  version: number,
  members: NetworkDocument["members"],
): NetworkDocument => ({
  v: 1,
  version,
  range: "10.88.37.0/24",
  port: 51820,
  mtu: 1420,
  members,
  blocked: [],
  allow: [],
});

const fingerprint = (one: NetworkDocument["members"][number]) =>
  joinFingerprint(one.key, one.signer, one.sealKey);

describe("the browser's own anchor", () => {
  it("lists every member this browser has not checked, with its fingerprint and where to compare it", async () => {
    const server = member(S1, "server-1");
    const laptop = member(L1, "laptop-1", { kind: "laptop", relay: {} });
    const unchecked = await checkAnchor(
      { document: documentOf(4, [server, laptop]), hash: HASH },
      memoryStore(),
    );
    expect(unchecked).toEqual([
      {
        node: S1,
        name: "server-1",
        fingerprint: await fingerprint(server),
        line: "Check that server-1 shows the same fingerprint: run sudo kry network fingerprint on it.",
      },
      {
        node: L1,
        name: "laptop-1",
        fingerprint: await fingerprint(laptop),
        line: "Check that laptop-1 shows the same fingerprint: in the tray, Fingerprint.",
      },
    ]);
  });

  it("passes members whose pins match and asks again, with a warning, for one whose keys changed", async () => {
    const store = memoryStore();
    const server = member(S1, "server-1");
    const current = { document: documentOf(4, [server]), hash: HASH };
    remember(store, [{ node: S1, fingerprint: await fingerprint(server) }], {
      version: 4,
      hash: HASH,
    });
    expect(await checkAnchor(current, store)).toEqual([]);
    const changed = { ...server, key: wgKey() };
    const swapped = {
      document: documentOf(5, [changed]),
      hash: "r".repeat(43),
    };
    expect(await checkAnchor(swapped, store)).toEqual([
      {
        node: S1,
        name: "server-1",
        fingerprint: await fingerprint(changed),
        line: "Check that server-1 shows the same fingerprint: run sudo kry network fingerprint on it.",
        warning:
          "server-1's keys changed since this browser last saw them. Check them on server-1 before you go on.",
      },
    ]);
  });

  it("refuses a document older than, or another than, the one this browser signed", async () => {
    const store = memoryStore();
    remember(store, [], { version: 6, hash: HASH });
    const older = { document: documentOf(5, []), hash: HASH };
    await expect(checkAnchor(older, store)).rejects.toThrow(
      "The network document is older than the one this browser last signed or checked. Nothing was signed.",
    );
    const other = { document: documentOf(6, []), hash: "r".repeat(43) };
    await expect(checkAnchor(other, store)).rejects.toThrow(
      "The network document is not the one this browser last signed or checked. Nothing was signed.",
    );
    expect(() =>
      checkBase({ document: documentOf(6, []), hash: HASH }, store),
    ).not.toThrow();
    expect(
      await checkAnchor(
        { document: documentOf(7, []), hash: "r".repeat(43) },
        store,
      ),
    ).toEqual([]);
  });

  it("never lowers the version it keeps", () => {
    const store = memoryStore();
    remember(store, [], { version: 6, hash: HASH });
    remember(store, [], { version: 3, hash: "r".repeat(43) });
    expect(() =>
      checkBase({ document: documentOf(6, []), hash: HASH }, store),
    ).not.toThrow();
  });

  it("keeps only fingerprints and hashes", async () => {
    const store = memoryStore();
    const server = member(S1, "server-1");
    remember(store, [{ node: S1, fingerprint: await fingerprint(server) }], {
      version: 4,
      hash: HASH,
    });
    const kept = JSON.parse(
      store.getItem("krynodes:network-anchor")!,
    ) as unknown;
    expect(kept).toEqual({
      pins: { [S1]: await fingerprint(server) },
      version: 4,
      hash: HASH,
    });
  });

  it("treats every member as unchecked when storage is missing, broken or throws", async () => {
    const server = member(S1, "server-1");
    const current = { document: documentOf(4, [server]), hash: HASH };
    const throwing: PinStore = {
      getItem: () => {
        throw new Error("blocked");
      },
      setItem: () => {
        throw new Error("blocked");
      },
    };
    const broken = memoryStore();
    broken.setItem("krynodes:network-anchor", "{not json");
    for (const store of [null, throwing, broken]) {
      expect(await checkAnchor(current, store)).toHaveLength(1);
    }
    for (const store of [null, throwing]) {
      expect(() =>
        remember(store, [{ node: S1, fingerprint: "x" }]),
      ).not.toThrow();
      expect(await checkAnchor(current, store)).toHaveLength(1);
    }
  });

  it("hashes a document the way it is signed", async () => {
    const document = documentOf(4, []);
    expect(await hashOf(document)).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(await hashOf(document)).toBe(await hashOf(documentOf(4, [])));
  });
});
