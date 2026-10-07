import { describe, expect, it } from "vitest";

import type { DeviceRecord, NodeRecord, NodeTrust } from "../types";
import {
  accessChange,
  accessIds,
  admitChange,
  appliedOn,
  buildChange,
  canRestartServer,
  decodeChange,
  describeChange,
  fingerprint,
  firstTrusts,
  formatPrint,
  nextVersion,
  predictMissing,
  removeChange,
  serverState,
  twinOf,
  signersFor,
  syncChange,
  type FleetView,
} from "./devices";

const T = Date.parse("2026-09-29T10:00:00.000Z");
const ORIGIN = "https://kry.example.test";
const N1 = "11111111-1111-4111-8111-111111111111";
const N2 = "22222222-2222-4222-8222-222222222222";
const N3 = "33333333-3333-4333-8333-333333333333";

const node = (id: string, agent = "0.6.0") =>
  ({
    id,
    name: id.slice(0, 2),
    agent_version: agent,
    enrolled_at: "2026-09-29 09:00:00",
    disabled_at: null,
  }) as NodeRecord;

const device = (id: string, core = true): DeviceRecord => ({
  id,
  name: id[0]!.toUpperCase() + id.slice(1),
  alg: -7,
  publicKey: `${id}-key`,
  createdAt: "2026-09-29T09:00:00.000Z",
  lastUsedAt: null,
  verifies: true,
  fingerprint: `${id}-print`.padEnd(16, "0").slice(0, 16),
  core,
});

const trust = (
  version: number,
  core: DeviceRecord[],
  access: DeviceRecord[],
): NodeTrust => ({
  version,
  core: core.map((entry) => entry.fingerprint),
  access: access.map((entry) => entry.fingerprint),
});

const laptop = device("laptop");
const phone = device("phone");
const tablet = device("tablet", false);

function view(
  devices: DeviceRecord[],
  servers: { node: NodeRecord; trust: NodeTrust | null }[],
): FleetView {
  return { devices, servers, origin: ORIGIN };
}

const bytes = (text: string) =>
  JSON.parse(atob(text.replaceAll("-", "+").replaceAll("_", "/"))) as Record<
    string,
    unknown
  >;

describe("fingerprints", () => {
  it("fingerprints a key the way the agent does", async () => {
    expect(await fingerprint("AQID")).toBe("039058c6f2c0cb49");
  });

  it("groups a fingerprint for reading aloud", () => {
    expect(formatPrint("a1b2c3d4e5f6a7b8")).toBe("A1B2 C3D4 E5F6 A7B8");
  });
});

describe("access", () => {
  it("maps a server's access to device ids", () => {
    expect(
      accessIds([laptop, phone], trust(2, [laptop, phone], [phone])),
    ).toEqual(["phone"]);
    expect(accessIds([laptop], null)).toEqual([]);
  });

  it("opens a session only with devices every target lets in", () => {
    const tabletCore = { ...tablet, core: true };
    const devices = [laptop, phone, tabletCore];
    expect(
      signersFor(devices, [
        trust(2, devices, [laptop, phone]),
        trust(2, devices, [phone, tabletCore]),
      ]),
    ).toEqual(["phone"]);
    expect(signersFor(devices, [null])).toEqual([]);
    expect(signersFor(devices, [])).toEqual([]);
  });

  it("offers a server restart to a current agent with access", () => {
    const own = trust(1, [laptop], [laptop]);
    expect(canRestartServer(node(N1, "0.6.0"), own)).toBe(true);
    expect(canRestartServer(node(N1, "0.4.1"), own)).toBe(false);
    expect(canRestartServer(node(N1), trust(1, [laptop], []))).toBe(false);
    expect(canRestartServer(node(N1), null)).toBe(false);
  });
});

describe("server state", () => {
  it("sorts servers into update, empty, behind and current", () => {
    const fleet = view(
      [laptop, phone],
      [
        { node: node(N1, "0.4.1"), trust: trust(1, [laptop], [laptop]) },
        { node: node(N2), trust: null },
        { node: node(N3), trust: trust(2, [laptop], [laptop]) },
      ],
    );
    expect(fleet.servers.map((entry) => serverState(fleet, entry))).toEqual([
      "update",
      "empty",
      "behind",
    ]);
    const current = view(
      [laptop, phone],
      [{ node: node(N1), trust: trust(3, [laptop, phone], []) }],
    );
    expect(serverState(current, current.servers[0]!)).toBe("current");
  });

  it("asks for agent 0.6.0 before devices can change", () => {
    const fleet = view(
      [laptop, phone],
      [
        { node: node(N1, "0.4.1"), trust: trust(3, [laptop, phone], []) },
        { node: node(N2, "dev"), trust: trust(3, [laptop, phone], []) },
      ],
    );
    expect(fleet.servers.map((entry) => serverState(fleet, entry))).toEqual([
      "update",
      "current",
    ]);
  });

  it("the next version beats every server", () => {
    expect(
      nextVersion(
        view(
          [laptop],
          [
            { node: node(N1), trust: trust(2, [laptop], []) },
            { node: node(N2), trust: trust(5, [laptop], []) },
            { node: node(N3), trust: null },
          ],
        ),
      ),
    ).toBe(6);
    expect(nextVersion(view([laptop], []))).toBe(2);
  });
});

describe("changes", () => {
  const two = view(
    [laptop, phone, tablet],
    [
      { node: node(N1), trust: trust(4, [laptop, phone], [laptop, phone]) },
      { node: node(N2), trust: trust(4, [laptop, phone], [laptop]) },
      { node: node(N3), trust: null },
    ],
  );

  it("encodes a change as the exact bytes the servers read", () => {
    const text = buildChange(two, {
      core: null,
      access: { [N1]: ["laptop"] },
      now: T,
    });
    expect(bytes(text)).toEqual({
      v: 2,
      origin: ORIGIN,
      rpId: "kry.example.test",
      version: 5,
      issuedAt: new Date(T).toISOString(),
      expiresAt: new Date(T + 24 * 3_600_000).toISOString(),
      core: null,
      passphrase: null,
      access: { [N1]: ["laptop"] },
    });
    expect(decodeChange(text)).toEqual(bytes(text));
    expect(decodeChange("bm90IGpzb24")).toBeNull();
    expect(decodeChange(btoa(JSON.stringify({ v: 1 })))).toBeNull();
  });

  it("admits a third device into the core without access", () => {
    const change = admitChange(two, tablet);
    expect(change.core?.map((key) => key.id)).toEqual([
      "laptop",
      "phone",
      "tablet",
    ]);
    expect(change.core?.[2]).toEqual({
      id: "tablet",
      name: "Tablet",
      alg: -7,
      publicKey: "tablet-key",
    });
    expect(change.access).toEqual({
      [N1]: ["laptop", "phone"],
      [N2]: ["laptop"],
    });
  });

  it("skips a waiting device that holds the same passkey as a trusted one", () => {
    const twin = {
      ...device("phone-again", false),
      publicKey: phone.publicKey,
    };
    const fleet = view(
      [laptop, phone, twin],
      [{ node: node(N1), trust: trust(4, [laptop, phone], [laptop]) }],
    );
    expect(twinOf(fleet, twin)?.id).toBe("phone");
    expect(twinOf(fleet, tablet)).toBeNull();
    expect(admitChange(fleet, twin).core?.map((key) => key.id)).toEqual([
      "laptop",
      "phone",
    ]);
  });

  it("admits the second device with access to every trusted server (founding)", () => {
    const one = view(
      [laptop, { ...phone, core: false }],
      [
        { node: node(N1), trust: trust(1, [laptop], [laptop]) },
        { node: node(N2), trust: trust(1, [laptop], [laptop]) },
      ],
    );
    expect(admitChange(one, phone).access).toEqual({
      [N1]: ["laptop", "phone"],
      [N2]: ["laptop", "phone"],
    });
  });

  it("removes a core device and its access everywhere", () => {
    const change = removeChange(two, phone);
    expect(change.core?.map((key) => key.id)).toEqual(["laptop"]);
    expect(change.access).toEqual({ [N1]: ["laptop"], [N2]: ["laptop"] });
  });

  it("changes access only on the servers that differ", () => {
    expect(
      accessChange(two, {
        [N1]: ["phone", "laptop"],
        [N2]: ["laptop", "phone"],
      }),
    ).toEqual({
      core: null,
      access: { [N2]: ["laptop", "phone"] },
    });
    expect(accessChange(two, { [N1]: ["laptop", "phone"] }).access).toEqual({});
  });

  it("syncs servers that missed a change with the devices and access only", () => {
    const behind = view(
      [laptop, phone],
      [
        { node: node(N1), trust: trust(4, [laptop, phone], [laptop]) },
        { node: node(N2), trust: trust(3, [laptop], [laptop]) },
      ],
    );
    const change = syncChange(behind);
    expect(change.core?.map((key) => key.id)).toEqual(["laptop", "phone"]);
    expect(change.access).toEqual({ [N1]: ["laptop"], [N2]: ["laptop"] });
    expect(change).not.toHaveProperty("requireUv");
    expect(bytes(buildChange(behind, { ...change, now: T }))).toMatchObject({
      passphrase: null,
    });
  });

  it("first trust sends the core with founding access, one server each", () => {
    const fresh = view(
      [{ ...laptop, core: false }],
      [
        { node: node(N1), trust: null },
        { node: node(N2), trust: null },
      ],
    );
    const [first, second] = firstTrusts(fresh, [N1, N2], "laptop", T).map(
      bytes,
    );
    expect(first).toMatchObject({
      version: 1,
      core: [{ id: "laptop" }],
      passphrase: null,
      requireUv: true,
      access: { [N1]: ["laptop"] },
    });
    expect(second?.access).toEqual({ [N2]: ["laptop"] });
    const later = view(
      [laptop, phone],
      [
        { node: node(N1), trust: trust(4, [laptop, phone], [laptop]) },
        { node: node(N3), trust: null },
      ],
    );
    expect(bytes(firstTrusts(later, [N3], "laptop", T)[0]!)).toMatchObject({
      version: 1,
      core: [{ id: "laptop" }, { id: "phone" }],
      passphrase: null,
      requireUv: true,
      access: { [N3]: [] },
    });
  });

  it("describes a change from its bytes with names and per-server access", () => {
    const text = buildChange(two, { ...admitChange(two, tablet), now: T });
    const summary = describeChange(two, decodeChange(text)!);
    expect(summary.title).toBe("Admit Tablet");
    const grant = buildChange(two, {
      core: null,
      access: { [N2]: ["laptop", "phone"] },
      now: T,
    });
    expect(describeChange(two, decodeChange(grant)!)).toMatchObject({
      title: "Give Phone access to 22",
      access: [{ nodeId: N2, added: ["phone"], removed: [] }],
    });
  });
});

describe("prediction", () => {
  const fleet = view(
    [laptop, phone, tablet],
    [
      { node: node(N1), trust: trust(4, [laptop, phone], [laptop]) },
      { node: node(N2), trust: trust(4, [laptop, phone], []) },
    ],
  );

  it("says what the approvers still miss, the way servers count", () => {
    const admit = decodeChange(
      buildChange(fleet, { ...admitChange(fleet, tablet), now: T }),
    )!;
    expect(predictMissing(fleet, admit, ["laptop"])).toBeNull();
    const helper = device("helper", false);
    const three = view(
      [laptop, phone, tablet, helper],
      [{ node: node(N1), trust: trust(4, [laptop, phone, tablet], [laptop]) }],
    );
    const fourth = decodeChange(
      buildChange(three, { ...admitChange(three, helper), now: T }),
    )!;
    expect(predictMissing(three, fourth, ["laptop"])).toBe(
      "needs 1 more approval",
    );
    expect(predictMissing(three, fourth, ["laptop", "phone"])).toBeNull();
    const grant = decodeChange(
      buildChange(fleet, {
        ...accessChange(fleet, { [N1]: ["laptop", "phone"], [N2]: ["phone"] }),
        now: T,
      }),
    )!;
    expect(predictMissing(fleet, grant, ["phone"])).toBe(
      "needs approval from another device that reaches this server",
    );
    expect(predictMissing(fleet, grant, ["laptop"])).toBeNull();
  });
});

describe("fingerprint, always", () => {
  it("lets the other device remove one that cannot verify while there are two", () => {
    const touch = { ...laptop, verifies: false };
    const pair = view(
      [touch, phone],
      [{ node: node(N1), trust: trust(4, [touch, phone], [touch, phone]) }],
    );
    const change = decodeChange(
      buildChange(pair, { ...removeChange(pair, touch), now: T }),
    )!;
    expect(change.core?.map((key) => key.id)).toEqual(["phone"]);
    expect(predictMissing(pair, change, ["phone"])).toBeNull();
    expect(describeChange(pair, change).title).toBe("Remove Laptop");
  });
});

describe("recent changes", () => {
  it("counts the servers that took an applied change, ignoring removed ones", () => {
    const fleet = view(
      [laptop, phone],
      [
        { node: node(N1), trust: trust(5, [laptop, phone], [laptop]) },
        { node: node(N2), trust: trust(4, [laptop, phone], [laptop]) },
      ],
    );
    expect(appliedOn(fleet, { version: 5, targets: [N1, N2, N3] })).toEqual({
      done: 1,
      total: 2,
    });
    expect(appliedOn(fleet, { version: 4, targets: [N1, N2] })).toEqual({
      done: 2,
      total: 2,
    });
  });
});
