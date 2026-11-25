import { describe, expect, it } from "vitest";

import fixture from "./fixtures/wire.json";
import { NETWORK_VERBS } from "./network";
import { STACK_ACTIONS } from "./stacks";
import {
  COMMAND_ACTIONS,
  COMMAND_KINDS,
  parseAgentMessage,
  parseHubMessage,
  WIRE_VERSION,
} from "./wire";

const raw = (message: unknown) => JSON.stringify(message);

describe("the wire between the agent and the hub", () => {
  it("is version 1", () => {
    expect(WIRE_VERSION).toBe(1);
  });

  it.each(fixture.agent.valid)("reads the agent message %#", (message) => {
    expect(parseAgentMessage(raw(message))).toEqual(message);
  });

  it.each(fixture.agent.invalid)("refuses $why", ({ message }) => {
    expect(parseAgentMessage(raw(message))).toBeNull();
  });

  it.each(fixture.hub.valid)("reads the hub message %#", (message) => {
    expect(parseHubMessage(raw(message))).toEqual(message);
  });

  it.each(fixture.hub.invalid)("refuses $why", ({ message }) => {
    expect(parseHubMessage(raw(message))).toBeNull();
  });

  it("refuses what is not JSON, and JSON that is not an object", () => {
    for (const text of ["", "{", "null", "7", '"hello"', "[]"]) {
      expect(parseAgentMessage(text), text).toBeNull();
      expect(parseHubMessage(text), text).toBeNull();
    }
  });

  it("marks every refused entry as structural or not", () => {
    for (const side of [fixture.agent, fixture.hub]) {
      for (const entry of side.invalid) {
        expect(typeof entry.structural, entry.why).toBe("boolean");
      }
    }
  });
});

describe("the network messages", () => {
  const KEY = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";
  const NODE = "11111111-1111-4111-8111-111111111111";
  const key = (n: number) => `${String(n).padStart(42, "A")}A=`;
  const link = (n: number) => ({
    key: key(n),
    handshake: null,
    rx: 0,
    tx: 0,
    endpoint: null,
    ms: null,
  });
  const hints = (overrides: Record<string, unknown> = {}) => ({
    type: "hints",
    endpoints: [],
    announced: [],
    meetings: [],
    held: [],
    connected: [],
    ...overrides,
  });
  const command = (action: string) => ({
    type: "command",
    id: "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a01",
    kind: "network",
    name: "kry0",
    action,
    signed: "eyJjb21tYW5kIjoiYyJ9",
  });
  const read = (message: unknown) => parseHubMessage(raw(message)) !== null;

  it("takes exactly 32 links and 32 of every hint", () => {
    expect(
      parseAgentMessage(
        raw({
          type: "links",
          links: Array.from({ length: 32 }, (_, i) => link(i + 1)),
        }),
      ),
    ).not.toBeNull();
    const makes: Record<string, (n: number) => unknown> = {
      endpoints: (n) => ({ key: key(n), endpoint: "203.0.113.1:1" }),
      announced: (n) => ({ node: NODE, key: key(n), signature: "c2ln" }),
      meetings: () => ({ laptop: NODE, via: NODE }),
      held: () => NODE,
      connected: () => NODE,
    };
    for (const [name, make] of Object.entries(makes)) {
      const list = (size: number) =>
        Array.from({ length: size }, (_, i) => make(i + 1));
      expect(read(hints({ [name]: list(32) })), name).toBe(true);
      expect(read(hints({ [name]: list(33) })), name).toBe(false);
    }
  });

  it("takes a signed document of 524288 characters and no more", () => {
    const document = (size: number) => ({
      type: "document",
      version: 1,
      signed: "a".repeat(size),
    });
    expect(read(document(524288))).toBe(true);
    expect(read(document(524289))).toBe(false);
  });

  it("takes exactly the seven network actions", () => {
    for (const action of [
      "inspect",
      "probe",
      "test",
      "prepare",
      "unprepare",
      "rekey",
      "drop",
    ]) {
      expect(read(command(action)), action).toBe(true);
    }
    for (const action of ["tighten", "apply", "INSPECT", "inspect ", ""]) {
      expect(read(command(action)), action).toBe(false);
    }
    expect(read({ ...command("restart"), kind: "host" })).toBe(true);
  });

  it("takes a network report of 300 characters and a key of the right length", () => {
    const hello = fixture.agent.valid[0]!;
    const network = (change: Record<string, unknown>) => ({
      ...hello,
      network: { version: 0, key: KEY, signer: KEY, ready: false, ...change },
    });
    expect(
      parseAgentMessage(raw(network({ reason: "r".repeat(300) }))),
    ).not.toBeNull();
    expect(
      parseAgentMessage(raw(network({ reason: "r".repeat(301) }))),
    ).toBeNull();
    expect(
      parseAgentMessage(raw(network({ reason: null, signer: KEY.slice(1) }))),
    ).toBeNull();
  });
});

describe("the stack messages", () => {
  const HASH = "0".repeat(64);
  const many = <T>(size: number, make: (n: number) => T) =>
    Array.from({ length: size }, (_, i) => make(i + 1));
  const stack = (over: Record<string, unknown> = {}) => ({
    project: "web",
    title: null,
    directory: "/var/lib/krynodes/stacks/web",
    own: true,
    access: "contained",
    running: 0,
    total: 0,
    rollback: false,
    network: [],
    services: [],
    ...over,
  });
  const container = (over: Record<string, unknown> = {}) => ({
    name: "web-app-1",
    project: null,
    service: null,
    image: "busybox",
    state: "running",
    health: null,
    ports: [],
    ...over,
  });
  const inventory = (over: Record<string, unknown> = {}) => ({
    type: "inventory",
    hash: HASH,
    docker: "ready",
    compose: null,
    stacks: [],
    containers: [],
    units: [],
    removed: [],
    ...over,
  });
  const fromAgent = (message: unknown) =>
    parseAgentMessage(raw(message)) !== null;
  const fromHub = (message: unknown) => parseHubMessage(raw(message)) !== null;
  const command = (kind: string, action: string) => ({
    type: "command",
    id: "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a01",
    kind,
    name: "web",
    action,
    signed: "eyJjb21tYW5kIjoiYyJ9",
  });

  it("takes exactly the verbs of every kind of command", () => {
    expect(COMMAND_KINDS).toEqual([
      "trust",
      "agent",
      "host",
      "network",
      "stack",
      "container",
      "unit",
      "docker",
    ]);
    for (const kind of COMMAND_KINDS) {
      const verbs = COMMAND_ACTIONS[kind];
      expect(verbs.length, kind).toBeGreaterThan(0);
      for (const action of verbs) {
        expect(fromHub(command(kind, action)), `${kind}/${action}`).toBe(true);
      }
      for (const action of ["export", "reboot", "STOP", ""]) {
        expect(fromHub(command(kind, action)), `${kind}/${action}`).toBe(false);
      }
    }
    expect(COMMAND_ACTIONS.stack).toBe(STACK_ACTIONS.stack);
    expect(Object.isFrozen(NETWORK_VERBS)).toBe(true);
    expect(COMMAND_ACTIONS.network).toBe(NETWORK_VERBS);
    expect(() => (NETWORK_VERBS as string[]).push("tighten")).toThrow();
    expect(fromHub(command("network", "tighten"))).toBe(false);
    expect(COMMAND_ACTIONS.network).toContain("inspect");
    expect(COMMAND_ACTIONS.network).not.toContain("tighten");
    expect(fromHub(command("unit", "deploy"))).toBe(false);
    expect(fromHub(command("container", "remove"))).toBe(false);
    expect(fromHub(command("pod", "start"))).toBe(false);
  });

  it("takes an inventory of 64 stacks, 256 containers, 256 units and 64 removed", () => {
    const limits: Record<string, [string, (n: number) => unknown, number]> = {
      stacks: ["stacks", (n) => stack({ project: `web-${n}` }), 64],
      containers: ["containers", (n) => container({ name: `web-${n}` }), 256],
      units: [
        "units",
        (n) => ({ name: `u${n}.service`, state: "running", protected: false }),
        256,
      ],
      removed: [
        "removed",
        (n) => ({ project: `old-${n}`, removedAt: "2026-11-20T08:30:00Z" }),
        64,
      ],
    };
    for (const [name, [key, make, size]] of Object.entries(limits)) {
      expect(fromAgent(inventory({ [key]: many(size, make) })), name).toBe(
        true,
      );
      expect(fromAgent(inventory({ [key]: many(size + 1, make) })), name).toBe(
        false,
      );
    }
  });

  it("takes the sizes of an entry and no more", () => {
    const holds = (
      make: (value: unknown) => unknown,
      good: unknown,
      bad: unknown,
      why: string,
    ) => {
      expect(fromAgent(make(good)), `${why} at its limit`).toBe(true);
      expect(fromAgent(make(bad)), `${why} over its limit`).toBe(false);
    };
    const inStack = (key: string) => (value: unknown) =>
      inventory({ stacks: [stack({ [key]: value })] });
    const inContainer = (key: string) => (value: unknown) =>
      inventory({ containers: [container({ [key]: value })] });
    holds(
      inStack("directory"),
      "d".repeat(4096),
      "d".repeat(4097),
      "directory",
    );
    holds(
      inStack("network"),
      many(32, (n) => n),
      many(33, (n) => n),
      "ports",
    );
    holds(inStack("network"), [65535], [65536], "port 65535");
    holds(inStack("network"), [1], [0], "port 1");
    holds(
      inStack("services"),
      many(64, (n) => ({ service: `s${n}`, container: `web-s${n}` })),
      many(65, (n) => ({ service: `s${n}`, container: `web-s${n}` })),
      "services",
    );
    holds(inContainer("image"), "i".repeat(512), "i".repeat(513), "image");
    holds(
      inContainer("ports"),
      many(32, () => "p".repeat(128)),
      many(33, () => "p"),
      "ports of a container",
    );
    holds(
      inContainer("ports"),
      ["p".repeat(128)],
      ["p".repeat(129)],
      "a port text",
    );
    holds(
      (value) => inventory({ compose: value }),
      "c".repeat(64),
      "c".repeat(65),
      "compose version",
    );
    holds(
      (value) => ({ ...inventory(), hash: value }),
      "abcdef0123456789".repeat(4),
      "abcdef0123456789".repeat(4) + "0",
      "hash",
    );
  });

  it("refuses a name that could not be a project, a container or a unit", () => {
    expect(fromAgent(inventory({ stacks: [stack({ project: "Web" })] }))).toBe(
      false,
    );
    expect(
      fromAgent(inventory({ containers: [container({ name: "a b" })] })),
    ).toBe(false);
    expect(
      fromAgent(inventory({ containers: [container({ project: "../x" })] })),
    ).toBe(false);
    expect(
      fromAgent(
        inventory({
          units: [{ name: "-x.service", state: "running", protected: false }],
        }),
      ),
    ).toBe(false);
    expect(
      fromAgent(
        inventory({
          removed: [{ project: "Old", removedAt: "2026-11-20T08:30:00Z" }],
        }),
      ),
    ).toBe(false);
    expect(
      fromAgent(
        inventory({ removed: [{ project: "old", removedAt: "yesterday" }] }),
      ),
    ).toBe(false);
  });

  it("takes 64 checks, each a container name", () => {
    const names = (size: number) => many(size, (n) => `web-${n}`);
    expect(fromHub({ type: "checks", names: names(64) })).toBe(true);
    expect(fromHub({ type: "checks", names: names(65) })).toBe(false);
    expect(fromHub({ type: "checks", names: ["a"] })).toBe(false);
    expect(fromHub({ type: "checks", names: ["web-app-1", 7] })).toBe(false);
    expect(fromHub({ type: "checks" })).toBe(false);
  });

  it("takes a check at its three states and with no time but a real one", () => {
    const check = (over: Record<string, unknown>) => ({
      type: "check",
      name: "web-app-1",
      state: "up",
      cause: null,
      at: "2026-11-24T10:15:00Z",
      detail: "",
      ...over,
    });
    for (const state of ["up", "down", "gone"]) {
      expect(fromAgent(check({ state })), state).toBe(true);
    }
    expect(fromAgent(check({ cause: "owner" }))).toBe(true);
    expect(fromAgent(check({ at: "2026-11-24" }))).toBe(false);
    expect(fromAgent(check({ at: "not a time" }))).toBe(false);
    expect(fromAgent(check({ name: "-web" }))).toBe(false);
  });
});
