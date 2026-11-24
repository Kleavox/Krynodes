import { describe, expect, it } from "vitest";

import fixture from "./fixtures/wire.json";
import { parseAgentMessage, parseHubMessage, WIRE_VERSION } from "./wire";

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
