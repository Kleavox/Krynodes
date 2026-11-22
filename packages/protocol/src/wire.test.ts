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
