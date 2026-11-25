import { describe, expect, it } from "vitest";

import fixture from "./fixtures/stack-args.json";
import { STACK_ACTIONS, stackArgsValid, type StackKind } from "./stacks";

describe("the actions on stacks, containers, units and Docker", () => {
  it("are exactly the ones the owner can sign", () => {
    expect(STACK_ACTIONS).toEqual({
      stack: [
        "create",
        "deploy",
        "edit",
        "read",
        "rollback",
        "start",
        "stop",
        "restart",
        "remove",
        "restore",
        "purge",
        "adopt",
        "logs",
      ],
      container: ["start", "stop", "restart", "logs"],
      unit: ["start", "stop", "restart"],
      docker: ["install"],
    });
  });
});

const kindOf = (kind: string) => kind as StackKind;

describe("the arguments of a stack action", () => {
  it("holds a fixture of both kinds", () => {
    expect(fixture.valid.length).toBeGreaterThan(10);
    expect(fixture.invalid.length).toBeGreaterThan(30);
  });

  it("names the kind of every entry, and every kind has a valid one", () => {
    const named = [...fixture.valid, ...fixture.invalid];
    expect(named.every((entry) => typeof entry.kind === "string")).toBe(true);
    for (const kind of Object.keys(STACK_ACTIONS)) {
      expect(
        fixture.valid.some((entry) => entry.kind === kind),
        kind,
      ).toBe(true);
    }
  });

  it.each(fixture.valid)("takes $kind $action %#", ({ kind, action, args }) => {
    expect(stackArgsValid(kindOf(kind), action, args)).toBe(true);
  });

  it.each(fixture.invalid)(
    "refuses $kind $action with $why",
    ({ kind, action, args }) => {
      expect(stackArgsValid(kindOf(kind), action, args)).toBe(false);
    },
  );

  it("counts a compose in bytes, not characters", () => {
    const save = (compose: string) => ({
      compose,
      access: "contained",
      network: "",
    });
    expect(
      stackArgsValid("stack", "create", save("€".repeat(10922) + "ab")),
    ).toBe(true);
    expect(stackArgsValid("stack", "create", save("€".repeat(10923)))).toBe(
      false,
    );
  });

  it("takes every verb of every kind with its own arguments only", () => {
    for (const kind of Object.keys(STACK_ACTIONS) as StackKind[]) {
      for (const action of STACK_ACTIONS[kind]) {
        const own =
          (kind === "stack" &&
            (action === "create" || action === "edit" || action === "adopt")) ||
          action === "logs";
        const label = `${kind}/${action}`;
        expect(stackArgsValid(kind, action, {}), label).toBe(!own);
        expect(stackArgsValid(kind, action, { extra: "1" }), label).toBe(false);
      }
    }
  });

  it("refuses a verb that is not in the list of its kind", () => {
    const all = new Set<string>(Object.values(STACK_ACTIONS).flat());
    for (const kind of Object.keys(STACK_ACTIONS) as StackKind[]) {
      const own: readonly string[] = STACK_ACTIONS[kind];
      for (const action of [...all, "export", ""]) {
        if (own.includes(action)) continue;
        for (const args of [{}, { lines: "1" }]) {
          expect(stackArgsValid(kind, action, args), `${kind}/${action}`).toBe(
            false,
          );
        }
      }
    }
    expect(stackArgsValid(kindOf("pod"), "start", {})).toBe(false);
    expect(stackArgsValid(kindOf("toString"), "start", {})).toBe(false);
  });

  it("takes arguments that are a plain object and nothing else", () => {
    const fake = (value: unknown) => stackArgsValid("stack", "deploy", value);
    expect(fake({})).toBe(true);
    expect(fake(Object.create(null))).toBe(true);
    for (const value of [
      null,
      undefined,
      [],
      [{}],
      "",
      "x",
      0,
      true,
      new Map(),
      new Date(),
      new (class Args {})(),
      () => ({}),
    ]) {
      expect(fake(value), String(value)).toBe(false);
    }
    expect(stackArgsValid("stack", "logs", null)).toBe(false);
    expect(stackArgsValid("container", "logs", [])).toBe(false);
  });

  it("refuses a key that only the prototype knows", () => {
    for (const key of ["toString", "constructor", "hasOwnProperty"]) {
      expect(stackArgsValid("stack", "deploy", { [key]: "x" }), key).toBe(
        false,
      );
      expect(
        stackArgsValid("stack", "logs", { lines: "5", [key]: "x" }),
        key,
      ).toBe(false);
    }
    const polluted = JSON.parse('{"lines":"5","__proto__":"x"}') as unknown;
    expect(stackArgsValid("stack", "logs", polluted)).toBe(false);
  });

  it("refuses a value that is not a string", () => {
    expect(stackArgsValid("stack", "logs", { lines: 5 })).toBe(false);
    expect(stackArgsValid("stack", "logs", { lines: null })).toBe(false);
    expect(
      stackArgsValid("stack", "create", {
        compose: "services: {}",
        access: "full",
        network: 80,
      }),
    ).toBe(false);
  });

  it("holds a sealed env to ASCII, so its length reads the same everywhere", () => {
    const save = (env: string) => ({
      compose: "services: {}",
      access: "contained",
      network: "",
      env,
    });
    const holds = (env: string) => stackArgsValid("stack", "create", save(env));
    expect(holds("A".repeat(24576))).toBe(true);
    expect(holds("A".repeat(24577))).toBe(false);
    expect(holds("Zm9v-_")).toBe(true);
    expect(holds("é")).toBe(false);
    expect(holds("A".repeat(24575) + "é")).toBe(false);
    expect(holds("Zm9v+/")).toBe(false);
    expect(holds("Zm9v=")).toBe(false);
    expect(holds("")).toBe(false);
  });

  it("refuses the same port twice", () => {
    const serve = (network: string) =>
      stackArgsValid("stack", "edit", {
        compose: "services: {}",
        access: "contained",
        network,
      });
    expect(serve("80,443")).toBe(true);
    expect(serve("80,80")).toBe(false);
    expect(serve("80,443,80")).toBe(false);
  });
});
