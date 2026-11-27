import { describe, expect, it } from "vitest";

import sealed from "./fixtures/sealed-output.json";
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

const to = sealed.to;

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

  it("holds a sealed compose to ASCII, so its length reads the same everywhere", () => {
    const holds = (compose: string) =>
      stackArgsValid("stack", "create", {
        compose,
        access: "contained",
        network: "",
        to,
      });
    expect(holds("A".repeat(58464))).toBe(true);
    expect(holds("A".repeat(58465))).toBe(false);
    expect(holds("Zm9v-_")).toBe(true);
    expect(holds("é")).toBe(false);
    expect(holds("A".repeat(58463) + "é")).toBe(false);
    expect(holds("Zm9v+/")).toBe(false);
    expect(holds("Zm9v=")).toBe(false);
    expect(holds("")).toBe(false);
    expect(holds("services:\n  app:\n    image: nginx:1.27\n")).toBe(false);
  });

  it("takes the sealed form of a 32768-byte compose and no more", () => {
    const text = (value: string) =>
      btoa(value).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
    const sealedOf = (size: number) =>
      text(
        JSON.stringify({
          v: 1,
          epk: text("e".repeat(65)),
          iv: text("i".repeat(12)),
          ct: text("c".repeat(size + 16)),
        }),
      );
    const holds = (compose: string) =>
      stackArgsValid("stack", "edit", {
        compose,
        access: "contained",
        network: "",
        to,
      });
    expect(sealedOf(32768)).toHaveLength(58463);
    expect(holds(sealedOf(32768))).toBe(true);
    expect(holds(sealedOf(32769))).toBe(false);
  });

  it("takes every verb of every kind with its own arguments only", () => {
    for (const kind of Object.keys(STACK_ACTIONS) as StackKind[]) {
      for (const action of STACK_ACTIONS[kind]) {
        const own =
          (kind === "stack" &&
            (action === "create" || action === "edit" || action === "adopt")) ||
          action === "logs";
        const sealed = kind === "stack" || kind === "container";
        const label = `${kind}/${action}`;
        expect(stackArgsValid(kind, action, {}), label).toBe(!sealed);
        expect(stackArgsValid(kind, action, { to }), label).toBe(
          sealed && !own,
        );
        expect(stackArgsValid(kind, action, { extra: "1" }), label).toBe(false);
        expect(stackArgsValid(kind, action, { to, extra: "1" }), label).toBe(
          false,
        );
      }
    }
  });

  it("needs a key on every stack and container verb, and takes none on a unit or Docker", () => {
    const covered = new Set<string>();
    for (const { kind, action, args } of fixture.valid) {
      const given = args as Record<string, string>;
      if (kind === "stack" || kind === "container") {
        expect(given.to, `${kind}/${action}`).toBeTypeOf("string");
        const { to: _key, ...without } = given;
        expect(stackArgsValid(kindOf(kind), action, without)).toBe(false);
        covered.add(`${kind}/${action}`);
      } else {
        expect(stackArgsValid(kindOf(kind), action, { ...given, to })).toBe(
          false,
        );
      }
    }
    for (const kind of ["stack", "container"] as const) {
      for (const action of STACK_ACTIONS[kind]) {
        expect(covered.has(`${kind}/${action}`), `${kind}/${action}`).toBe(
          true,
        );
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
    expect(fake({ to })).toBe(true);
    expect(fake(Object.assign(Object.create(null), { to }))).toBe(true);
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
        stackArgsValid("stack", "logs", { lines: "5", to, [key]: "x" }),
        key,
      ).toBe(false);
    }
    const polluted = JSON.parse(
      `{"lines":"5","to":"${to}","__proto__":"x"}`,
    ) as unknown;
    expect(stackArgsValid("stack", "logs", polluted)).toBe(false);
  });

  it("refuses a value that is not a string", () => {
    expect(stackArgsValid("stack", "logs", { lines: 5, to })).toBe(false);
    expect(stackArgsValid("stack", "logs", { lines: null, to })).toBe(false);
    expect(stackArgsValid("stack", "read", { to: 87 })).toBe(false);
    expect(
      stackArgsValid("stack", "create", {
        compose: "c2VhbGVk",
        access: "full",
        network: 80,
      }),
    ).toBe(false);
  });

  it("holds a sealed env to ASCII, so its length reads the same everywhere", () => {
    const save = (env: string) => ({
      compose: "c2VhbGVk",
      access: "contained",
      network: "",
      env,
      to,
    });
    const holds = (env: string) => stackArgsValid("stack", "create", save(env));
    expect(holds("A".repeat(29337))).toBe(true);
    expect(holds("A".repeat(29338))).toBe(false);
    expect(holds("Zm9v-_")).toBe(true);
    expect(holds("é")).toBe(false);
    expect(holds("A".repeat(29336) + "é")).toBe(false);
    expect(holds("Zm9v+/")).toBe(false);
    expect(holds("Zm9v=")).toBe(false);
    expect(holds("")).toBe(false);
  });

  it("takes the sealed form of a 16384-byte .env and no more", () => {
    const text = (value: string) =>
      btoa(value).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
    const sealedOf = (size: number) =>
      text(
        JSON.stringify({
          v: 1,
          epk: text("e".repeat(65)),
          iv: text("i".repeat(12)),
          ct: text("c".repeat(size + 16)),
        }),
      );
    const holds = (env: string) =>
      stackArgsValid("stack", "create", {
        compose: "c2VhbGVk",
        access: "contained",
        network: "",
        env,
        to,
      });
    expect(sealedOf(16384)).toHaveLength(29336);
    expect(holds(sealedOf(16384))).toBe(true);
    expect(holds(sealedOf(16385))).toBe(false);
  });

  it("refuses the same port twice", () => {
    const serve = (network: string) =>
      stackArgsValid("stack", "edit", {
        compose: "c2VhbGVk",
        access: "contained",
        network,
        to,
      });
    expect(serve("80,443")).toBe(true);
    expect(serve("80,80")).toBe(false);
    expect(serve("80,443,80")).toBe(false);
  });
});
