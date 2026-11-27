import { describe, expect, it } from "vitest";

import targets from "./fixtures/targets.json";
import {
  assertionSchema,
  COMMAND_GRACE_MS,
  isProtected,
  isValidTarget,
  parseStackNames,
  SESSION_MS,
  signedCommandSchema,
  signedTrustSchema,
  stackArgsValid,
  stackTitleValid,
  TRUST_CHANGE_MS,
} from "./index";

const pairs = (list: string[][]) =>
  list.map(([kind = "", name = ""]) => ({ kind, name }));

describe("service targets", () => {
  it("protects what keeps a server reachable, and Krynodes itself", () => {
    for (const { kind, name } of pairs(targets.protected)) {
      expect(isValidTarget(kind, name), name).toBe(true);
      const held =
        (kind === "container" || kind === "unit") && isProtected(kind, name);
      expect(held, name).toBe(true);
    }
  });

  it("lets every other well-formed service through", () => {
    for (const { kind, name } of pairs(targets.allowed)) {
      expect(isValidTarget(kind, name), name).toBe(true);
      if (kind === "container" || kind === "unit") {
        expect(isProtected(kind, name), name).toBe(false);
      }
    }
  });

  it("refuses names that could be read as options, paths or other kinds", () => {
    for (const { kind, name } of pairs(targets.invalid)) {
      expect(isValidTarget(kind, name), JSON.stringify(name)).toBe(false);
    }
  });

  it("stops names at 128 characters", () => {
    expect(isValidTarget("container", "a".repeat(128))).toBe(true);
    expect(isValidTarget("container", "a".repeat(129))).toBe(false);
  });

  it("names the one Docker target docker, and nothing else", () => {
    expect(isValidTarget("docker", "docker")).toBe(true);
    expect(isValidTarget("docker", "resolver")).toBe(false);
    expect(isValidTarget("stack", "Web")).toBe(false);
    expect(isValidTarget("unit", "nginx")).toBe(false);
  });

  it("names no target after Tailscale", () => {
    expect(isValidTarget("vault", "tailscale")).toBe(false);
    expect(isValidTarget("host", "tailscale")).toBe(false);
    expect(isValidTarget("vault", "cloudflare")).toBe(true);
  });
});

describe("stack names", () => {
  it("takes a display name with capitals and spaces", () => {
    expect(stackTitleValid("Resolver")).toBe(true);
    expect(stackTitleValid("Pi-hole · DNS")).toBe(true);
    expect(stackTitleValid("x".repeat(64))).toBe(true);
    expect(stackTitleValid("")).toBe(false);
    expect(stackTitleValid(" Resolver")).toBe(false);
    expect(stackTitleValid("Resolver ")).toBe(false);
    expect(stackTitleValid("x".repeat(65))).toBe(false);
    expect(stackTitleValid("Ad\nGuard")).toBe(false);
  });

  it("reads service=container pairs", () => {
    expect(
      parseStackNames("webserver=paperless,db=paperless-db,broker=redis.1"),
    ).toEqual({
      webserver: "paperless",
      db: "paperless-db",
      broker: "redis.1",
    });
    expect(parseStackNames("")).toEqual({});
    expect(parseStackNames("__proto__=not a name")).toBeNull();
    expect(parseStackNames("__proto__=a")).toBeNull();
    expect(parseStackNames("__proto__=one,__proto__=two")).toBeNull();
    expect(parseStackNames("__proto__=proxy-1")).toEqual(
      JSON.parse('{"__proto__":"proxy-1"}'),
    );
    expect(Object.keys(parseStackNames("__proto__=proxy-1")!)).toEqual([
      "__proto__",
    ]);
    expect(parseStackNames("web=a")).toBeNull();
    expect(parseStackNames("web=-web")).toBeNull();
    expect(parseStackNames("web=my web")).toBeNull();
    expect(parseStackNames("web")).toBeNull();
    expect(parseStackNames("web=one,web=two")).toBeNull();
    expect(parseStackNames("web=same,db=same")).toBeNull();
    expect(
      parseStackNames(
        Array.from({ length: 65 }, (_, n) => `s${n}=c${n}x`).join(","),
      ),
    ).toBeNull();
  });
});

const assertion = {
  credentialId: "Y3JlZA",
  authenticatorData: "YXV0aA",
  clientDataJSON: "Y2xpZW50",
  signature: "c2ln",
};
const signedCommand = {
  grant: { grant: "Z3JhbnQ", ...assertion },
  command: "Y29tbWFuZA",
  signature: "c2lnbmF0dXJl",
};

describe("signed messages", () => {
  it("reads an assertion, and refuses a missing or extra member", () => {
    expect(assertionSchema.safeParse(assertion).success).toBe(true);
    expect(
      assertionSchema.safeParse({ ...assertion, signature: "not b64url!" })
        .success,
    ).toBe(false);
    expect(assertionSchema.safeParse({ ...assertion, extra: 1 }).success).toBe(
      false,
    );
    expect(
      assertionSchema.safeParse({ ...assertion, credentialId: undefined })
        .success,
    ).toBe(false);
  });

  it("reads a signed command, and refuses a grant with a passphrase proof", () => {
    expect(signedCommandSchema.safeParse(signedCommand).success).toBe(true);
    expect(
      signedCommandSchema.safeParse({
        ...signedCommand,
        grant: { ...signedCommand.grant, proof: "cHJvb2Y" },
      }).success,
    ).toBe(false);
    expect(
      signedCommandSchema.safeParse({ ...signedCommand, extra: 1 }).success,
    ).toBe(false);
  });

  it("carries the largest save any protocol-valid stack action can make", () => {
    const text = (value: string) =>
      btoa(
        Array.from(new TextEncoder().encode(value), (byte) =>
          String.fromCharCode(byte),
        ).join(""),
      )
        .replaceAll("+", "-")
        .replaceAll("/", "_")
        .replace(/=+$/u, "");
    const sealedOf = (size: number) =>
      text(
        JSON.stringify({
          v: 1,
          epk: text("e".repeat(65)),
          iv: text("i".repeat(12)),
          ct: text("c".repeat(size + 16)),
        }),
      );
    const names = Array.from(
      { length: 64 },
      (_, n) =>
        `s${String(n).padStart(3, "0")}`.padEnd(128, "x") +
        "=" +
        `c${String(n).padStart(3, "0")}`.padEnd(128, "y"),
    ).join(",");
    const args = {
      compose: sealedOf(32768),
      access: "contained",
      network: Array.from({ length: 32 }, (_, n) => String(65535 - n)).join(
        ",",
      ),
      env: sealedOf(16384),
      title: "�".repeat(64),
      names,
      to: "A".repeat(87),
    };
    expect(args.compose).toHaveLength(58463);
    expect(args.env).toHaveLength(29336);
    expect(names).toHaveLength(16511);
    expect(stackArgsValid("stack", "create", args)).toBe(true);
    expect(stackArgsValid("stack", "edit", args)).toBe(true);
    expect(
      stackArgsValid("stack", "create", { ...args, env: sealedOf(16385) }),
    ).toBe(false);
    const command = text(
      JSON.stringify({
        v: 1,
        id: "i".repeat(64),
        nodeId: "n".repeat(64),
        kind: "stack",
        name: "a".repeat(63),
        action: "create",
        issuedAt: "2026-11-22T10:00:00.000Z",
        expiresAt: "2026-11-22T11:15:00.000Z",
        args,
      }),
    );
    expect(command.length).toBeGreaterThan(131072);
    expect(command.length).toBeLessThanOrEqual(147456);
    expect(
      signedCommandSchema.safeParse({ ...signedCommand, command }).success,
    ).toBe(true);
  });

  it("takes a command of 147456 characters and no more", () => {
    const sized = (size: number) => ({
      ...signedCommand,
      command: "A".repeat(size),
    });
    expect(signedCommandSchema.safeParse(sized(147456)).success).toBe(true);
    expect(signedCommandSchema.safeParse(sized(147457)).success).toBe(false);
  });

  it("reads a signed trust change with approvals, or none for a first trust", () => {
    expect(
      signedTrustSchema.safeParse({
        change: "Y2hhbmdl",
        approvals: [assertion, assertion],
      }).success,
    ).toBe(true);
    expect(
      signedTrustSchema.safeParse({
        change: "Y2hhbmdl",
        approvals: [{ ...assertion, proof: "cHJvb2Y" }],
      }).success,
    ).toBe(false);
    expect(
      signedTrustSchema.safeParse({ change: "Y2hhbmdl", approvals: [] })
        .success,
    ).toBe(true);
    expect(
      signedTrustSchema.safeParse({ change: "Y2hhbmdl", assertion }).success,
    ).toBe(false);
    expect(signedTrustSchema.safeParse(signedCommand).success).toBe(false);
  });

  it("names the session limits", () => {
    expect(SESSION_MS).toBe(15 * 60_000);
    expect(COMMAND_GRACE_MS).toBe(60 * 60_000);
    expect(TRUST_CHANGE_MS).toBe(10 * 60_000);
  });
});
