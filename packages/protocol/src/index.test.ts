import { describe, expect, it } from "vitest";

import targets from "./fixtures/targets.json";
import {
  assertionSchema,
  COMMAND_GRACE_MS,
  isProtectedTarget,
  isValidTarget,
  parseStackNames,
  SESSION_MS,
  signedCommandSchema,
  signedTrustSchema,
  stackTitleValid,
  TRUST_CHANGE_MS,
} from "./index";

const pairs = (list: string[][]) =>
  list.map(([kind = "", name = ""]) => ({ kind, name }));

describe("service targets", () => {
  it("protects what keeps a server reachable, and Krynodes itself", () => {
    for (const { kind, name } of pairs(targets.protected)) {
      expect(isValidTarget(kind, name), name).toBe(true);
      expect(isProtectedTarget(kind, name), name).toBe(true);
    }
  });

  it("lets every other well-formed service through", () => {
    for (const { kind, name } of pairs(targets.allowed)) {
      expect(isValidTarget(kind, name), name).toBe(true);
      expect(isProtectedTarget(kind, name), name).toBe(false);
    }
  });

  it("refuses names that could be read as options, paths or other kinds", () => {
    for (const { kind, name } of pairs(targets.invalid)) {
      expect(isValidTarget(kind, name), JSON.stringify(name)).toBe(false);
    }
  });

  it("stops names at 128 characters", () => {
    expect(isValidTarget("docker", "a".repeat(128))).toBe(true);
    expect(isValidTarget("docker", "a".repeat(129))).toBe(false);
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
