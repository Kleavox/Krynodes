import { describe, expect, it } from "vitest";

import {
  agentActionSchema,
  agentHeartbeatSchema,
  heartbeatResponseSchema,
  networkArgsValid,
} from "./index";
import {
  eventSchema,
  looser,
  QUARANTINE,
  quarantineSettingsSchema,
  codeOf,
  releaseText,
} from "./quarantine";

declare const crypto: {
  subtle: { digest(name: string, data: Uint8Array): Promise<ArrayBuffer> };
};
declare class TextEncoder {
  encode(text: string): Uint8Array;
}

const ONES = `${"AQEB".repeat(10)}AQE=`;
const TWOS = `${"AgIC".repeat(10)}AgI=`;

const releaseCode = async (input: Parameters<typeof releaseText>[0]) =>
  codeOf(
    new Uint8Array(
      await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(releaseText(input)),
      ),
    ),
  );

const assertion = {
  credentialId: "Y3JlZA",
  authenticatorData: "YXV0aA",
  clientDataJSON: "Y2xpZW50",
  signature: "c2ln",
};
const signed = {
  grant: { grant: "Z3JhbnQ", ...assertion },
  command: "Y29tbWFuZA",
  signature: "c2lnbmF0dXJl",
};
const action = (
  kind: string,
  name: string,
  verb: string,
  extra: Record<string, unknown> = {},
) =>
  agentActionSchema.safeParse({
    id: "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a01",
    kind,
    name,
    action: verb,
    expiresAt: "2026-10-27T10:10:00.000Z",
    ...extra,
  }).success;

const event = {
  id: "knock-1",
  kind: "knock",
  at: "2026-10-27T21:04:00.000Z",
  detail: { from: "10.88.0.1", count: "41" },
};

describe("what only takes away goes unsigned", () => {
  it("lets a lockdown come either way and keeps unlock signed", () => {
    expect(action("host", "server", "lockdown")).toBe(true);
    expect(action("host", "server", "lockdown", { signed })).toBe(true);
    expect(action("host", "server", "unlock")).toBe(false);
  });

  it("blocks a tailnet address unsigned and lifts it only signed", () => {
    expect(action("host", "tailscale", "block", { attachment: "e30" })).toBe(
      true,
    );
    expect(action("host", "tailscale", "block", { signed })).toBe(false);
    expect(action("host", "tailscale", "unblock")).toBe(false);
    expect(action("host", "tailscale", "unblock", { signed })).toBe(true);
    expect(action("host", "server", "block", { attachment: "e30" })).toBe(
      false,
    );
  });

  it("drops a member and tightens the knock settings unsigned", () => {
    expect(action("network", "kry0", "drop", { attachment: "e30" })).toBe(true);
    expect(action("network", "kry0", "tighten", { attachment: "e30" })).toBe(
      true,
    );
    expect(
      networkArgsValid("drop", {
        node: "11111111-1111-4111-8111-111111111111",
        key: ONES,
        address: "10.88.0.1",
      }),
    ).toBe(true);
    expect(networkArgsValid("tighten", { scan: "5", stop: "true" })).toBe(true);
    expect(networkArgsValid("tighten", { scan: "7", stop: "true" })).toBe(
      false,
    );
  });

  it("signs It Was Me and Release", () => {
    expect(action("host", "server", "accept")).toBe(false);
    expect(action("host", "server", "accept", { signed })).toBe(true);
    expect(action("host", "server", "release", { signed })).toBe(true);
  });
});

describe("the heartbeat carries what the server saw", () => {
  const beat = {
    nodeId: "11111111-1111-4111-8111-111111111111",
    hostname: "vps-1",
    operatingSystem: "linux",
    architecture: "amd64",
    agentVersion: "0.7.0",
    metrics: {
      cpuPercent: 1,
      memoryUsedBytes: 1,
      memoryTotalBytes: 2,
      diskUsedBytes: 1,
      diskTotalBytes: 2,
      load1: 0,
      load5: 0,
      load15: 0,
      uptimeSeconds: 1,
    },
  };

  it("takes the boot counter, events and a pending release", () => {
    expect(
      agentHeartbeatSchema.safeParse({
        ...beat,
        boot: { id: "4f0c6a3e-1d2b-4c5a-9e8f-7a6b5c4d3e2f", count: 1201 },
        events: [event],
        release: {
          key: ONES,
          signer: TWOS,
          seal: "c2VhbA",
          token: "a".repeat(64),
          expires: "2026-10-27T21:20:00.000Z",
        },
      }).success,
    ).toBe(true);
    expect(
      agentHeartbeatSchema.safeParse({
        ...beat,
        events: Array.from({ length: 51 }, (_, n) => ({
          ...event,
          id: `knock-${n}`,
        })),
      }).success,
    ).toBe(false);
  });

  it("answers with the acked ids and whether the server is quarantined", () => {
    expect(
      heartbeatResponseSchema.safeParse({
        ok: true,
        intervalSeconds: 60,
        configVersion: "1",
        acked: ["knock-1"],
        quarantined: true,
      }).success,
    ).toBe(true);
  });

  it("knows every kind of event and refuses others", () => {
    for (const kind of [
      "knock",
      "wrong-port",
      "stack",
      "ssh-key",
      "ssh-login",
      "user",
      "sudo",
      "port",
      "rule",
      "firewall",
      "confinement",
    ]) {
      expect(eventSchema.safeParse({ ...event, kind }).success).toBe(true);
    }
    expect(eventSchema.safeParse({ ...event, kind: "cron" }).success).toBe(
      false,
    );
  });
});

describe("Settings, Quarantine", () => {
  it("starts from the defaults", () => {
    expect(QUARANTINE.defaults).toEqual({
      cutoff: 15,
      scan: 10,
      agree: 2,
      stop: true,
    });
    expect(
      quarantineSettingsSchema.safeParse(QUARANTINE.defaults).success,
    ).toBe(true);
    expect(
      quarantineSettingsSchema.safeParse({ ...QUARANTINE.defaults, scan: 7 })
        .success,
    ).toBe(false);
  });

  it("calls longer, higher, more servers and Warn Only looser", () => {
    const base = QUARANTINE.defaults;
    expect(looser(base, { ...base, cutoff: 30 })).toBe(true);
    expect(looser(base, { ...base, cutoff: null })).toBe(true);
    expect(looser(base, { ...base, cutoff: 5 })).toBe(false);
    expect(looser({ ...base, cutoff: null }, { ...base, cutoff: 60 })).toBe(
      false,
    );
    expect(looser(base, { ...base, scan: 20 })).toBe(true);
    expect(looser(base, { ...base, scan: 5 })).toBe(false);
    expect(looser(base, { ...base, agree: 3 })).toBe(true);
    expect(looser(base, { ...base, agree: 1 })).toBe(false);
    expect(looser(base, { ...base, stop: false })).toBe(true);
    expect(looser({ ...base, stop: false }, base)).toBe(false);
    expect(looser(base, base)).toBe(false);
  });
});

describe("the release code", () => {
  it("is bound to the new keys and the time it ends", async () => {
    const input = {
      key: "KEY",
      signer: "SIGNER",
      seal: "SEAL",
      token: "a".repeat(64),
      expires: "2026-10-27T21:20:00.000Z",
    };
    expect(await releaseCode(input)).toBe("274DW-SMBYH");
    expect(await releaseCode({ ...input, seal: "OTHER" })).not.toBe(
      "274DW-SMBYH",
    );
  });
});
