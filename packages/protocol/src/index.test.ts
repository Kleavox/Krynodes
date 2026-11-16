import { describe, expect, it } from "vitest";

import fixture from "./fixtures/agent-config.json";
import targets from "./fixtures/targets.json";
import shared from "./fixtures/packages-report.json";
import {
  actionResultSchema,
  agentActionSchema,
  agentActionsRequestSchema,
  agentActionsResponseSchema,
  agentConfigResponseSchema,
  agentEnrollSchema,
  agentHeartbeatSchema,
  agentHostSchema,
  agentKnowsMemberKinds,
  laptopAddress6,
  laptopEnrollSchema,
  links,
  MEMBER_KINDS_AGENT,
  NETWORK,
  networkReplySchema,
  progressSchema,
  checkResultSchema,
  denialsSchema,
  enrollmentResponseSchema,
  heartbeatResponseSchema,
  isProtectedTarget,
  COMMAND_GRACE_MS,
  SESSION_MS,
  TRUST_CHANGE_MS,
  FIREWALL_FROM_REPORTED,
  isValidTarget,
  parseStackNames,
  SELINUX_BOOLEAN,
  SETUP_PHASES,
  setupSchema,
  stackEntrySchema,
  stackTitleValid,
} from "./index";

describe("Krynodes Agent protocol v1", () => {
  it("validates the shared Agent configuration fixture", () => {
    expect(
      agentConfigResponseSchema.parse(fixture).checks[0]?.timeoutSeconds,
    ).toBe(10);
  });

  it("rejects database-shaped timeout fields", () => {
    const result = agentConfigResponseSchema.safeParse({
      ...fixture,
      checks: [
        {
          ...fixture.checks[0],
          timeoutSeconds: undefined,
          timeout_seconds: 10,
        },
      ],
    });
    expect(result.success).toBe(false);
  });

  it("carries a config version in the shared fixture", () => {
    expect(agentConfigResponseSchema.parse(fixture).configVersion).toBe(
      "0123456789abcdef",
    );
  });

  it("accepts a heartbeat carrying check results, and one without, but no unknown status", () => {
    const heartbeat = {
      nodeId: fixture.nodeId,
      hostname: "server-1",
      operatingSystem: "linux",
      architecture: "arm64",
      agentVersion: "0.3.0",
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
    expect(agentHeartbeatSchema.parse(heartbeat).results).toBeUndefined();
    expect(
      agentHeartbeatSchema.parse({
        ...heartbeat,
        results: [
          {
            checkId: fixture.checks[0]?.id,
            status: "UP",
            latencyMs: 12,
            message: null,
          },
        ],
      }).results,
    ).toHaveLength(1);
    expect(
      agentHeartbeatSchema.safeParse({
        ...heartbeat,
        results: [
          {
            checkId: fixture.checks[0]?.id,
            status: "UNKNOWN",
            latencyMs: null,
            message: null,
          },
        ],
      }).success,
    ).toBe(false);
  });

  it("carries since when a check result says it, and only as a time", () => {
    const result = {
      checkId: fixture.checks[0]?.id,
      status: "UP",
      latencyMs: null,
      message: null,
    };
    expect(
      checkResultSchema.parse({ ...result, since: "2026-10-24T09:24:39Z" })
        .since,
    ).toBe("2026-10-24T09:24:39Z");
    expect(checkResultSchema.parse(result).since).toBeUndefined();
    expect(
      checkResultSchema.safeParse({ ...result, since: "yesterday" }).success,
    ).toBe(false);
  });

  it("accepts a heartbeat from a legacy node with more than 20 checks", () => {
    const results = Array.from({ length: 21 }, () => ({
      checkId: fixture.checks[0]?.id,
      status: "UP",
      latencyMs: 1,
      message: null,
    }));
    expect(
      agentHeartbeatSchema.safeParse({
        nodeId: fixture.nodeId,
        hostname: "legacy",
        operatingSystem: "linux",
        architecture: "amd64",
        agentVersion: "0.3.0",
        metrics: {
          cpuPercent: null,
          memoryUsedBytes: null,
          memoryTotalBytes: null,
          diskUsedBytes: null,
          diskTotalBytes: null,
          load1: null,
          load5: null,
          load15: null,
          uptimeSeconds: null,
        },
        results,
      }).success,
    ).toBe(true);
  });

  it("requires a config version in the heartbeat response", () => {
    expect(
      heartbeatResponseSchema.safeParse({ ok: true, intervalSeconds: 60 })
        .success,
    ).toBe(false);
  });

  it("carries an update instruction only with a strict version", () => {
    const base = { ok: true, intervalSeconds: 60, configVersion: "v1" };
    const parsed = heartbeatResponseSchema.parse({
      ...base,
      update: { version: "0.5.2", requestedAt: "2026-09-28T08:00:00.000Z" },
    });
    expect(parsed.update).toEqual({
      version: "0.5.2",
      requestedAt: "2026-09-28T08:00:00.000Z",
    });
    expect(
      heartbeatResponseSchema.safeParse({
        ...base,
        update: { version: "../evil", requestedAt: "x" },
      }).success,
    ).toBe(false);
  });
});

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

describe("service action messages", () => {
  const id = "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a01";
  const action = {
    id,
    kind: "docker",
    name: "resolver",
    action: "restart",
    expiresAt: "2026-09-29T10:10:00.000Z",
    signed: signedCommand,
  };

  it("carries a start, stop or restart only with a signed command", () => {
    expect(agentActionSchema.safeParse(action).success).toBe(true);
    const { signed: _, ...unsigned } = action;
    expect(agentActionSchema.safeParse(unsigned).success).toBe(false);
    expect(
      agentActionSchema.safeParse({
        ...action,
        signed: { change: "Y2hhbmdl", assertion },
      }).success,
    ).toBe(false);
  });

  it("carries a signed logs request for services and stacks, never for a server", () => {
    const logs = { ...action, action: "logs" };
    expect(agentActionSchema.safeParse(logs).success).toBe(true);
    expect(
      agentActionSchema.safeParse({
        ...logs,
        kind: "systemd",
        name: "nginx.service",
      }).success,
    ).toBe(true);
    expect(
      agentActionSchema.safeParse({
        ...logs,
        kind: "compose",
        name: "listmonk",
      }).success,
    ).toBe(true);
    expect(
      agentActionSchema.safeParse({ ...logs, kind: "host", name: "server" })
        .success,
    ).toBe(false);
    const { signed: _, ...unsigned } = logs;
    expect(agentActionSchema.safeParse(unsigned).success).toBe(false);
  });

  it("carries the stack and container commands of agent 0.4.0, signed", () => {
    for (const verb of [
      "start",
      "stop",
      "restart",
      "remove",
      "purge",
      "create",
      "restore",
    ]) {
      expect(
        agentActionSchema.safeParse({
          ...action,
          kind: "compose",
          name: "panel",
          action: verb,
        }).success,
        verb,
      ).toBe(true);
    }
    expect(
      agentActionSchema.safeParse({ ...action, action: "remove" }).success,
    ).toBe(true);
    expect(
      agentActionSchema.safeParse({ ...action, action: "purge" }).success,
    ).toBe(false);
    expect(
      agentActionSchema.safeParse({
        ...action,
        kind: "systemd",
        name: "nginx.service",
        action: "remove",
      }).success,
    ).toBe(false);
    const { signed: _, ...unsigned } = action;
    expect(
      agentActionSchema.safeParse({
        ...unsigned,
        kind: "compose",
        name: "panel",
        action: "create",
      }).success,
    ).toBe(false);
  });

  it("turns auto-restart on only with a signature; off and heal need none", () => {
    const unit = { ...action, kind: "systemd", name: "nginx.service" };
    const { signed: _, ...bare } = unit;
    expect(
      agentActionSchema.safeParse({ ...unit, action: "autorestart" }).success,
    ).toBe(true);
    expect(
      agentActionSchema.safeParse({ ...bare, action: "autorestart" }).success,
    ).toBe(false);
    expect(
      agentActionSchema.safeParse({ ...bare, action: "manual" }).success,
    ).toBe(true);
    expect(
      agentActionSchema.safeParse({ ...bare, action: "heal" }).success,
    ).toBe(true);
    expect(
      agentActionSchema.safeParse({
        ...bare,
        kind: "docker",
        name: "resolver",
        action: "heal",
      }).success,
    ).toBe(false);
  });

  it("lets a signed command carry a compose file of up to 32 KB", () => {
    const command = "a".repeat(60_000);
    expect(
      agentActionSchema.safeParse({
        ...action,
        kind: "compose",
        name: "panel",
        action: "create",
        signed: { ...signedCommand, command },
      }).success,
    ).toBe(true);
  });

  it("carries a result of up to 64 KiB, enough for the last log lines", () => {
    const result = {
      id,
      ok: true,
      exitCode: 0,
      output: "x".repeat(65536),
      finishedAt: "2026-09-29T10:10:00.000Z",
    };
    expect(actionResultSchema.safeParse(result).success).toBe(true);
    expect(
      actionResultSchema.safeParse({ ...result, output: "x".repeat(65537) })
        .success,
    ).toBe(false);
  });

  it("takes the id of a request the agent made itself, which has no UUID version", () => {
    const own = "f63d813d-3f39-6f5d-4000-6f19ada72522";
    expect(
      actionResultSchema.safeParse({
        id: own,
        ok: true,
        exitCode: 0,
        output: "",
        finishedAt: "2026-09-29T10:10:00.000Z",
      }).success,
    ).toBe(true);
    expect(
      progressSchema.safeParse({
        id: own,
        at: "2026-09-29T10:10:00.000Z",
        done: 1,
        total: 2,
        line: "",
      }).success,
    ).toBe(true);
    expect(
      actionResultSchema.safeParse({
        id: "not-an-id",
        ok: true,
        exitCode: 0,
        output: "",
        finishedAt: "2026-09-29T10:10:00.000Z",
      }).success,
    ).toBe(false);
  });

  it("carries actions and a refresh in the heartbeat response", () => {
    const parsed = heartbeatResponseSchema.parse({
      ok: true,
      intervalSeconds: 60,
      configVersion: "v1",
      actions: [action],
      refresh: true,
    });
    expect(parsed.actions).toEqual([action]);
    expect(parsed.refresh).toBe(true);
    expect(
      heartbeatResponseSchema.safeParse({
        ok: true,
        intervalSeconds: 60,
        configVersion: "v1",
        actions: [{ ...action, name: "a;b" }],
      }).success,
    ).toBe(false);
    expect(
      heartbeatResponseSchema.safeParse({
        ok: true,
        intervalSeconds: 60,
        configVersion: "v1",
        actions: [{ ...action, action: "exec" }],
      }).success,
    ).toBe(false);
  });

  it("accepts results, an inventory, or both, and nothing else", () => {
    const nodeId = "11111111-1111-4111-8111-111111111111";
    const result = {
      id,
      ok: false,
      exitCode: 1,
      output: "Job failed",
      finishedAt: "2026-09-29T10:01:05.000Z",
    };
    const inventory = {
      hash: "a".repeat(64),
      services: [
        {
          kind: "systemd",
          name: "nginx.service",
          state: "running",
          since: null,
          system: false,
        },
      ],
    };
    expect(
      agentActionsRequestSchema.safeParse({ nodeId, results: [result] })
        .success,
    ).toBe(true);
    expect(
      agentActionsRequestSchema.safeParse({ nodeId, inventory }).success,
    ).toBe(true);
    expect(
      agentActionsRequestSchema.safeParse({
        nodeId,
        inventory: { hash: "a".repeat(64) },
      }).success,
    ).toBe(true);
    for (const docker of ["ready", "no-compose", "missing"]) {
      expect(
        agentActionsRequestSchema.safeParse({
          nodeId,
          inventory: { ...inventory, docker },
        }).success,
        docker,
      ).toBe(true);
    }
    expect(
      agentActionsRequestSchema.safeParse({
        nodeId,
        inventory: { ...inventory, docker: "maybe" },
      }).success,
    ).toBe(false);
    const removed = {
      project: "panel",
      directory: "/var/lib/kry-exec/compose/panel",
      removedAt: "2026-10-05T10:00:00.000Z",
    };
    expect(
      agentActionsRequestSchema.safeParse({
        nodeId,
        inventory: { ...inventory, removed: [removed] },
      }).success,
    ).toBe(true);
    expect(
      agentActionsRequestSchema.safeParse({
        nodeId,
        inventory: {
          ...inventory,
          removed: [{ ...removed, project: "Panel" }],
        },
      }).success,
    ).toBe(false);
    expect(agentActionsRequestSchema.safeParse({ nodeId }).success).toBe(false);
    expect(
      agentActionsRequestSchema.safeParse({
        nodeId,
        results: [{ ...result, output: "x".repeat(65537) }],
      }).success,
    ).toBe(false);
    expect(
      agentActionsRequestSchema.safeParse({
        nodeId,
        inventory: { hash: "not-a-hash" },
      }).success,
    ).toBe(false);
    expect(
      agentActionsRequestSchema.safeParse({
        nodeId,
        inventory: {
          hash: "a".repeat(64),
          services: Array.from({ length: 501 }, (_, index) => ({
            kind: "docker",
            name: `c${index}`,
            state: "running",
            since: null,
            system: false,
          })),
        },
      }).success,
    ).toBe(false);
    expect(
      agentActionsRequestSchema.safeParse({
        nodeId,
        results: Array.from({ length: 11 }, () => result),
      }).success,
    ).toBe(false);
    expect(
      agentActionsResponseSchema.parse({ ok: true, inventoryHash: null }),
    ).toEqual({ ok: true, inventoryHash: null });
  });
});

describe("strict action messages", () => {
  const nodeId = "11111111-1111-4111-8111-111111111111";
  const id = "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a01";

  it("refuses unknown keys in results, inventories and actions", () => {
    const result = {
      id,
      ok: true,
      exitCode: 0,
      output: "",
      finishedAt: "2026-09-29T10:01:05.000Z",
    };
    expect(
      agentActionsRequestSchema.safeParse({
        nodeId,
        results: [{ ...result, shell: "rm -rf /" }],
      }).success,
    ).toBe(false);
    expect(
      agentActionsRequestSchema.safeParse({
        nodeId,
        inventory: { hash: "a".repeat(64), extra: true },
      }).success,
    ).toBe(false);
    expect(
      agentActionsRequestSchema.safeParse({
        nodeId,
        results: [result],
        extra: 1,
      }).success,
    ).toBe(false);
    expect(
      heartbeatResponseSchema.safeParse({
        ok: true,
        intervalSeconds: 60,
        configVersion: "v1",
        actions: [
          {
            id,
            kind: "docker",
            name: "resolver",
            action: "restart",
            expiresAt: "2026-09-29T10:10:00.000Z",
            command: "x",
          },
        ],
      }).success,
    ).toBe(false);
  });
});

describe("deploy messages", () => {
  const id = "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a02";
  const deploy = {
    id,
    kind: "compose",
    name: "listmonk",
    action: "deploy",
    expiresAt: "2026-09-29T10:10:00.000Z",
    signed: signedCommand,
  };
  const inventory = (extra: Record<string, unknown>) => ({
    nodeId: "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a03",
    inventory: { hash: "a".repeat(64), ...extra },
  });

  it("accepts a signed compose deploy and refuses it unsigned or with a server action", () => {
    expect(agentActionSchema.safeParse(deploy).success).toBe(true);
    expect(
      agentActionSchema.safeParse({ ...deploy, action: "rollback" }).success,
    ).toBe(true);
    const { signed: _, ...unsigned } = deploy;
    expect(agentActionSchema.safeParse(unsigned).success).toBe(false);
    expect(
      agentActionSchema.safeParse({ ...deploy, action: "reboot" }).success,
    ).toBe(false);
    expect(
      agentActionSchema.safeParse({
        ...deploy,
        kind: "docker",
        name: "resolver",
        action: "deploy",
      }).success,
    ).toBe(false);
    expect(
      agentActionSchema.safeParse({
        ...deploy,
        signed: { ...signedCommand, extra: 1 },
      }).success,
    ).toBe(false);
  });

  it("accepts a trust action with approvals, or none for a first trust", () => {
    const trust = {
      id,
      kind: "trust",
      name: "devices",
      action: "trust",
      expiresAt: "2026-09-29T10:10:00.000Z",
      signed: {
        change: "Y2hhbmdl",
        approvals: [assertion, { ...assertion, proof: "cHJvb2Y" }],
      },
    };
    expect(agentActionSchema.safeParse(trust).success).toBe(true);
    expect(
      agentActionSchema.safeParse({
        ...trust,
        signed: { change: "Y2hhbmdl", approvals: [] },
      }).success,
    ).toBe(true);
    expect(
      agentActionSchema.safeParse({
        ...trust,
        signed: { change: "Y2hhbmdl", assertion },
      }).success,
    ).toBe(false);
    expect(
      agentActionSchema.safeParse({ ...trust, signed: signedCommand }).success,
    ).toBe(false);
  });

  it("lets a grant carry a passphrase proof", () => {
    expect(
      agentActionSchema.safeParse({
        ...deploy,
        signed: {
          ...signedCommand,
          grant: { ...signedCommand.grant, proof: "cHJvb2Y" },
        },
      }).success,
    ).toBe(true);
  });

  it("accepts trust reports only in the shape agents send since 0.3.0", () => {
    const fp = "0123456789abcdef";
    expect(
      agentActionsRequestSchema.safeParse(
        inventory({
          trust: { version: 3, core: [fp], access: [fp], passphrase: true },
        }),
      ).success,
    ).toBe(true);
    expect(
      agentActionsRequestSchema.safeParse(
        inventory({ trust: { version: 2, keys: [fp] } }),
      ).success,
    ).toBe(false);
    expect(
      agentActionsRequestSchema.safeParse(
        inventory({
          trust: {
            version: 4,
            core: [fp],
            access: [fp],
            passphrase: false,
            requireUv: true,
          },
        }),
      ).success,
    ).toBe(true);
    expect(
      agentActionsRequestSchema.safeParse(
        inventory({
          trust: { version: 3, core: [fp], access: ["xyz"], passphrase: false },
        }),
      ).success,
    ).toBe(false);
  });

  it("accepts stacks and trust in the inventory and refuses a relative directory", () => {
    const stack = {
      project: "listmonk",
      directory: "/opt/listmonk",
      running: 5,
      total: 5,
      compose: true,
      rollback: false,
    };
    const trust = {
      version: 2,
      core: ["0123456789abcdef"],
      access: [],
      passphrase: false,
    };
    expect(
      agentActionsRequestSchema.safeParse(inventory({ stacks: [stack], trust }))
        .success,
    ).toBe(true);
    expect(
      agentActionsRequestSchema.safeParse(
        inventory({ stacks: [{ ...stack, directory: "opt/listmonk" }] }),
      ).success,
    ).toBe(false);
    expect(
      agentActionsRequestSchema.safeParse(
        inventory({
          trust: { version: 1, core: ["xyz"], access: [], passphrase: false },
        }),
      ).success,
    ).toBe(false);
  });

  it("names the session limits", () => {
    expect(SESSION_MS).toBe(15 * 60_000);
    expect(COMMAND_GRACE_MS).toBe(60 * 60_000);
    expect(TRUST_CHANGE_MS).toBe(10 * 60_000);
  });
});

describe("server restart messages", () => {
  const reboot = {
    id: "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a04",
    kind: "host",
    name: "server",
    action: "reboot",
    expiresAt: "2026-09-29T10:10:00.000Z",
    signed: signedCommand,
  };

  it("carries a signed restart of the server and nothing else for host", () => {
    expect(agentActionSchema.safeParse(reboot).success).toBe(true);
    const { signed: _, ...unsigned } = reboot;
    expect(agentActionSchema.safeParse(unsigned).success).toBe(false);
    expect(
      agentActionSchema.safeParse({ ...reboot, action: "restart" }).success,
    ).toBe(false);
    expect(
      agentActionSchema.safeParse({ ...reboot, name: "other" }).success,
    ).toBe(false);
    expect(
      agentActionSchema.safeParse({
        ...reboot,
        kind: "docker",
        name: "resolver",
      }).success,
    ).toBe(false);
  });
});

describe("orchestration messages of agent 0.5.0", () => {
  const base = {
    id: "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a09",
    expiresAt: "2026-10-05T10:10:00.000Z",
    signed: signedCommand,
  };
  const parse = (value: object) =>
    agentActionSchema.safeParse({ ...base, ...value }).success;

  it("carries the new stack verbs, signed", () => {
    for (const verb of [
      "edit",
      "read",
      "export",
      "expose",
      "unexpose",
      "adopt",
    ]) {
      expect(
        parse({ kind: "compose", name: "listmonk", action: verb }),
        verb,
      ).toBe(true);
    }
    expect(parse({ kind: "compose", name: "listmonk", action: "apply" })).toBe(
      false,
    );
  });

  it("applies and undoes only known recipes, and keeps the server verbs on server", () => {
    for (const recipe of [
      "security-updates",
      "reboot-window",
      "ssh-keys-only",
      "fail2ban",
      "firewall",
      "free-port-53",
    ]) {
      expect(
        parse({ kind: "host", name: recipe, action: "apply" }),
        recipe,
      ).toBe(true);
      expect(
        parse({ kind: "host", name: recipe, action: "undo" }),
        recipe,
      ).toBe(true);
      expect(
        parse({ kind: "host", name: recipe, action: "reboot" }),
        recipe,
      ).toBe(false);
    }
    expect(parse({ kind: "host", name: "server", action: "apply" })).toBe(
      false,
    );
    expect(parse({ kind: "host", name: "server", action: "lockdown" })).toBe(
      true,
    );
    expect(parse({ kind: "host", name: "server", action: "unlock" })).toBe(
      true,
    );
    expect(parse({ kind: "host", name: "rm-rf", action: "apply" })).toBe(false);
  });

  it("installs only Docker, and Docker only by install", () => {
    expect(parse({ kind: "host", name: "docker", action: "install" })).toBe(
      true,
    );
    for (const verb of ["apply", "undo", "reboot", "lockdown"]) {
      expect(parse({ kind: "host", name: "docker", action: verb }), verb).toBe(
        false,
      );
    }
    for (const name of ["server", "fail2ban"]) {
      expect(parse({ kind: "host", name, action: "install" }), name).toBe(
        false,
      );
    }
  });

  it("removes Krynodes only from a whole server", () => {
    expect(parse({ kind: "host", name: "server", action: "uninstall" })).toBe(
      true,
    );
    for (const name of ["docker", "fail2ban", "reboot-window"]) {
      expect(parse({ kind: "host", name, action: "uninstall" }), name).toBe(
        false,
      );
    }
  });

  it("checks a server without a signature", () => {
    const { signed: _, ...unsigned } = base;
    expect(
      agentActionSchema.safeParse({
        ...unsigned,
        kind: "host",
        name: "server",
        action: "scan",
      }).success,
    ).toBe(true);
    expect(parse({ kind: "host", name: "server", action: "scan" })).toBe(false);
  });

  it("keeps the Cloudflare token pieces behind signed vault verbs", () => {
    for (const verb of ["store", "release", "reshare", "forget"]) {
      expect(
        parse({ kind: "vault", name: "cloudflare", action: verb }),
        verb,
      ).toBe(true);
    }
    expect(parse({ kind: "vault", name: "other", action: "store" })).toBe(
      false,
    );
    expect(
      parse({ kind: "vault", name: "cloudflare", action: "restart" }),
    ).toBe(false);
  });

  it("delivers a sealed attachment with an action", () => {
    expect(
      parse({
        kind: "compose",
        name: "listmonk",
        action: "create",
        attachment: "eyJ2IjoxfQ",
      }),
    ).toBe(true);
    expect(
      parse({
        kind: "compose",
        name: "listmonk",
        action: "create",
        attachment: "not base64url!",
      }),
    ).toBe(false);
  });

  it("reports a seal key, security findings, the vault and stack access", () => {
    const stack = {
      project: "resolver",
      directory: "/var/lib/kry-exec/compose/resolver",
      running: 1,
      total: 1,
      compose: true,
      rollback: false,
      access: "full",
      public: ["53/udp", "53/tcp"],
    };
    const security = {
      checkedAt: "2026-10-05T10:00:00.000Z",
      findings: [
        {
          id: "ssh-password",
          severity: "serious",
          detail: "Password login is on",
        },
      ],
      recipes: ["security-updates"],
      lockdown: false,
      rebootHour: 3,
    };
    const request = (value: object) =>
      agentActionsRequestSchema.safeParse({
        nodeId: "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a11",
        inventory: {
          hash: "a".repeat(64),
          sealKey: "B" + "A".repeat(86),
          security,
          vault: { set: "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a10", holders: 3 },
          stacks: [stack],
          ...value,
        },
      }).success;
    expect(request({})).toBe(true);
    const platform = {
      family: "rhel",
      name: "Rocky Linux 11.0",
      verified: false,
      checked: "8 to 10",
    };
    expect(request({ security: { ...security, platform } })).toBe(true);
    expect(
      request({
        security: { ...security, platform: { ...platform, family: null } },
      }),
    ).toBe(true);
    expect(
      request({
        security: { ...security, platform: { ...platform, family: "arch" } },
      }),
    ).toBe(false);
    const named = {
      family: "debian",
      name: "Debian GNU/Linux 12",
      id: "debian",
      version: "12",
    };
    expect(request({ security: { ...security, platform: named } })).toBe(true);
    expect(
      request({
        security: {
          ...security,
          platform: { ...named, endOfLife: "2028-06-30" },
        },
      }),
    ).toBe(false);
    const listener = {
      address: "100.79.66.29",
      port: 57969,
      protocol: "tcp",
      process: "tailscaled",
    };
    expect(request({ security: { ...security, listeners: [listener] } })).toBe(
      true,
    );
    expect(
      request({
        security: {
          ...security,
          listeners: [{ ...listener, standalone: true }],
        },
      }),
    ).toBe(true);
    for (const bad of [
      { ...listener, standalone: "yes" },
      { ...listener, port: 70000 },
      { ...listener, protocol: "sctp" },
      { ...listener, address: "x".repeat(65) },
      { ...listener, extra: 1 },
    ]) {
      expect(request({ security: { ...security, listeners: [bad] } })).toBe(
        false,
      );
    }
    expect(
      request({
        security: { ...security, listeners: Array(101).fill(listener) },
      }),
    ).toBe(false);
    expect(request({ vault: null })).toBe(true);
    const previous = {
      set: "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a20",
      holders: 2,
    };
    expect(
      request({
        vault: {
          set: "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a10",
          holders: 3,
          previous,
        },
      }),
    ).toBe(true);
    expect(
      request({
        vault: {
          set: "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a10",
          holders: 3,
          previous: { ...previous, set: "x" },
        },
      }),
    ).toBe(false);
    expect(request({ sealKey: "short" })).toBe(false);
    expect(request({ security: { ...security, recipes: ["rm-rf"] } })).toBe(
      false,
    );
    expect(
      request({
        security: {
          ...security,
          findings: [{ id: "x", severity: "bad", detail: "" }],
        },
      }),
    ).toBe(false);
    expect(request({ stacks: [{ ...stack, public: ["53"] }] })).toBe(false);
    expect(request({ stacks: [{ ...stack, access: "root" }] })).toBe(false);
  });

  it("carries a stack's containers by their exact names", () => {
    const stack = {
      project: "listmonk",
      directory: "/var/lib/kry-exec/compose/listmonk",
      running: 2,
      total: 2,
      compose: true,
      rollback: false,
    };
    const accepts = (containers: unknown) =>
      stackEntrySchema.safeParse({ ...stack, containers }).success;
    expect(accepts(["listmonk_app", "listmonk_db"])).toBe(true);
    expect(accepts(undefined)).toBe(true);
    expect(accepts(["bad;name"])).toBe(false);
    expect(accepts(Array(501).fill("listmonk_app"))).toBe(false);
  });

  it("carries a stack's display name and container names", () => {
    const stack = {
      project: "resolver",
      directory: "/var/lib/kry-exec/compose/resolver",
      running: 1,
      total: 1,
      compose: true,
      rollback: false,
    };
    const accepts = (extra: Record<string, unknown>) =>
      stackEntrySchema.safeParse({ ...stack, ...extra }).success;
    expect(
      accepts({ title: "Resolver", names: { resolver: "resolver" } }),
    ).toBe(true);
    expect(accepts({ title: " Resolver" })).toBe(false);
    expect(accepts({ title: "x".repeat(65) })).toBe(false);
    expect(accepts({ names: { resolver: "bad name" } })).toBe(false);
    expect(accepts({ names: { "bad service": "resolver" } })).toBe(false);
  });

  it("carries a stack's service names and a server's leftovers", () => {
    const stack = {
      project: "monitoring",
      directory: "/var/lib/kry-exec/compose/monitoring",
      running: 2,
      total: 2,
      compose: true,
      rollback: false,
    };
    const accepts = (services: unknown) =>
      stackEntrySchema.safeParse({ ...stack, services }).success;
    expect(accepts(["panel", "db"])).toBe(true);
    expect(accepts(["bad service"])).toBe(false);
    expect(accepts(Array(65).fill("db"))).toBe(false);
    const leftovers = (names: unknown) =>
      agentActionsRequestSchema.safeParse({
        nodeId: "3f1c2b4a-5d6e-4f70-8a9b-0c1d2e3f4a5b",
        inventory: { hash: "a".repeat(64), leftovers: names },
      }).success;
    expect(leftovers(["resolver"])).toBe(true);
    expect(leftovers(["Bad Name"])).toBe(false);
    expect(leftovers(Array(51).fill("x"))).toBe(false);
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

describe("package messages of agent 0.7.0", () => {
  const base = {
    id: "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a70",
    kind: "apt",
    name: "nginx",
    expiresAt: "2026-10-26T10:10:00.000Z",
  };
  const nodeId = "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a71";
  const hash = "a".repeat(64);
  const { packages: report } = shared;
  const accepts = (inventory: Record<string, unknown>) =>
    agentActionsRequestSchema.safeParse({
      nodeId,
      inventory: { hash, ...inventory },
    }).success;

  it("changes packages only with a signed command", () => {
    for (const action of [
      "install",
      "upgrade",
      "hold",
      "unhold",
      "remove",
      "purge",
      "addrepo",
      "droprepo",
    ]) {
      expect(
        agentActionSchema.safeParse({ ...base, action, signed: signedCommand })
          .success,
        action,
      ).toBe(true);
      expect(agentActionSchema.safeParse({ ...base, action }).success).toBe(
        false,
      );
    }
  });

  it("asks and dry-runs without a signature, its arguments in the attachment", () => {
    for (const action of ["refresh", "find", "preview"]) {
      expect(
        agentActionSchema.safeParse({
          ...base,
          name: "system",
          action,
          attachment: "eyJxIjoibmdpbngifQ",
        }).success,
        action,
      ).toBe(true);
      expect(
        agentActionSchema.safeParse({ ...base, action, signed: signedCommand })
          .success,
      ).toBe(false);
    }
    expect(
      agentActionSchema.safeParse({ ...base, action: "restart" }).success,
    ).toBe(false);
  });

  it("reports the package list", () => {
    expect(accepts({ packages: report })).toBe(true);
    expect(
      accepts({ packages: { apt: false, system: "Fedora Linux 41" } }),
    ).toBe(true);
    expect(accepts({ packages: { ...report, restart: null } })).toBe(true);
    expect(
      accepts({
        packages: {
          ...report,
          updates: [{ ...report.updates[1], back: "Needs a new package." }],
        },
      }),
    ).toBe(false);
    expect(
      accepts({
        packages: { ...report, updates: Array(501).fill(report.updates[0]) },
      }),
    ).toBe(false);
    expect(
      accepts({
        packages: {
          ...report,
          packages: [{ ...report.packages[0], name: "Bad Name" }],
        },
      }),
    ).toBe(false);
  });

  it("carries the step of a long job", () => {
    const progress = [
      {
        id: base.id,
        at: "2026-10-26T09:00:41.000Z",
        done: 6,
        total: 14,
        line: "Unpacking docker-ce",
      },
    ];
    expect(
      agentActionsRequestSchema.safeParse({ nodeId, progress }).success,
    ).toBe(true);
    expect(
      agentActionsRequestSchema.safeParse({
        nodeId,
        progress: [{ ...progress[0], done: -1 }],
      }).success,
    ).toBe(false);
  });
});

describe("Tailscale left Krynodes", () => {
  const nodeId = "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a91";
  const hash = "b".repeat(64);
  const accepts = (inventory: Record<string, unknown>) =>
    agentActionsRequestSchema.safeParse({
      nodeId,
      inventory: { hash, ...inventory },
    }).success;
  const security = {
    checkedAt: "2026-11-14T10:00:00.000Z",
    findings: [],
    recipes: ["firewall"],
    lockdown: false,
    rebootHour: null,
  };
  const step = (kind: string, name: string, action: string, signed = true) =>
    agentActionSchema.safeParse({
      id: "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a92",
      kind,
      name,
      action,
      expiresAt: "2026-11-14T10:10:00.000Z",
      ...(signed ? { signed: signedCommand } : {}),
    }).success;

  it("an inventory from agent 0.7.22 with Tailscale fields still parses", () => {
    expect(
      accepts({
        tailscale: { running: true },
        tailscaleVault: { set: "x" },
      }),
    ).toBe(true);
    expect(accepts({ tailscale: null, tailscaleVault: null })).toBe(true);
    expect(accepts({ packages: shared.packages, tailscale: {} })).toBe(true);
  });

  it("no target names Tailscale", () => {
    expect(isValidTarget("vault", "tailscale")).toBe(false);
    expect(isValidTarget("host", "tailscale")).toBe(false);
    expect(isValidTarget("vault", "cloudflare")).toBe(true);
  });

  it("a reported opening from Tailscale parses, a sent one does not", () => {
    const report = (from: string) => ({
      ...security,
      firewall: {
        closed: true,
        open: [{ port: 22, protocol: "tcp", from }],
        other: [],
      },
    });
    expect(accepts({ security: report("tailscale") })).toBe(true);
    expect(accepts({ security: report("everyone") })).toBe(true);
    expect(accepts({ security: report("nobody") })).toBe(false);
    expect(FIREWALL_FROM_REPORTED).toEqual([
      "everyone",
      "tailscale",
      "addresses",
    ]);
  });

  it("no verb is left for signing in, blocking, joining, exit nodes or DNS", () => {
    for (const action of [
      "signin",
      "block",
      "unblock",
      "join",
      "inspect",
      "exitnode",
      "dns",
    ]) {
      for (const name of ["server", "tailscale", "firewall"]) {
        for (const signed of [true, false]) {
          expect(step("host", name, action, signed), `${name} ${action}`).toBe(
            false,
          );
        }
      }
    }
    for (const action of ["policy", "save", "key", "remove"]) {
      expect(step("vault", "cloudflare", action), action).toBe(false);
      expect(step("vault", "tailscale", action), action).toBe(false);
    }
    for (const action of ["store", "release", "reshare", "forget"]) {
      expect(step("vault", "cloudflare", action), action).toBe(true);
      expect(step("vault", "tailscale", action), action).toBe(false);
    }
  });
});

describe("Firewall of agent 0.7.4", () => {
  const nodeId = "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a92";
  const parses = (name: string, action: string, signed = true) =>
    agentActionSchema.safeParse({
      id: "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a93",
      kind: "host",
      name,
      action,
      expiresAt: "2026-10-29T10:10:00.000Z",
      ...(signed ? { signed: signedCommand } : {}),
    }).success;
  const security = {
    checkedAt: "2026-10-29T10:00:00.000Z",
    findings: [],
    recipes: ["firewall"],
    lockdown: false,
    rebootHour: null,
  };
  const accepts = (firewall: unknown) =>
    agentActionsRequestSchema.safeParse({
      nodeId,
      inventory: { hash: "c".repeat(64), security: { ...security, firewall } },
    }).success;

  it("opens, closes and puts back only on the firewall, signed", () => {
    for (const action of ["open", "close", "putback"]) {
      expect(parses("firewall", action), action).toBe(true);
      expect(parses("firewall", action, false), action).toBe(false);
      expect(parses("server", action), action).toBe(false);
      expect(parses("fail2ban", action), action).toBe(false);
    }
    expect(parses("firewall", "apply")).toBe(true);
  });

  it("reports what is open, what it keeps and what came from outside", () => {
    const open = [
      { port: 443, protocol: "tcp", from: "everyone" },
      { port: 8443, protocol: "tcp", from: "tailscale" },
      {
        port: 53,
        protocol: "udp",
        from: "addresses",
        addresses: ["203.0.113.0/24", "2001:db8::/32"],
      },
    ];
    expect(
      accepts({ closed: true, open, other: [], drift: ["allow 9999/tcp"] }),
    ).toBe(true);
    expect(accepts({ closed: false, open: [], other: ["allow OpenSSH"] })).toBe(
      true,
    );
    expect(accepts(undefined)).toBe(true);
    expect(
      accepts({
        closed: true,
        open: [{ port: 0, protocol: "tcp", from: "everyone" }],
        other: [],
      }),
    ).toBe(false);
    expect(
      accepts({
        closed: true,
        open: [{ port: 80, protocol: "tcp", from: "nobody" }],
        other: [],
      }),
    ).toBe(false);
    expect(
      accepts({
        closed: true,
        open: [
          {
            port: 80,
            protocol: "tcp",
            from: "addresses",
            addresses: Array.from({ length: 9 }, (_, i) => `203.0.113.${i}/32`),
          },
        ],
        other: [],
      }),
    ).toBe(false);
    expect(accepts({ closed: true, open: [], other: ["x".repeat(301)] })).toBe(
      false,
    );
    expect(accepts({ closed: true, open: [] })).toBe(false);
  });
});

describe("SELinux and AppArmor of agent 0.7.4", () => {
  const nodeId = "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a92";
  const parses = (name: string, action: string, signed = true) =>
    agentActionSchema.safeParse({
      id: "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a93",
      kind: "host",
      name,
      action,
      expiresAt: "2026-10-29T10:10:00.000Z",
      ...(signed ? { signed: signedCommand } : {}),
    }).success;
  const security = {
    checkedAt: "2026-10-29T10:00:00.000Z",
    findings: [],
    recipes: ["confinement"],
    lockdown: false,
    rebootHour: null,
  };
  const accepts = (confinement: unknown) =>
    agentActionsRequestSchema.safeParse({
      nodeId,
      inventory: {
        hash: "c".repeat(64),
        security: { ...security, confinement },
      },
    }).success;
  const managed = {
    system: "selinux",
    mode: "enforcing",
    enforced: null,
    complain: null,
    managed: true,
    restart: false,
    docker: true,
  };
  const line = {
    at: "2026-10-29T09:58:00Z",
    program: "cat",
    wanted: "read shadow",
    stack: "panel",
  };

  it("turns on and confines containers, signed, and is never undone", () => {
    expect(parses("confinement", "apply")).toBe(true);
    expect(parses("confinement", "undo")).toBe(false);
    expect(parses("confinement", "containers")).toBe(true);
    expect(parses("confinement", "containers", false)).toBe(false);
    expect(parses("firewall", "containers")).toBe(false);
    expect(parses("server", "containers")).toBe(false);
  });

  it("sets an SELinux boolean, signed, only through confinement", () => {
    expect(parses("confinement", "boolean")).toBe(true);
    expect(parses("confinement", "boolean", false)).toBe(false);
    expect(parses("firewall", "boolean")).toBe(false);
    expect(parses("server", "boolean")).toBe(false);
    expect(SELINUX_BOOLEAN.test("httpd_can_network_connect")).toBe(true);
    for (const name of [
      "Httpd",
      "_httpd",
      "httpd-x",
      "a;b",
      "a".repeat(65),
      "",
    ]) {
      expect(SELINUX_BOOLEAN.test(name), name).toBe(false);
    }
  });

  it("reports what the server has, managed or not", () => {
    expect(accepts(managed)).toBe(true);
    expect(
      accepts({
        system: null,
        mode: null,
        enforced: null,
        complain: null,
        managed: false,
        restart: false,
        docker: null,
      }),
    ).toBe(true);
    expect(
      accepts({
        ...managed,
        system: "apparmor",
        mode: "kernel-off",
        enforced: 3,
        complain: 1,
      }),
    ).toBe(true);
    expect(accepts({ ...managed, mode: "relaxed" })).toBe(false);
    expect(accepts({ ...managed, denials: 2 })).toBe(false);
  });

  it("sends the denials with the heartbeat, at most twenty lines", () => {
    expect(denialsSchema.safeParse({ count: 2, lines: [line] }).success).toBe(
      true,
    );
    expect(denialsSchema.safeParse({ count: 0, lines: [] }).success).toBe(true);
    expect(denialsSchema.safeParse({ count: -1, lines: [] }).success).toBe(
      false,
    );
    expect(
      denialsSchema.safeParse({ count: 21, lines: Array(21).fill(line) })
        .success,
    ).toBe(false);
    expect(
      denialsSchema.safeParse({
        count: 1,
        lines: [{ ...line, wanted: "x".repeat(301) }],
      }).success,
    ).toBe(false);
    expect("denials" in agentHeartbeatSchema.shape).toBe(true);
  });

  it("carries where setup is, its step of steps, and whether it stopped", () => {
    const accepts = (value: unknown) => setupSchema.safeParse(value).success;
    expect(accepts({ phase: "upgrade", step: 2, of: 6 })).toBe(true);
    expect(accepts({ phase: "restart", step: 6, of: 6, stopped: true })).toBe(
      true,
    );
    expect(accepts({ phase: "reinstall", step: 1, of: 6 })).toBe(false);
    expect(accepts({ phase: "upgrade", step: 0, of: 6 })).toBe(false);
    expect(accepts({ phase: "upgrade", step: 7, of: 6 })).toBe(false);
    expect(accepts({ phase: "upgrade", step: 2, of: 6, extra: 1 })).toBe(false);
    expect(SETUP_PHASES).toEqual([
      "admin",
      "upgrade",
      "protections",
      "selinux",
      "apparmor",
      "docker",
      "network",
      "restart",
    ]);
    expect("setup" in agentHeartbeatSchema.shape).toBe(true);
  });
});

describe("laptops of agent 0.7.24", () => {
  const A = "11111111-1111-4111-8111-111111111111";
  const B = "22222222-2222-4222-8222-222222222222";
  const key = `${"A".repeat(42)}A=`;
  const seal = "s".repeat(87);
  const laptop = { key, signer: key, port: 51820, sealKey: seal };
  const host = {
    hostname: "laptop-1",
    operatingSystem: "windows",
    architecture: "amd64",
    agentVersion: "0.7.24",
  };
  const reply = (network: unknown) =>
    heartbeatResponseSchema.safeParse({
      ok: true,
      intervalSeconds: 30,
      configVersion: "a",
      network,
    }).success;

  it("reaches the app and the Worker by the package's name", () => {
    expect(MEMBER_KINDS_AGENT).toBe("0.7.24");
    expect(agentKnowsMemberKinds("0.7.24")).toBe(true);
    expect(agentKnowsMemberKinds("0.7.23")).toBe(false);
    expect(NETWORK.pool6).toBe("fd88:88::/64");
    expect(laptopAddress6("10.88.3.9")).toBe("fd88:88::3:9");
    expect(typeof links).toBe("function");
  });

  it("an enroll body may carry a laptop's keys, and one without still parses", () => {
    expect(agentEnrollSchema.safeParse(host).success).toBe(true);
    expect(agentEnrollSchema.safeParse({ ...host, laptop }).success).toBe(true);
    expect(laptopEnrollSchema.safeParse(laptop).success).toBe(true);
    expect(agentEnrollSchema.parse({ ...host, laptop }).laptop?.sealKey).toBe(
      seal,
    );
    expect("laptop" in agentHostSchema.shape).toBe(false);
  });

  it("refuses a heartbeat that carries a laptop's keys", () => {
    const heartbeat = {
      ...host,
      nodeId: A,
      metrics: {
        cpuPercent: null,
        memoryUsedBytes: null,
        memoryTotalBytes: null,
        diskUsedBytes: null,
        diskTotalBytes: null,
        load1: null,
        load5: null,
        load15: null,
        uptimeSeconds: null,
      },
    };
    expect(agentHeartbeatSchema.safeParse(heartbeat).success).toBe(true);
    expect(
      agentHeartbeatSchema.safeParse({ ...heartbeat, laptop }).success,
    ).toBe(false);
  });

  it("an enroll answer may carry the trust tokens", () => {
    const answer = { nodeId: A, token: "t", intervalSeconds: 60 };
    expect(enrollmentResponseSchema.safeParse(answer).success).toBe(true);
    expect(
      enrollmentResponseSchema.parse({ ...answer, trust: ["a.-7.b"] }).trust,
    ).toEqual(["a.-7.b"]);
  });

  it("refuses a laptop whose keys or port are wrong, or that carries more", () => {
    const refused = (change: Record<string, unknown>) =>
      laptopEnrollSchema.safeParse({ ...laptop, ...change }).success;
    expect(refused({ key: "abc" })).toBe(false);
    expect(refused({ signer: "abc" })).toBe(false);
    expect(refused({ port: 80 })).toBe(false);
    expect(refused({ sealKey: "short" })).toBe(false);
    expect(refused({ extra: 1 })).toBe(false);
    expect(
      laptopEnrollSchema.safeParse({ key, signer: key, port: 51820 }).success,
    ).toBe(false);
  });

  it("a reply names meetings for NAT members and held servers for laptops", () => {
    expect(reply({ meetings: [{ laptop: A, via: B }] })).toBe(true);
    expect(reply({ held: [A, B] })).toBe(true);
    expect(reply({ meetings: [], held: [] })).toBe(true);
    expect(reply({})).toBe(true);
    expect(reply({ meetings: [{ laptop: A }] })).toBe(false);
    expect(reply({ meetings: [{ laptop: A, via: "b" }] })).toBe(false);
    expect(reply({ meetings: [{ laptop: A, via: B, extra: 1 }] })).toBe(false);
    expect(reply({ held: ["a"] })).toBe(false);
  });

  it("limits meetings and held to 32", () => {
    const meeting = { laptop: A, via: B };
    expect(
      networkReplySchema.safeParse({ meetings: Array(32).fill(meeting) })
        .success,
    ).toBe(true);
    expect(
      networkReplySchema.safeParse({ meetings: Array(33).fill(meeting) })
        .success,
    ).toBe(false);
    expect(
      networkReplySchema.safeParse({ held: Array(32).fill(A) }).success,
    ).toBe(true);
    expect(
      networkReplySchema.safeParse({ held: Array(33).fill(A) }).success,
    ).toBe(false);
  });
});
