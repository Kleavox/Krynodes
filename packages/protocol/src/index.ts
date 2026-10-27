import { z } from "zod";

import {
  networkBeatSchema,
  networkInventorySchema,
  stackNetworkSchema,
} from "./network";
import { eventSchema, releaseSchema } from "./quarantine";
import { reachSchema } from "./tailscale";
import { isValidTarget, RECIPES } from "./targets";

export { isProtectedTarget, isValidTarget, RECIPES } from "./targets";
export {
  portSchema,
  reachSchema,
  ruleSchema,
  TAILSCALE,
  webhookBodySchema,
  type TailnetRule,
  type WebhookEvent,
} from "./tailscale";
export {
  EVENT_KINDS,
  eventSchema,
  looser,
  QUARANTINE,
  quarantineSettingsSchema,
  codeOf,
  releaseSchema,
  releaseText,
  type PendingRelease,
  type QuarantineEvent,
  type QuarantineSettings,
} from "./quarantine";
export {
  dnsName,
  NETWORK,
  networkArgsValid,
  networkBeatSchema,
  networkDocumentSchema,
  networkInspectSchema,
  networkInventorySchema,
  networkLinkSchema,
  networkPreparedSchema,
  networkProbeSchema,
  networkRekeySchema,
  networkTestSchema,
  placeSchema,
  stackNetworkSchema,
  type NetworkBeat,
  type NetworkDocument,
  type NetworkInspect,
  type NetworkInventory,
  type NetworkLink,
  type NetworkMember,
  type NetworkTest,
  type StackNetwork,
} from "./network";
export {
  passphraseKeySchema,
  trustChangeSchema,
  trustKeySchema,
  type PassphraseKeyRecord,
  type TrustChange,
  type TrustKeyRecord,
} from "./change";
export { summarizeChange, type ChangeSummary } from "./summary";
export {
  agentHasFeatures,
  agentSupported,
  agentUpdatable,
  compareVersions,
  FEATURE_AGENT,
  MIN_AGENT_VERSION,
  UPDATABLE_FROM,
} from "./versions";
export { evaluateQuorum, type QuorumInput, type QuorumResult } from "./quorum";
export {
  NOT_WORK,
  isWork,
  ownerOf,
  touches,
  workTouches,
  type CheckOwner,
  type OwnerServer,
} from "./owner";

export const agentHostSchema = z.object({
  hostname: z.string().min(1).max(255),
  operatingSystem: z.string().min(1).max(64),
  architecture: z.string().min(1).max(64),
  agentVersion: z.string().min(1).max(64),
});

export const metricSnapshotSchema = z.object({
  cpuPercent: z.number().min(0).max(100).nullable(),
  memoryUsedBytes: z.number().int().nonnegative().nullable(),
  memoryTotalBytes: z.number().int().nonnegative().nullable(),
  diskUsedBytes: z.number().int().nonnegative().nullable(),
  diskTotalBytes: z.number().int().nonnegative().nullable(),
  load1: z.number().nonnegative().nullable(),
  load5: z.number().nonnegative().nullable(),
  load15: z.number().nonnegative().nullable(),
  uptimeSeconds: z.number().int().nonnegative().nullable(),
});

export const checkResultSchema = z.object({
  checkId: z.string().uuid(),
  status: z.enum(["UP", "DOWN"]),
  latencyMs: z.number().int().nonnegative().nullable(),
  message: z.string().max(500).nullable(),
  checkedAt: z.string().datetime().optional(),
  since: z.string().datetime().nullable().optional(),
});

export const agentHeartbeatSchema = agentHostSchema.extend({
  nodeId: z.string().uuid(),
  metrics: metricSnapshotSchema,
  results: z.array(checkResultSchema).max(100).optional(),
  update: z
    .object({
      version: z.string().regex(/^\d+\.\d+\.\d+$/u),
      message: z.string().min(1).max(300),
    })
    .optional(),
  network: networkBeatSchema.optional(),
  boot: z
    .strictObject({
      id: z.string().min(1).max(64),
      count: z.number().int().nonnegative(),
    })
    .optional(),
  events: z.array(eventSchema).max(50).optional(),
  release: releaseSchema.optional(),
});

export const enrollmentResponseSchema = z.object({
  nodeId: z.string().uuid(),
  token: z.string().min(1),
  intervalSeconds: z.number().int().positive(),
});

const serviceKindSchema = z.enum(["systemd", "docker"]);

export const SESSION_MS = 15 * 60_000;
export const COMMAND_GRACE_MS = 60 * 60_000;
export const TRUST_CHANGE_MS = 10 * 60_000;

const b64url = z
  .string()
  .min(1)
  .max(4096)
  .regex(/^[A-Za-z0-9_-]+$/u);

export const assertionSchema = z.strictObject({
  credentialId: b64url,
  authenticatorData: b64url,
  clientDataJSON: b64url,
  signature: b64url,
});

const approvalSchema = assertionSchema.extend({ proof: b64url.optional() });

export const signedCommandSchema = z.strictObject({
  grant: approvalSchema.extend({ grant: b64url }),
  command: z
    .string()
    .min(1)
    .max(65536)
    .regex(/^[A-Za-z0-9_-]+$/u),
  signature: b64url,
});

export const signedDocumentSchema = z.strictObject({
  grant: approvalSchema.extend({ grant: b64url }),
  document: z
    .string()
    .min(1)
    .max(600000)
    .regex(/^[A-Za-z0-9_-]+$/u),
  signature: b64url,
});

export const networkReplySchema = z.strictObject({
  document: signedDocumentSchema.optional(),
  endpoints: z
    .array(
      z.strictObject({
        key: z.string().max(44),
        endpoint: z.string().max(64),
      }),
    )
    .max(32)
    .optional(),
  announced: z
    .array(
      z.strictObject({
        node: z.string().uuid(),
        key: z.string().max(44),
        signature: b64url,
      }),
    )
    .max(32)
    .optional(),
});

export const UNSIGNED_VERBS = [
  "manual",
  "heal",
  "scan",
  "refresh",
  "find",
  "preview",
  "inspect",
  "probe",
  "test",
  "block",
  "drop",
  "tighten",
] as const;

export const KIND_VERBS = {
  systemd: [
    "start",
    "stop",
    "restart",
    "logs",
    "autorestart",
    "manual",
    "heal",
  ],
  docker: ["start", "stop", "restart", "logs", "remove"],
  compose: [
    "deploy",
    "rollback",
    "logs",
    "start",
    "stop",
    "restart",
    "remove",
    "purge",
    "create",
    "restore",
    "edit",
    "read",
    "export",
    "expose",
    "unexpose",
    "adopt",
    "reach",
  ],
  host: [
    "reboot",
    "apply",
    "undo",
    "lockdown",
    "unlock",
    "scan",
    "install",
    "uninstall",
    "signin",
    "accept",
    "release",
    "block",
    "unblock",
    "join",
    "inspect",
  ],
  trust: ["trust"],
  vault: [
    "store",
    "release",
    "reshare",
    "forget",
    "policy",
    "save",
    "key",
    "remove",
  ],
  apt: [
    "refresh",
    "find",
    "preview",
    "install",
    "upgrade",
    "hold",
    "unhold",
    "remove",
    "purge",
    "addrepo",
    "droprepo",
  ],
  network: [
    "inspect",
    "probe",
    "test",
    "prepare",
    "unprepare",
    "rekey",
    "drop",
    "tighten",
  ],
} as const;

const RECIPE_VERBS: readonly string[] = ["apply", "undo"];

const TOKEN_VERBS: readonly string[] = [
  "store",
  "release",
  "reshare",
  "forget",
];

export function hostVerbFits(name: string, action: string): boolean {
  const tailnet = ["signin", "block", "unblock", "join", "inspect"];
  if (name === "tailscale" || tailnet.includes(action)) {
    return name === "tailscale" && tailnet.includes(action);
  }
  if (action === "uninstall") return name === "server";
  if (name === "docker") return action === "install";
  const recipe = (RECIPES as readonly string[]).includes(name);
  return action !== "install" && RECIPE_VERBS.includes(action) === recipe;
}

export const signedTrustSchema = z.strictObject({
  change: z
    .string()
    .min(1)
    .max(65536)
    .regex(/^[A-Za-z0-9_-]+$/u),
  approvals: z.array(approvalSchema).max(20),
});

export const agentActionSchema = z
  .strictObject({
    id: z.string().uuid(),
    kind: z.enum([
      "systemd",
      "docker",
      "compose",
      "trust",
      "host",
      "vault",
      "apt",
      "network",
    ]),
    name: z.string(),
    action: z.enum([
      "start",
      "stop",
      "restart",
      "deploy",
      "rollback",
      "trust",
      "reboot",
      "logs",
      "remove",
      "purge",
      "create",
      "restore",
      "autorestart",
      "manual",
      "heal",
      "edit",
      "read",
      "export",
      "expose",
      "unexpose",
      "adopt",
      "reach",
      "apply",
      "undo",
      "lockdown",
      "unlock",
      "scan",
      "store",
      "release",
      "reshare",
      "forget",
      "install",
      "uninstall",
      "signin",
      "refresh",
      "find",
      "preview",
      "upgrade",
      "hold",
      "unhold",
      "addrepo",
      "droprepo",
      "inspect",
      "probe",
      "test",
      "prepare",
      "unprepare",
      "rekey",
      "accept",
      "block",
      "unblock",
      "drop",
      "tighten",
      "policy",
      "save",
      "key",
      "join",
    ]),
    expiresAt: z.string().datetime(),
    signed: z.union([signedCommandSchema, signedTrustSchema]).optional(),
    attachment: z
      .string()
      .min(1)
      .max(200000)
      .regex(/^[A-Za-z0-9_-]+$/u)
      .optional(),
  })
  .refine((action) => isValidTarget(action.kind, action.name))
  .refine((action) => {
    if (action.kind === "trust") {
      return (
        action.action === "trust" &&
        signedTrustSchema.safeParse(action.signed).success
      );
    }
    const allowed: readonly string[] = KIND_VERBS[action.kind];
    if (!allowed.includes(action.action)) return false;
    if (action.kind === "host" && !hostVerbFits(action.name, action.action)) {
      return false;
    }
    if (
      action.kind === "vault" &&
      action.name === "cloudflare" &&
      !TOKEN_VERBS.includes(action.action)
    ) {
      return false;
    }
    if (action.action === "lockdown" && action.signed === undefined) {
      return true;
    }
    return (UNSIGNED_VERBS as readonly string[]).includes(action.action)
      ? action.signed === undefined
      : signedCommandSchema.safeParse(action.signed).success;
  });

export const heartbeatResponseSchema = z.object({
  ok: z.literal(true),
  intervalSeconds: z.number().int().positive(),
  configVersion: z.string().min(1),
  update: z
    .object({
      version: z.string().regex(/^\d+\.\d+\.\d+$/u),
      requestedAt: z.string().min(1),
    })
    .optional(),
  actions: z.array(agentActionSchema).max(10).optional(),
  refresh: z.literal(true).optional(),
  acked: z.array(z.string().max(64)).max(50).optional(),
  quarantined: z.literal(true).optional(),
  network: networkReplySchema.optional(),
});

export const serviceEntrySchema = z
  .strictObject({
    kind: serviceKindSchema,
    name: z.string(),
    state: z.enum(["running", "stopped", "failed", "starting"]),
    since: z.string().datetime().nullable(),
    system: z.boolean(),
  })
  .refine((entry) => isValidTarget(entry.kind, entry.name));

export const stackEntrySchema = z
  .strictObject({
    project: z.string(),
    directory: z.string().min(1).max(4096).startsWith("/"),
    running: z.number().int().nonnegative(),
    total: z.number().int().nonnegative(),
    compose: z.boolean(),
    rollback: z.boolean(),
    access: z.enum(["contained", "full"]).optional(),
    public: z
      .array(z.string().regex(/^\d{1,5}\/(tcp|udp)$/u))
      .max(64)
      .optional(),
    containers: z
      .array(z.string().refine((name) => isValidTarget("docker", name)))
      .max(500)
      .optional(),
    network: stackNetworkSchema.optional(),
  })
  .refine((stack) => isValidTarget("compose", stack.project));

export const securityReportSchema = z.strictObject({
  checkedAt: z.string().datetime(),
  findings: z
    .array(
      z.strictObject({
        id: z.string().regex(/^[a-z0-9-]{1,40}$/u),
        severity: z.enum(["serious", "warning", "note"]),
        detail: z.string().min(1).max(300),
      }),
    )
    .max(50),
  recipes: z.array(z.enum(RECIPES)).max(RECIPES.length),
  lockdown: z.boolean(),
  rebootHour: z.number().int().min(0).max(23).nullable(),
  platform: z
    .strictObject({
      family: z.enum(["debian", "rhel"]).nullable(),
      name: z.string().max(120),
      verified: z.boolean(),
      checked: z.string().max(40),
    })
    .optional(),
  listeners: z
    .array(
      z.strictObject({
        address: z.string().max(64),
        port: z.number().int().min(0).max(65_535),
        protocol: z.enum(["tcp", "udp"]),
        process: z.string().max(64),
      }),
    )
    .max(100)
    .optional(),
});

const vaultPieceSchema = z.strictObject({
  set: z.string().uuid(),
  holders: z.number().int().min(1).max(100),
});

export const vaultReportSchema = vaultPieceSchema
  .extend({ previous: vaultPieceSchema.optional() })
  .nullable();

const fingerprints = z.array(z.string().regex(/^[0-9a-f]{16}$/u)).max(20);

export const trustReportSchema = z.strictObject({
  version: z.number().int().nonnegative(),
  core: fingerprints,
  access: fingerprints,
  passphrase: z.boolean(),
  requireUv: z.boolean().optional(),
});

export const removedStackSchema = z
  .strictObject({
    project: z.string(),
    directory: z.string().min(1).max(4096).startsWith("/"),
    removedAt: z.string().datetime(),
  })
  .refine((stack) => isValidTarget("compose", stack.project));

const stamp = z.string().datetime();
const aptName = z.string().refine((name) => isValidTarget("apt", name));
const aptVersion = z.string().min(1).max(128);

export const packagesReportSchema = z.union([
  z.strictObject({ apt: z.literal(false), system: z.string().max(120) }),
  z.strictObject({
    apt: z.literal(true),
    system: z.string().max(120),
    codename: z.string().max(40),
    readAt: stamp,
    checkedAt: stamp.nullable(),
    installed: z.number().int().nonnegative(),
    packages: z
      .array(
        z.strictObject({
          name: aptName,
          version: aptVersion,
          from: z.string().max(80).nullable(),
          by: z.string().max(64).nullable(),
          feature: z.string().max(60).nullable(),
          more: z.number().int().nonnegative(),
          held: z.boolean(),
        }),
      )
      .max(5000),
    updates: z
      .array(
        z.strictObject({
          name: aptName,
          from: aptVersion,
          to: aptVersion,
          source: z.string().max(80).nullable(),
          security: z.boolean(),
          held: z.boolean(),
          back: z
            .strictObject({
              adds: z.array(aptName).max(50),
              removes: z.array(aptName).max(50),
            })
            .nullable(),
        }),
      )
      .max(500),
    sources: z
      .array(
        z.strictObject({
          name: z.string().min(1).max(80),
          host: z.string().max(253),
          suites: z.array(z.string().max(80)).max(20),
          key: z.string().max(60).nullable(),
          krynodes: z.boolean(),
          file: z.string().min(1).max(4096).startsWith("/"),
          system: z.boolean(),
        }),
      )
      .max(50),
    security: z.strictObject({ on: z.boolean(), lastRan: stamp.nullable() }),
    restart: z
      .strictObject({
        since: stamp,
        running: z.string().max(80).nullable(),
        newest: z.string().max(80).nullable(),
        file: z.boolean(),
        services: z.array(z.string().max(128)).max(50),
      })
      .nullable(),
  }),
]);

export const tailscaleReportSchema = z.strictObject({
  state: z.enum(["running", "needs-login", "stopped"]),
  addresses: z.array(z.string().max(64)).max(8),
  name: z.string().max(253).nullable(),
  keyExpiry: stamp.nullable(),
  id: z.string().max(64).nullable().optional(),
  tailnet: z.string().max(253).nullable().optional(),
  tags: z.array(z.string().max(64)).max(8).optional(),
  peers: z.number().int().nonnegative().optional(),
  reach: z.array(reachSchema).max(64).nullable().optional(),
  names: z
    .record(z.string().max(64), z.string().max(63))
    .refine((names) => Object.keys(names).length <= 64)
    .optional(),
});

export const progressSchema = z.strictObject({
  id: z.string().uuid(),
  at: stamp,
  done: z.number().int().nonnegative(),
  total: z.number().int().nonnegative(),
  line: z.string().max(200),
});

export const actionResultSchema = z.strictObject({
  id: z.string().uuid(),
  ok: z.boolean(),
  exitCode: z.number().int().nullable(),
  output: z.string().max(65536),
  finishedAt: z.string().datetime(),
});

export const agentActionsRequestSchema = z
  .strictObject({
    nodeId: z.string().uuid(),
    results: z.array(actionResultSchema).max(10).optional(),
    inventory: z
      .strictObject({
        hash: z.string().regex(/^[0-9a-f]{64}$/u),
        docker: z.enum(["ready", "no-compose", "missing"]).optional(),
        removed: z.array(removedStackSchema).max(50).optional(),
        sealKey: z
          .string()
          .regex(/^[A-Za-z0-9_-]{87}$/u)
          .optional(),
        security: securityReportSchema.optional(),
        vault: vaultReportSchema.optional(),
        tailscaleVault: vaultReportSchema.optional(),
        services: z.array(serviceEntrySchema).max(500).optional(),
        stacks: z.array(stackEntrySchema).max(50).optional(),
        trust: trustReportSchema.optional(),
        packages: packagesReportSchema.optional(),
        tailscale: tailscaleReportSchema.optional(),
        network: networkInventorySchema.optional(),
      })
      .optional(),
    progress: z.array(progressSchema).max(10).optional(),
  })
  .refine(
    (request) =>
      request.results !== undefined ||
      request.inventory !== undefined ||
      request.progress !== undefined,
  );

export const agentActionsResponseSchema = z.object({
  ok: z.literal(true),
  inventoryHash: z.string().nullable(),
});

export const agentCheckSchema = z.object({
  id: z.string().uuid(),
  name: z.string().min(1),
  kind: z.enum(["HTTP", "TCP", "SERVICE", "CONTAINER"]),
  target: z.string().min(1),
  timeoutSeconds: z.number().int().positive(),
});

export const agentConfigResponseSchema = z.object({
  nodeId: z.string().uuid(),
  intervalSeconds: z.number().int().positive(),
  checks: z.array(agentCheckSchema),
  configVersion: z.string().min(1),
});

export type AgentHost = z.infer<typeof agentHostSchema>;
export type MetricSnapshot = z.infer<typeof metricSnapshotSchema>;
export type AgentHeartbeat = z.infer<typeof agentHeartbeatSchema>;
export type CheckResult = z.infer<typeof checkResultSchema>;
export type EnrollmentResponse = z.infer<typeof enrollmentResponseSchema>;
export type HeartbeatResponse = z.infer<typeof heartbeatResponseSchema>;
export type AgentCheck = z.infer<typeof agentCheckSchema>;
export type AgentConfigResponse = z.infer<typeof agentConfigResponseSchema>;
export type AgentActionResult = z.infer<typeof actionResultSchema>;
export type ServiceEntry = z.infer<typeof serviceEntrySchema>;
export type AgentActionsRequest = z.infer<typeof agentActionsRequestSchema>;
export type Assertion = z.infer<typeof assertionSchema>;
export type SignedCommand = z.infer<typeof signedCommandSchema>;
export type SignedTrust = z.infer<typeof signedTrustSchema>;
export type SignedDocument = z.infer<typeof signedDocumentSchema>;
export type NetworkReply = z.infer<typeof networkReplySchema>;
export type StackEntry = z.infer<typeof stackEntrySchema>;
export type TrustReport = z.infer<typeof trustReportSchema>;
export type PackagesReport = z.infer<typeof packagesReportSchema>;
export type TailscaleReport = z.infer<typeof tailscaleReportSchema>;
export type ActionProgress = z.infer<typeof progressSchema>;
