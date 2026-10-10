import { z } from "zod";

import { isValidTarget, RECIPES } from "./targets";

export { isProtectedTarget, isValidTarget, RECIPES } from "./targets";
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
  agentSupported,
  agentUpdatable,
  compareVersions,
  MIN_AGENT_VERSION,
  UPDATABLE_FROM,
} from "./versions";
export { evaluateQuorum, type QuorumInput, type QuorumResult } from "./quorum";

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

export const UNSIGNED_VERBS = ["manual", "heal", "scan"] as const;

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
  ],
  trust: ["trust"],
  vault: ["store", "release", "reshare", "forget"],
} as const;

const RECIPE_VERBS: readonly string[] = ["apply", "undo"];

export function hostVerbFits(name: string, action: string): boolean {
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
    kind: z.enum(["systemd", "docker", "compose", "trust", "host", "vault"]),
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
        services: z.array(serviceEntrySchema).max(500).optional(),
        stacks: z.array(stackEntrySchema).max(50).optional(),
        trust: trustReportSchema.optional(),
      })
      .optional(),
  })
  .refine(
    (request) =>
      request.results !== undefined || request.inventory !== undefined,
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
export type StackEntry = z.infer<typeof stackEntrySchema>;
export type TrustReport = z.infer<typeof trustReportSchema>;
