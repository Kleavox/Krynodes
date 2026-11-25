import { z } from "zod";

import {
  b64url,
  endpoint,
  NETWORK_VERBS,
  networkLinkSchema,
  sealKeySchema,
  wireguardKey,
} from "./network";
import {
  checkSchema,
  checksSchema,
  inventorySchema,
  STACK_ACTIONS,
} from "./stacks";

export const WIRE_VERSION = 1;

const id = z.string().min(1).max(64);
const credentials = z
  .array(z.string().regex(/^[A-Za-z0-9_-]{1,1400}$/u))
  .max(20);

export const trustReportSchema = z.strictObject({
  version: z.number().int().nonnegative(),
  core: credentials,
  access: credentials,
});

export const networkHelloSchema = z.strictObject({
  version: z.number().int().nonnegative(),
  key: wireguardKey,
  signer: wireguardKey,
  ready: z.boolean(),
  reason: z.string().max(300).nullable(),
});

export const COMMAND_KINDS = [
  "trust",
  "agent",
  "host",
  "network",
  "stack",
  "container",
  "unit",
  "docker",
] as const;

export type CommandKind = (typeof COMMAND_KINDS)[number];

export const COMMAND_ACTIONS: Record<CommandKind, readonly string[]> = {
  trust: ["apply"],
  agent: ["update", "remove"],
  host: ["restart"],
  network: NETWORK_VERBS,
  ...STACK_ACTIONS,
};

const nodeId = z.string().uuid();
const upTo32 = <T extends z.ZodType>(item: T) => z.array(item).max(32);

export const agentMessageSchema = z.discriminatedUnion("type", [
  z.strictObject({
    type: z.literal("hello"),
    v: z.literal(WIRE_VERSION),
    version: z.string().min(1).max(64),
    hostname: z.string().min(1).max(255),
    os: z.string().min(1).max(64),
    arch: z.string().min(1).max(64),
    kernel: z.string().min(1).max(128),
    kind: z.enum(["server", "laptop"]),
    sealKey: sealKeySchema,
    trust: trustReportSchema.nullable(),
    network: networkHelloSchema.nullable(),
  }),
  z.strictObject({
    type: z.literal("progress"),
    id,
    line: z.string().max(512),
  }),
  z.strictObject({
    type: z.literal("result"),
    id,
    ok: z.boolean(),
    message: z.string().max(2048),
    output: z.string().max(65536).optional(),
    trust: trustReportSchema.optional(),
  }),
  z.strictObject({
    type: z.literal("applied"),
    version: z.number().int().nonnegative(),
    ok: z.boolean(),
    message: z.string().max(2048),
  }),
  z.strictObject({
    type: z.literal("links"),
    links: upTo32(networkLinkSchema),
  }),
  z.strictObject({
    type: z.literal("announce"),
    key: wireguardKey,
    signature: b64url,
  }),
  z.strictObject({ type: z.literal("meet"), via: nodeId }),
  inventorySchema,
  checkSchema,
]);

export const hubMessageSchema = z.discriminatedUnion("type", [
  z
    .strictObject({
      type: z.literal("command"),
      id,
      kind: z.enum(COMMAND_KINDS),
      name: z.string().min(1).max(128),
      action: z.string().min(1).max(64),
      signed: z.string().min(1),
    })
    .refine((command) =>
      COMMAND_ACTIONS[command.kind].includes(command.action),
    ),
  z.strictObject({ type: z.literal("ack"), id }),
  z.strictObject({
    type: z.literal("document"),
    version: z.number().int().positive(),
    signed: z.string().min(1).max(524288),
  }),
  z.strictObject({
    type: z.literal("hints"),
    endpoints: upTo32(z.strictObject({ key: wireguardKey, endpoint })),
    announced: upTo32(
      z.strictObject({ node: nodeId, key: wireguardKey, signature: b64url }),
    ),
    meetings: upTo32(z.strictObject({ laptop: nodeId, via: nodeId })),
    held: upTo32(nodeId),
    connected: upTo32(nodeId),
  }),
  z.strictObject({ type: z.literal("refresh") }),
  checksSchema,
]);

export type TrustReport = z.infer<typeof trustReportSchema>;
export type NetworkHello = z.infer<typeof networkHelloSchema>;
export type AgentMessage = z.infer<typeof agentMessageSchema>;
export type HubMessage = z.infer<typeof hubMessageSchema>;

function parse<T>(schema: z.ZodType<T>, raw: string): T | null {
  try {
    const result = schema.safeParse(JSON.parse(raw));
    return result.success ? result.data : null;
  } catch {
    return null;
  }
}

export const parseAgentMessage = (raw: string) =>
  parse(agentMessageSchema, raw);

export const parseHubMessage = (raw: string) => parse(hubMessageSchema, raw);
