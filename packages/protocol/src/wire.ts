import { z } from "zod";

import { sealKeySchema } from "./network";

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

export const agentMessageSchema = z.discriminatedUnion("type", [
  z.strictObject({
    type: z.literal("hello"),
    v: z.literal(WIRE_VERSION),
    version: z.string().min(1).max(64),
    hostname: z.string().min(1).max(255),
    os: z.string().min(1).max(64),
    arch: z.string().min(1).max(64),
    kernel: z.string().min(1).max(128),
    sealKey: sealKeySchema,
    trust: trustReportSchema.nullable(),
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
    trust: trustReportSchema.optional(),
  }),
]);

export const hubMessageSchema = z.discriminatedUnion("type", [
  z.strictObject({
    type: z.literal("command"),
    id,
    kind: z.enum(["trust", "agent", "host"]),
    name: z.string().min(1).max(128),
    action: z.string().min(1).max(64),
    signed: z.string().min(1),
  }),
  z.strictObject({ type: z.literal("ack"), id }),
]);

export type TrustReport = z.infer<typeof trustReportSchema>;
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
