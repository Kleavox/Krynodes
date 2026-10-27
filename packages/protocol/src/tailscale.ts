import { z } from "zod";

export const TAILSCALE = {
  tag: "tag:kry",
  hook: "/hooks/tailscale",
  events: ["nodeCreated", "policyUpdate"],
  keySeconds: 600,
  judgeMinutes: 3,
  judgeLimitMinutes: 15,
  appliedMinutes: 5,
  saveQuietMinutes: 2,
  tolerance: 300,
} as const;

const PORT = /^(\*|(\d{1,5})(-(\d{1,5}))?(\/(tcp|udp))?)$/u;

const inRange = (port: string) => {
  const match = PORT.exec(port);
  if (!match) return false;
  if (match[1] === "*") return true;
  const first = Number(match[2]);
  const last = match[4] === undefined ? first : Number(match[4]);
  return first >= 1 && last <= 65535 && first <= last;
};

export const portSchema = z.string().max(16).refine(inRange);

const nodeId = z.string().uuid();

export const ruleSchema = z.union([
  z.strictObject({ from: z.literal("devices"), to: z.literal("rest") }),
  z.strictObject({
    from: z.union([z.literal("devices"), z.literal("servers"), nodeId]),
    to: z.union([z.literal("servers"), nodeId]),
    ports: z.array(portSchema).min(1).max(32),
  }),
  z.strictObject({ raw: z.string().min(2).max(2000) }),
]);

export type TailnetRule = z.infer<typeof ruleSchema>;

export const reachSchema = z.strictObject({
  from: z.array(z.string().max(64)).max(32),
  ports: z.array(z.string().max(16)).max(32),
});

export const webhookBodySchema = z
  .array(
    z.object({
      timestamp: z.string().max(64),
      version: z.number().optional(),
      type: z.string().max(64),
      tailnet: z.string().max(253),
      message: z.string().max(2000).optional(),
      data: z.record(z.string(), z.unknown()).nullable().optional(),
    }),
  )
  .max(20);

export type WebhookEvent = z.infer<typeof webhookBodySchema>[number];
