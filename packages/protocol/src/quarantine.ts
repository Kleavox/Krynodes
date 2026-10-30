import { z } from "zod";

export const QUARANTINE = {
  cutoff: [5, 15, 30, 60, null],
  scan: [5, 10, 20],
  agree: [1, 2, 3],
  defaults: { cutoff: 15, scan: 10, agree: 2, stop: true },
  codeMinutes: 10,
  agreeMinutes: 10,
  readVerbs: ["logs", "read", "export", "scan", "refresh", "inspect"],
} as const;

export const EVENT_KINDS = [
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
] as const;

export const quarantineSettingsSchema = z.strictObject({
  cutoff: z.union([
    z.literal(5),
    z.literal(15),
    z.literal(30),
    z.literal(60),
    z.null(),
  ]),
  scan: z.union([z.literal(5), z.literal(10), z.literal(20)]),
  agree: z.union([z.literal(1), z.literal(2), z.literal(3)]),
  stop: z.boolean(),
});

export type QuarantineSettings = z.infer<typeof quarantineSettingsSchema>;

export function looser(
  before: QuarantineSettings,
  after: QuarantineSettings,
): boolean {
  const longer =
    before.cutoff !== null &&
    (after.cutoff === null || after.cutoff > before.cutoff);
  return (
    longer ||
    after.scan > before.scan ||
    after.agree > before.agree ||
    (before.stop && !after.stop)
  );
}

export const eventSchema = z.strictObject({
  id: z
    .string()
    .min(1)
    .max(64)
    .regex(/^[A-Za-z0-9_.:-]+$/u),
  kind: z.enum(EVENT_KINDS),
  at: z.string().datetime(),
  detail: z
    .record(z.string().max(32), z.string().max(500))
    .refine((detail) => Object.keys(detail).length <= 8),
});

export type QuarantineEvent = z.infer<typeof eventSchema>;

export const releaseSchema = z.strictObject({
  key: z.string().min(1).max(64),
  signer: z.string().min(1).max(64),
  seal: z
    .string()
    .min(1)
    .max(200)
    .regex(/^[A-Za-z0-9_-]+$/u),
  token: z.string().regex(/^[0-9a-f]{64}$/u),
  expires: z.string().datetime(),
});

export type PendingRelease = z.infer<typeof releaseSchema>;

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export const releaseText = (input: PendingRelease) =>
  [input.key, input.signer, input.seal, input.token, input.expires].join("\n");

export function codeOf(digest: Uint8Array): string {
  let bits = "";
  for (const byte of digest) bits += byte.toString(2).padStart(8, "0");
  let code = "";
  for (let index = 0; code.length < 10; index += 5) {
    code += BASE32[parseInt(bits.slice(index, index + 5), 2)];
  }
  return `${code.slice(0, 5)}-${code.slice(5)}`;
}
