import { z } from "zod";

const b64url = /^[A-Za-z0-9_-]+$/u;
const credential = z.string().min(1).max(1400).regex(b64url);

export const TRUST_VERSION_STEP = 1000;

export const trustKeySchema = z.strictObject({
  id: credential,
  name: z.string().min(1).max(40),
  alg: z.union([z.literal(-7), z.literal(-257)]),
  publicKey: z.string().min(1).max(4096).regex(b64url),
});

export const passphraseKeySchema = z.strictObject({
  salt: z.string().min(1).max(64).regex(b64url),
  iterations: z.number().int().min(100000).max(10000000),
  publicKey: z.string().min(1).max(64).regex(b64url),
});

export const trustChangeSchema = z
  .strictObject({
    v: z.literal(2),
    origin: z.string().url(),
    rpId: z.string().min(1).max(253),
    version: z.number().int().positive(),
    issuedAt: z.string().datetime(),
    expiresAt: z.string().datetime(),
    core: z.array(trustKeySchema).min(1).max(20).nullable(),
    passphrase: passphraseKeySchema.nullable(),
    requireUv: z.literal(true).optional(),
    access: z.record(z.string().uuid(), z.array(credential).max(20)),
  })
  .refine((change) => {
    const targets = Object.keys(change.access).length;
    return targets >= 1 && targets <= 100;
  });

export type TrustKeyRecord = z.infer<typeof trustKeySchema>;
export type PassphraseKeyRecord = z.infer<typeof passphraseKeySchema>;
export type TrustChange = z.infer<typeof trustChangeSchema>;
