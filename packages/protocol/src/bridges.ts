import { z } from "zod";

export { BRIDGE_NAME } from "./targets";
export const OFFER_ENTRY =
  /^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}\/[A-Za-z0-9][A-Za-z0-9_.-]{0,62}=\d{1,5}\/(tcp|udp)$/u;
export const PEER_ENTRY =
  /^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}\/[A-Za-z0-9][A-Za-z0-9_.-]{0,62}\.[a-z0-9][a-z0-9_-]{0,62}:\d{1,5}\/(tcp|udp)$/u;
export const ADMIN_NAME = /^[a-z_][a-z0-9_-]{0,31}$/u;
export const ADMIN_KEY_ARG = /^[A-Za-z0-9+/]+={0,3}:[A-Za-z0-9._-]{1,32}$/u;

const label = z.string().min(1).max(255);

export const bridgesReportSchema = z.strictObject({
  networks: z
    .array(
      z.strictObject({
        name: label,
        kind: z.enum(["contained", "full", "outside"]),
        subnet: z.string().max(43).nullable(),
        members: z
          .array(
            z.strictObject({
              project: label,
              service: label,
              address: z.string().max(45).nullable(),
              offers: z
                .array(z.string().regex(/^\d{1,5}\/(tcp|udp)$/u))
                .max(16),
              guest: z.boolean(),
            }),
          )
          .max(256),
      }),
    )
    .max(32),
  taken: z
    .array(
      z.strictObject({
        range: z.string().max(43),
        by: label,
        own: z.boolean().optional(),
      }),
    )
    .max(128),
  claimed: z.array(label).max(128),
});

export type BridgesReport = z.infer<typeof bridgesReportSchema>;
