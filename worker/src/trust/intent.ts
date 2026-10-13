import { SESSION_MS, signedCommandSchema } from "@krynodes/protocol";

import type { Env } from "../env";
import { decodeJson, fromB64url } from "../lib/b64url";
import type { KrynodesContext } from "../routes/shared";
import { Refusal, verifyApproval } from "./approval";
import { loadFleet, type Fleet } from "./fleet";

const INTENT_MS = 2 * 60_000;
const SKEW_MS = 60_000;

type Fields = Record<string, unknown> | null;

const bad = (message: string) => new Refusal(400, "BAD_PROOF", message);

async function verifyIntent(
  env: Env,
  fleet: Fleet,
  header: string | undefined,
  expected: { op: string; target: string },
  now = Date.now(),
): Promise<void> {
  if (fleet.core.length === 0) return;
  if (!header) {
    throw new Refusal(
      403,
      "PROOF_NEEDED",
      "Confirm with the passkey of a trusted device.",
    );
  }
  const signed = signedCommandSchema.safeParse(decodeJson(header));
  if (!signed.success) throw bad("The confirmation is malformed.");
  const { grant: grantText, ...approval } = signed.data.grant;
  const grantBytes = fromB64url(grantText);
  await verifyApproval(env, fleet, grantBytes, approval);

  const origin = new URL(env.PUBLIC_ORIGIN);
  const grant = decodeJson(grantText) as Fields;
  const issued = Date.parse(String(grant?.issuedAt));
  const expires = Date.parse(String(grant?.expiresAt));
  if (
    grant?.v !== 1 ||
    grant.rpId !== origin.hostname ||
    typeof grant.sessionKey !== "string" ||
    !(issued - SKEW_MS <= now && now <= expires) ||
    expires - issued > SESSION_MS
  ) {
    throw bad("The passkey session has ended. Confirm again.");
  }
  const intentBytes = fromB64url(signed.data.command);
  const key = await crypto.subtle
    .importKey(
      "spki",
      fromB64url(grant.sessionKey),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    )
    .catch(() => null);
  if (
    !key ||
    !(await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      fromB64url(signed.data.signature),
      intentBytes,
    ))
  ) {
    throw bad("The confirmation did not verify.");
  }
  const intent = decodeJson(signed.data.command) as Fields;
  if (
    intent?.v !== 1 ||
    intent.op !== expected.op ||
    intent.target !== expected.target ||
    intent.origin !== origin.origin ||
    !(Math.abs(now - Date.parse(String(intent.at))) <= INTENT_MS)
  ) {
    throw bad("The confirmation was for something else. Try again.");
  }
}

export function confirmingDevice(context: KrynodesContext): string | null {
  const header = context.req.header("x-kry-proof");
  const signed = header
    ? signedCommandSchema.safeParse(decodeJson(header))
    : null;
  return signed?.success ? signed.data.grant.credentialId : null;
}

export async function confirmed(
  context: KrynodesContext,
  op: string,
  target: string,
  fleet?: Fleet,
): Promise<Response | null> {
  const owned =
    fleet ?? (await loadFleet(context.env.DB, context.get("identity").id));
  try {
    await verifyIntent(context.env, owned, context.req.header("x-kry-proof"), {
      op,
      target,
    });
    return null;
  } catch (error) {
    if (!(error instanceof Refusal)) throw error;
    return context.json(
      {
        code: error.code,
        message: error.message,
        ...(error.code === "PROOF_NEEDED"
          ? {
              op,
              target,
              core: owned.core,
            }
          : {}),
      },
      error.status,
    );
  }
}
