import type { Env } from "../env";
import { fromB64url } from "../lib/b64url";
import { verifyAssertion } from "../lib/webauthn";
import type { Fleet } from "./fleet";

interface Approval {
  credentialId: string;
  authenticatorData: string;
  clientDataJSON: string;
  signature: string;
  proof?: string;
}

export class Refusal extends Error {
  readonly status: 400 | 403 | 404 | 409 | 410 | 422;
  readonly code: string;

  constructor(
    status: 400 | 403 | 404 | 409 | 410 | 422,
    code: string,
    message: string,
  ) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

const handle = (email: string) => email.split("@")[0] || email;

export function notYours(
  device: { name: string; account: string | null },
  email: string,
): Refusal | null {
  return device.account !== null && device.account !== email
    ? new Refusal(
        403,
        "NOT_YOUR_DEVICE",
        `${device.name} belongs to ${handle(device.account)}. Use one of your own devices.`,
      )
    : null;
}

export async function verifyApproval(
  env: Env,
  fleet: Fleet,
  bytes: Uint8Array<ArrayBuffer>,
  approval: Approval,
  email: string,
) {
  const device = fleet.devices.find(
    (entry) => entry.id === approval.credentialId && entry.removedAt === null,
  );
  if (!device || !fleet.core.includes(device.id)) {
    throw new Refusal(403, "NOT_CORE", "Use a trusted passkey.");
  }
  const refused = notYours(device, email);
  if (refused) throw refused;
  const origin = new URL(env.PUBLIC_ORIGIN);
  let uv: boolean;
  try {
    ({ uv } = await verifyAssertion(device, approval, {
      origin: origin.origin,
      rpId: origin.hostname,
      challenge: new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)),
    }));
  } catch (error) {
    throw new Refusal(
      400,
      "BAD_APPROVAL",
      `The approval did not verify: ${(error as Error).message}.`,
    );
  }
  if (!uv) {
    throw new Refusal(
      400,
      "FINGERPRINT_NEEDED",
      "This passkey was opened without your fingerprint, face or PIN. Open it with one of those, or choose Use a phone in the passkey window.",
    );
  }
  if (device.account === null) {
    await env.DB.prepare(
      "UPDATE devices SET account = ? WHERE id = ? AND account IS NULL",
    )
      .bind(email, device.id)
      .run();
  }
}

export async function ownersRefusal(
  env: Env,
  fleet: Fleet,
  grants: (Approval & { grant: string })[],
  email: string,
): Promise<Refusal | null> {
  const distinct = new Map(grants.map((grant) => [grant.credentialId, grant]));
  for (const grant of distinct.values()) {
    const refused = await signedByOwner(env, fleet, grant, email);
    if (refused) return refused;
  }
  return null;
}

async function signedByOwner(
  env: Env,
  fleet: Fleet,
  grant: Approval & { grant: string },
  email: string,
): Promise<Refusal | null> {
  const device = fleet.devices.find(
    (entry) => entry.id === grant.credentialId && entry.removedAt === null,
  );
  if (!device) return null;
  const refused = notYours(device, email);
  if (refused || device.account !== null) return refused;
  try {
    await verifyApproval(env, fleet, fromB64url(grant.grant), grant, email);
    return null;
  } catch (error) {
    if (error instanceof Refusal) return error;
    throw error;
  }
}
