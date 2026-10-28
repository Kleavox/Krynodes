import { openSession } from "./deploy-session";
import { ApiError, apiFetch, errorMessage } from "./http";
import { signIntent } from "./passkeys";

const NO_FINGERPRINT_HERE =
  "No fingerprint was confirmed. If this device has none, choose Use a phone in the passkey window.";

export function failure(error: unknown): string {
  if (error instanceof DOMException && error.name === "InvalidStateError") {
    return "This device is already registered.";
  }
  if (!(error instanceof DOMException && error.name === "NotAllowedError")) {
    return errorMessage(error);
  }
  return NO_FINGERPRINT_HERE;
}

interface Needed {
  op: string;
  target: string;
  core: string[];
}

export async function guardedFetch<T = unknown>(
  path: string,
  init: RequestInit,
  expected?: { op: string; target: string },
): Promise<T> {
  try {
    return await apiFetch<T>(path, init);
  } catch (error) {
    if (!(error instanceof ApiError) || error.code !== "PROOF_NEEDED") {
      throw error;
    }
    const needed = error.details as unknown as Needed;
    if (
      expected &&
      (needed.op !== expected.op || needed.target !== expected.target)
    ) {
      throw new Error(
        "Krynodes asked to confirm something else. Nothing was saved.",
      );
    }
    let proof: string;
    try {
      const session = await openSession(needed.core);
      proof = await signIntent(
        session,
        needed.op,
        needed.target,
        window.location.origin,
      );
    } catch (cause) {
      throw new Error(failure(cause));
    }
    return apiFetch<T>(path, {
      ...init,
      headers: { ...init.headers, "x-kry-proof": proof },
    });
  }
}
