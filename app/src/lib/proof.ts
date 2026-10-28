import { openSession } from "./deploy-session";
import { ApiError, apiFetch, errorMessage } from "./http";
import { signIntent } from "./passkeys";

const NOT_CONFIRMED =
  "The passkey was not confirmed. If this device cannot open it, choose Use a phone in the passkey window.";

export function failure(error: unknown): string {
  if (error instanceof DOMException && error.name === "InvalidStateError") {
    return "This passkey is already registered.";
  }
  if (!(error instanceof DOMException && error.name === "NotAllowedError")) {
    return errorMessage(error);
  }
  return NOT_CONFIRMED;
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
