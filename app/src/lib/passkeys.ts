import type { RegisterOptions } from "../types";
import { errorMessage } from "./http";

export interface Approval {
  credentialId: string;
  authenticatorData: string;
  clientDataJSON: string;
  signature: string;
}

export interface RegisterBody {
  id: string;
  name: string;
  alg: number;
  publicKey: string;
  challenge: string;
  assertion: Approval;
}

const encoder = new TextEncoder();

export function b64url(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = "";
  for (const byte of view) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}

export function fromB64url(text: string): Uint8Array<ArrayBuffer> {
  const padded = text.replaceAll("-", "+").replaceAll("_", "/");
  const binary = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

export const sha256 = async (bytes: Uint8Array<ArrayBuffer>) =>
  new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));

const NOT_TOUCHED =
  "The passkey was not touched. Try again and confirm on your device.";

const NOT_UNLOCKED =
  "This passkey was opened without your fingerprint, face or PIN. Open it with one of those, or choose Use a phone or a security key.";

const NOT_CONFIRMED =
  "The passkey was not confirmed. If this device cannot open it, choose Use a phone in the passkey window.";

const HINTS = ["client-device", "security-key", "hybrid"];

export function failure(error: unknown): string {
  if (error instanceof DOMException && error.name === "InvalidStateError") {
    return "This passkey is already registered.";
  }
  if (!(error instanceof DOMException && error.name === "NotAllowedError")) {
    return errorMessage(error);
  }
  return NOT_CONFIRMED;
}

export function nameFor(transports: string[], fallback: string): string {
  if (transports.includes("hybrid")) return "Phone";
  if (transports.some((item) => ["usb", "nfc", "ble"].includes(item))) {
    return "Security Key";
  }
  return fallback;
}

function requireUnlock(
  authenticatorData: ArrayBuffer,
  attachment: string | null | undefined,
) {
  const flags = new Uint8Array(authenticatorData)[32] ?? 0;
  if ((flags & 0x01) !== 0x01) {
    const detail = [
      `flags 0x${flags.toString(16).padStart(2, "0")}`,
      attachment ?? "unknown authenticator",
    ].join(", ");
    throw new Error(`${NOT_TOUCHED} (${detail})`);
  }
  if ((flags & 0x04) !== 0x04) throw new Error(NOT_UNLOCKED);
}

export async function assert(
  challenge: Uint8Array<ArrayBuffer>,
  rpId: string,
  allowed: string[],
): Promise<Approval> {
  const credential = (await navigator.credentials.get({
    publicKey: {
      challenge,
      rpId,
      allowCredentials: allowed.map((id) => ({
        type: "public-key" as const,
        id: fromB64url(id),
      })),
      userVerification: "required",
      hints: HINTS,
      timeout: 120_000,
    },
  })) as PublicKeyCredential | null;
  if (!credential) throw new Error("The passkey did not answer.");
  const response = credential.response as AuthenticatorAssertionResponse;
  requireUnlock(response.authenticatorData, credential.authenticatorAttachment);
  return {
    credentialId: credential.id,
    authenticatorData: b64url(response.authenticatorData),
    clientDataJSON: b64url(response.clientDataJSON),
    signature: b64url(response.signature),
  };
}

export async function registerDevice(
  options: RegisterOptions,
  name: string,
  { guessed = false } = {},
): Promise<RegisterBody> {
  const challenge = fromB64url(options.challenge);
  const credential = (await navigator.credentials.create({
    publicKey: {
      rp: { id: options.rpId, name: "Krynodes" },
      user: {
        id: encoder.encode(options.user.id),
        name: options.user.name,
        displayName: options.user.name,
      },
      challenge,
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 },
      ],
      authenticatorSelection: {
        userVerification: "required",
        residentKey: "preferred",
      },
      hints: HINTS,
      attestation: "none",
      excludeCredentials: options.exclude.map((id) => ({
        type: "public-key" as const,
        id: fromB64url(id),
      })),
      timeout: 120_000,
    },
  })) as PublicKeyCredential | null;
  if (!credential) throw new Error("No passkey was created.");
  const response = credential.response as AuthenticatorAttestationResponse;
  requireUnlock(
    response.getAuthenticatorData(),
    credential.authenticatorAttachment,
  );
  const publicKey = response.getPublicKey();
  if (!publicKey) {
    throw new Error("This browser does not share the passkey's public key.");
  }
  const assertion = await assert(challenge, options.rpId, [credential.id]);
  return {
    id: credential.id,
    name: guessed ? nameFor(response.getTransports?.() ?? [], name) : name,
    alg: response.getPublicKeyAlgorithm(),
    publicKey: b64url(publicKey),
    challenge: options.challenge,
    assertion,
  };
}
