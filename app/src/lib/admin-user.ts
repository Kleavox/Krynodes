import { ADMIN_NAME } from "@krynodes/protocol";
import { agentHasFeatures, FEATURE_AGENT } from "@krynodes/protocol/versions";

import type { NodeRecord } from "../types";

export interface AdminKey {
  line: string;
  type: string;
  fingerprint: string;
  label: string;
}

export interface EnrollAdmin {
  name: string;
  keys: AdminKey[];
}

const TYPES: Record<string, string> = {
  "ssh-ed25519": "ED25519",
  "ecdsa-sha2-nistp256": "ECDSA",
  "ecdsa-sha2-nistp384": "ECDSA",
  "ecdsa-sha2-nistp521": "ECDSA",
  "sk-ssh-ed25519@openssh.com": "ED25519-SK",
  "sk-ecdsa-sha2-nistp256@openssh.com": "ECDSA-SK",
  "ssh-rsa": "RSA",
};
const BASE64 = /^[A-Za-z0-9+/]+={0,3}$/u;
const MAX_BLOB = 16384;

export const MAX_ADMIN_KEYS = 4;

const NAME_HINT =
  "Lowercase letters, digits, dashes and underscores. Not root.";

const bytesOf = (blob: string) =>
  Uint8Array.from(atob(blob), (char) => char.charCodeAt(0));

function innerType(blob: string): string | null {
  try {
    const bytes = bytesOf(blob);
    if (bytes.length < 4) return null;
    const length = new DataView(bytes.buffer).getUint32(0);
    if (length > bytes.length - 4) return null;
    return new TextDecoder().decode(bytes.subarray(4, 4 + length));
  } catch {
    return null;
  }
}

export const keyText = (
  key: Pick<AdminKey, "type" | "fingerprint" | "label">,
) => `${TYPES[key.type] ?? key.type} ${key.fingerprint} ${key.label}`;

export async function keyRow(
  line: string,
  index: number,
): Promise<AdminKey | null> {
  const [type = "", blob = "", ...comment] = line.trim().split(/\s+/u);
  if (
    !(type in TYPES) ||
    blob.length > MAX_BLOB ||
    !BASE64.test(blob) ||
    innerType(blob) !== type
  ) {
    return null;
  }
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", bytesOf(blob)),
  );
  return {
    line: line.trim(),
    type,
    fingerprint: `SHA256:${btoa(String.fromCharCode(...digest)).replace(/=+$/u, "")}`,
    label:
      comment
        .join(" ")
        .replace(/[^A-Za-z0-9._-]/gu, "-")
        .slice(0, 32) || `key${index + 1}`,
  };
}

export const adminNameProblem = (name: string) =>
  name === "" || (ADMIN_NAME.test(name) && name !== "root") ? null : NAME_HINT;

export function adminProblem(name: string, keys: AdminKey[]): string | null {
  const named = name.trim();
  if (named === "" && keys.length === 0) return null;
  if (named === "") return "Type the admin user's name.";
  if (keys.length === 0) return "Add at least one SSH public key.";
  return adminNameProblem(named);
}

const linesOf = (admin: EnrollAdmin | null) =>
  admin ? [admin.name, ...admin.keys.map((key) => key.line)].join("\n") : "";

export const adminChanged = (
  before: EnrollAdmin | null,
  after: EnrollAdmin | null,
) => linesOf(before) !== linesOf(after);

export async function adminDigest(
  admin: { name: string; keys: string[] } | null,
): Promise<string> {
  const text = admin ? `${admin.name}\n${admin.keys.join("\n")}` : "";
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text),
  );
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export function adminOption(admin: EnrollAdmin | null): {
  available: boolean;
  text: string;
} {
  if (!admin || admin.keys.length === 0) {
    return {
      available: false,
      text: "Set an admin user in Enroll Defaults first.",
    };
  }
  const count = admin.keys.length;
  return {
    available: true,
    text: `${admin.name}, with sudo and ${count} SSH ${count === 1 ? "key" : "keys"} from Enroll Defaults. The server asks for its password on its own screen, then turns root login off.`,
  };
}

export const adminArgs = (name: string, keys: AdminKey[]) => ({
  name,
  keys: keys
    .map((key) => `${key.line.trim().split(/\s+/u)[1]}:${key.label}`)
    .join(","),
});

export const adminCommand = (name: string) => `sudo kry admin-user ${name}`;

export function adminBlocker(
  node: Pick<NodeRecord, "name" | "agent_version">,
  admin: EnrollAdmin | null,
): string | null {
  if (!agentHasFeatures(node.agent_version)) {
    return `Needs agent ${FEATURE_AGENT} · ${node.name} runs ${node.agent_version ?? "--"}`;
  }
  if (!admin || admin.keys.length === 0) {
    return "Add your SSH public keys in Enroll Defaults first.";
  }
  return null;
}

export const loginLine = (name: string, address: string | null) =>
  address ? `ssh ${name}@${address}` : null;
