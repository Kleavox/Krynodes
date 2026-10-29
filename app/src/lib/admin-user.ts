import { ADMIN_NAME } from "@krynodes/protocol";
import { FEATURE_AGENT } from "@krynodes/protocol/versions";

import type { NodeRecord } from "../types";
import { agentGap, FIRST_REPORT } from "./devices";

export interface AdminKey {
  line: string;
  type: string;
  fingerprint: string;
  label: string;
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

export async function addKeys(
  text: string,
  keys: AdminKey[],
): Promise<{ keys: AdminKey[]; rest: string; note: string | null }> {
  const next = [...keys];
  const wrong: string[] = [];
  let repeated = 0;
  let over = 0;
  for (const line of text.split("\n").map((part) => part.trim())) {
    if (line === "" || line.startsWith("#")) continue;
    const row = await keyRow(line, next.length);
    if (!row) wrong.push(line);
    else if (next.some((key) => key.fingerprint === row.fingerprint)) {
      repeated += 1;
    } else if (next.length >= MAX_ADMIN_KEYS) over += 1;
    else next.push(row);
  }
  const notes = [
    wrong.length === 1 && "1 line is not a public key.",
    wrong.length > 1 && `${wrong.length} lines are not public keys.`,
    over > 0 && `Up to ${MAX_ADMIN_KEYS} keys: ${over} left out.`,
    next.length === keys.length &&
      wrong.length === 0 &&
      over === 0 &&
      repeated > 0 &&
      (repeated === 1
        ? "That key is already here."
        : "Those keys are already here."),
  ].filter((note) => typeof note === "string");
  return {
    keys: next,
    rest: wrong.join("\n"),
    note: notes.length > 0 ? notes.join(" ") : null,
  };
}

const linesOf = (keys: AdminKey[]) => keys.map((key) => key.line).join("\n");

export const keysChanged = (before: AdminKey[], after: AdminKey[]) =>
  linesOf(before) !== linesOf(after);

export async function keysDigest(lines: string[]): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(lines.join("\n")),
  );
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

const NO_KEYS = "Add your SSH public keys in Enroll Defaults first.";

export function adminOption(keys: AdminKey[]): {
  available: boolean;
  text: string;
} {
  if (keys.length === 0) return { available: false, text: NO_KEYS };
  const count = keys.length;
  return {
    available: true,
    text: `A sudo user that logs in with your ${count} SSH ${count === 1 ? "key" : "keys"} from Enroll Defaults. The server asks for its password on its own screen, then turns root login off.`,
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
  keys: AdminKey[],
): string | null {
  const gap = agentGap(node.agent_version, FEATURE_AGENT);
  if (gap === FIRST_REPORT) return gap;
  if (gap !== null) return `${gap} · ${node.name} runs ${node.agent_version}`;
  return keys.length === 0 ? NO_KEYS : null;
}

export const loginLine = (name: string, address: string | null) =>
  address ? `ssh ${name}@${address}` : null;
