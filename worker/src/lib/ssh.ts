const TYPES = [
  "ssh-ed25519",
  "ecdsa-sha2-nistp256",
  "ecdsa-sha2-nistp384",
  "ecdsa-sha2-nistp521",
  "sk-ssh-ed25519@openssh.com",
  "sk-ecdsa-sha2-nistp256@openssh.com",
  "ssh-rsa",
];
const BASE64 = /^[A-Za-z0-9+/]+={0,3}$/u;
const MAX_BLOB = 16384;

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

export const keyLabel = (comment: string, index: number) =>
  comment.replace(/[^A-Za-z0-9._-]/gu, "-").slice(0, 32) || `key${index + 1}`;

export function parseKeyLine(
  line: string,
  index = 0,
): { type: string; blob: string; label: string } | null {
  const [type = "", blob = "", ...comment] = line.trim().split(/\s+/u);
  if (
    !TYPES.includes(type) ||
    blob.length > MAX_BLOB ||
    !BASE64.test(blob) ||
    innerType(blob) !== type
  ) {
    return null;
  }
  return { type, blob, label: keyLabel(comment.join(" "), index) };
}

export async function fingerprint(blob: string): Promise<string> {
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", bytesOf(blob)),
  );
  return `SHA256:${btoa(String.fromCharCode(...digest)).replace(/=+$/u, "")}`;
}
