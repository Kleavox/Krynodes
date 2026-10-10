export const CHECK_KINDS = ["HTTP", "TCP", "SERVICE", "CONTAINER"] as const;

export type CheckKind = (typeof CHECK_KINDS)[number];

export const CONTAINER_AGENT = "0.6.3";

export function validateCheckTarget(
  kind: CheckKind,
  target: string,
): string | null {
  const value = target.trim();
  if (kind === "HTTP") {
    try {
      const url = new URL(value);
      return url.protocol === "http:" || url.protocol === "https:"
        ? url.href
        : null;
    } catch {
      return null;
    }
  }

  if (kind === "TCP") {
    const match = /^([a-zA-Z0-9.-]+):([0-9]{1,5})$/u.exec(value);
    if (!match) return null;
    const port = Number(match[2]);
    return port >= 1 && port <= 65_535 ? value.toLowerCase() : null;
  }

  if (kind === "CONTAINER") {
    return /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/u.test(value) ? value : null;
  }

  return /^[a-zA-Z0-9@_.:-]{1,128}$/u.test(value) ? value : null;
}
