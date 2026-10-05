const TARGET_NAME = /^[A-Za-z0-9][A-Za-z0-9@._-]{0,127}$/u;
const PROJECT_NAME = /^[a-z0-9][a-z0-9_-]{0,62}$/u;

export const RECIPES = [
  "security-updates",
  "reboot-window",
  "ssh-keys-only",
  "fail2ban",
  "firewall",
  "free-port-53",
] as const;

const PROTECTED_UNITS = [
  /^ssh\.service$/u,
  /^sshd\.service$/u,
  /^krynodes\.service$/u,
  /^krynodes-.+\.service$/u,
  /^docker\.service$/u,
  /^containerd\.service$/u,
  /^systemd-.+\.service$/u,
  /^dbus\.service$/u,
  /^dbus-broker\.service$/u,
  /^networking\.service$/u,
  /^NetworkManager\.service$/u,
  /^cloudflared\.service$/u,
  /^cloudflared-.+\.service$/u,
  /^getty@.*\.service$/u,
  /^serial-getty@.*\.service$/u,
  /^user@.*\.service$/u,
  /^snap\.docker\..+\.service$/u,
];

export function isValidTarget(kind: string, name: string): boolean {
  if (kind === "compose") return PROJECT_NAME.test(name);
  if (kind === "trust") return name === "devices";
  if (kind === "host") {
    return name === "server" || (RECIPES as readonly string[]).includes(name);
  }
  if (kind === "vault") return name === "cloudflare";
  if (!TARGET_NAME.test(name)) return false;
  if (kind === "systemd") return name.endsWith(".service");
  return kind === "docker";
}

export function isProtectedTarget(kind: string, name: string): boolean {
  if (kind === "docker") return name === "krynodes-tunnel";
  return (
    kind === "systemd" && PROTECTED_UNITS.some((pattern) => pattern.test(name))
  );
}
