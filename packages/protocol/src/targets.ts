const TARGET_NAME = /^[A-Za-z0-9][A-Za-z0-9@._-]{0,127}$/u;
const PROJECT_NAME = /^[a-z0-9][a-z0-9_-]{0,62}$/u;
export const BRIDGE_NAME = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$/u;
const APT_NAME = /^[a-z0-9][a-z0-9+.-]{0,127}$/u;
export const CONTAINER_NAME = /^[A-Za-z0-9][A-Za-z0-9_.-]{1,127}$/u;
export const SERVICE_NAME = /^[A-Za-z0-9._-]{1,128}$/u;
const MAX_STACK_NAMES = 64;

export const stackTitleValid = (title: string) =>
  title !== "" &&
  [...title].length <= 64 &&
  title.trim() === title &&
  !/\p{Cc}/u.test(title);

export const stackNamesValid = (names: Record<string, string>) => {
  const entries = Object.entries(names);
  return (
    entries.length <= MAX_STACK_NAMES &&
    entries.every(
      ([service, name]) =>
        SERVICE_NAME.test(service) && CONTAINER_NAME.test(name),
    ) &&
    new Set(entries.map(([, name]) => name)).size === entries.length
  );
};

export function parseStackNames(text: string): Record<string, string> | null {
  if (text === "") return {};
  const names: Record<string, string> = {};
  for (const entry of text.split(",")) {
    const [service = "", name, ...rest] = entry.split("=");
    if (name === undefined || rest.length > 0 || service in names) return null;
    names[service] = name;
  }
  return stackNamesValid(names) ? names : null;
}

export const RECIPES = [
  "security-updates",
  "reboot-window",
  "ssh-keys-only",
  "no-root-login",
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
  /^ufw\.service$/u,
  /^firewalld\.service$/u,
  /^nftables\.service$/u,
  /^netfilter-persistent\.service$/u,
  /^iptables\.service$/u,
  /^ip6tables\.service$/u,
];

export function isValidTarget(kind: string, name: string): boolean {
  if (kind === "compose") return PROJECT_NAME.test(name);
  if (kind === "trust") return name === "devices";
  if (kind === "host") {
    return (
      name === "server" ||
      name === "docker" ||
      name === "tailscale" ||
      (RECIPES as readonly string[]).includes(name)
    );
  }
  if (kind === "vault") return name === "cloudflare" || name === "tailscale";
  if (kind === "apt") return APT_NAME.test(name);
  if (kind === "network") return name === "kry0";
  if (kind === "bridge") return BRIDGE_NAME.test(name);
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
