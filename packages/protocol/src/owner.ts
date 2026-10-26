export type CheckOwner =
  | { kind: "stack"; project: string }
  | { kind: "container"; name: string }
  | { kind: "systemd"; unit: string };

export interface OwnerServer {
  stacks: { project: string; containers?: string[] }[];
  services: { kind: "systemd" | "docker"; name: string }[];
  webAddresses?: { hostname: string; project: string }[];
}

const unitName = (name: string) =>
  name.endsWith(".service") ? name : `${name}.service`;

const HOST = /^https?:\/\/(?:[^@/?#]*@)?(\[[^\]]+\]|[^:/?#]+)/iu;

function hostnameOf(target: string): string | null {
  return HOST.exec(target.trim())?.[1]?.toLowerCase() ?? null;
}

export function ownerOf(
  check: { kind: string; target: string },
  server: OwnerServer,
): CheckOwner | null {
  switch (check.kind) {
    case "CONTAINER": {
      const listed = server.services.some(
        (service) => service.kind === "docker" && service.name === check.target,
      );
      if (!listed) return null;
      const stack = server.stacks.find((entry) =>
        entry.containers?.includes(check.target),
      );
      return stack
        ? { kind: "stack", project: stack.project }
        : { kind: "container", name: check.target };
    }
    case "SERVICE": {
      const unit = unitName(check.target);
      return server.services.some(
        (service) => service.kind === "systemd" && service.name === unit,
      )
        ? { kind: "systemd", unit }
        : null;
    }
    case "HTTP": {
      const hostname = hostnameOf(check.target);
      const address = server.webAddresses?.find(
        (entry) => entry.hostname.toLowerCase() === hostname,
      );
      return hostname && address
        ? { kind: "stack", project: address.project }
        : null;
    }
    default:
      return null;
  }
}

export function touches(
  owner: CheckOwner,
  action: { kind: string; name: string },
  server: OwnerServer,
): boolean {
  switch (owner.kind) {
    case "stack":
      return (
        (action.kind === "compose" && action.name === owner.project) ||
        (action.kind === "docker" &&
          (server.stacks
            .find((stack) => stack.project === owner.project)
            ?.containers?.includes(action.name) ??
            false))
      );
    case "container":
      return action.kind === "docker" && action.name === owner.name;
    case "systemd":
      return action.kind === "systemd" && unitName(action.name) === owner.unit;
  }
}

export const NOT_WORK: readonly string[] = [
  "logs",
  "read",
  "export",
  "scan",
  "autorestart",
  "manual",
  "heal",
  "trust",
  "store",
  "release",
  "reshare",
  "forget",
  "refresh",
  "find",
  "preview",
];

export const isWork = (action: { action: string }) =>
  !NOT_WORK.includes(action.action);

export function workTouches(
  check: { kind: string; target: string },
  action: { kind: string; name: string; action: string },
  server: OwnerServer,
): boolean {
  if (!isWork(action)) return false;
  if (action.kind === "host") return true;
  const owner = ownerOf(check, server);
  return owner !== null && touches(owner, action, server);
}
