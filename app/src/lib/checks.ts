import { compareVersions } from "@krynodes/protocol/versions";

import type { CheckKind, ServiceEntry, ServiceKind } from "../types";

export const TARGET_HINT: Record<CheckKind, string> = {
  HTTP: "Fetched from the node. Down on errors, timeouts and 5xx answers.",
  TCP: "Opened from the node. Down when the connection fails in time.",
  SERVICE: "A unit on the node. Up while systemd reports it active.",
  CONTAINER:
    "A container on the node. Up while Docker reports it running and not unhealthy.",
};

export const TARGET_PLACEHOLDER: Record<CheckKind, string> = {
  HTTP: "https://example.com/health",
  TCP: "127.0.0.1:5432",
  SERVICE: "Choose a service",
  CONTAINER: "Choose a container",
};

const PICKED: Partial<Record<CheckKind, ServiceKind>> = {
  SERVICE: "systemd",
  CONTAINER: "docker",
};

const CONTAINER_AGENT = "0.6.3";

export const pickedKind = (kind: CheckKind) => kind in PICKED;

export const containerChecksReady = (version: string | null) =>
  /^\d+\.\d+\.\d+$/u.test(version ?? "") &&
  compareVersions(version!, CONTAINER_AGENT) >= 0;

export function targetOptions(
  services: ServiceEntry[] | undefined,
  kind: CheckKind,
  current: string,
): { name: string; seen: boolean }[] {
  const wanted = PICKED[kind];
  if (!wanted) return [];
  const names = [
    ...new Set(
      (services ?? [])
        .filter((entry) => entry.kind === wanted)
        .map((entry) => entry.name),
    ),
  ].sort((a, b) => a.localeCompare(b));
  const options = names.map((name) => ({ name, seen: true }));
  return current && !names.includes(current)
    ? [{ name: current, seen: false }, ...options]
    : options;
}

export function checkTargetProblem(
  kind: CheckKind,
  target: string,
): string | null {
  const value = target.trim();
  if (value === "" && kind === "CONTAINER") return "Choose a container.";
  if (value === "" && kind === "SERVICE") return "Choose a service.";
  if (value === "") return "Enter a target.";
  if (kind === "HTTP") {
    try {
      const url = new URL(value);
      if (url.protocol === "http:" || url.protocol === "https:") return null;
    } catch {
      return "Use a full URL starting with http:// or https://.";
    }
    return "Use a full URL starting with http:// or https://.";
  }
  if (kind === "TCP") {
    const match = /^([a-zA-Z0-9.-]+):([0-9]{1,5})$/u.exec(value);
    if (!match) return "Use host:port, such as 127.0.0.1:5432.";
    const port = Number(match[2]);
    return port >= 1 && port <= 65_535
      ? null
      : "The port must be between 1 and 65535.";
  }
  if (kind === "CONTAINER") {
    return /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/u.test(value)
      ? null
      : "Choose a container.";
  }
  return /^[a-zA-Z0-9@_.:-]{1,128}$/u.test(value)
    ? null
    : "Use a systemd unit name, such as nginx.service.";
}
