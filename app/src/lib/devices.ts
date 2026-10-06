import type { TrustChange, TrustKeyRecord } from "@krynodes/protocol";
import { evaluateQuorum } from "@krynodes/protocol/quorum";
import {
  summarizeChange,
  type ChangeSummary,
} from "@krynodes/protocol/summary";

import type { DeviceRecord, NodeRecord, NodeTrust } from "../types";
import { agentSupported, compareVersions } from "@krynodes/protocol/versions";
import { b64url, fromB64url } from "./passkeys";

const CHANGE_MS = 24 * 3_600_000;

export interface FleetServer {
  node: NodeRecord;
  trust: NodeTrust | null;
}

export interface FleetView {
  origin: string;
  devices: DeviceRecord[];
  servers: FleetServer[];
}

export interface Plan {
  core: TrustKeyRecord[] | null;
  requireUv?: true;
  access: Record<string, string[]>;
}

export type ServerState = "update" | "empty" | "behind" | "current";

export async function fingerprint(publicKey: string): Promise<string> {
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", fromB64url(publicKey)),
  );
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0"))
    .join("")
    .slice(0, 16);
}

export const formatPrint = (print: string) =>
  (print.toUpperCase().match(/.{1,4}/gu) ?? []).join(" ");

export const agentCurrent = (node: Pick<NodeRecord, "agent_version">) =>
  agentSupported(node.agent_version);

export function canRestartServer(
  node: Pick<NodeRecord, "agent_version">,
  trust: NodeTrust | null,
): boolean {
  return agentCurrent(node) && (trust?.access.length ?? 0) > 0;
}

export function accessIds(
  devices: DeviceRecord[],
  trust: NodeTrust | null,
): string[] {
  return devices
    .filter((device) => trust?.access.includes(device.fingerprint))
    .map((device) => device.id);
}

const coreIds = (devices: DeviceRecord[], trust: NodeTrust | null) =>
  devices
    .filter((device) => trust?.core.includes(device.fingerprint))
    .map((device) => device.id);

export function signersFor(
  devices: DeviceRecord[],
  targets: (NodeTrust | null)[],
): string[] {
  if (targets.length === 0) return [];
  return devices
    .filter((device) =>
      targets.every((trust) => trust?.access.includes(device.fingerprint)),
    )
    .map((device) => device.id);
}

const coreOf = (view: FleetView) =>
  view.devices.filter((device) => device.core);

const keyOf = ({ id, name, alg, publicKey }: DeviceRecord): TrustKeyRecord => ({
  id,
  name,
  alg: alg as TrustKeyRecord["alg"],
  publicKey,
});

const sameSet = (a: string[], b: string[]) =>
  a.length === b.length && a.every((item) => b.includes(item));

export const trustedServers = (view: FleetView) =>
  view.servers.filter((server) => (server.trust?.core.length ?? 0) > 0);

export function serverState(view: FleetView, server: FleetServer): ServerState {
  if (!agentCurrent(server.node)) return "update";
  if (!server.trust || server.trust.core.length === 0) return "empty";
  const core = coreOf(view).map((device) => device.fingerprint);
  return sameSet(server.trust.core, core) ? "current" : "behind";
}

export function appliedOn(
  view: FleetView,
  change: { version: number; targets: string[] },
) {
  const servers = view.servers.filter((server) =>
    change.targets.includes(server.node.id),
  );
  return {
    done: servers.filter(
      (server) => (server.trust?.version ?? 0) >= change.version,
    ).length,
    total: servers.length,
  };
}

export function nextVersion(view: FleetView): number {
  return (
    Math.max(1, ...view.servers.map((server) => server.trust?.version ?? 0)) + 1
  );
}

const currentAccess = (view: FleetView) =>
  Object.fromEntries(
    trustedServers(view).map((server) => [
      server.node.id,
      accessIds(view.devices, server.trust),
    ]),
  );

export function buildChange(
  view: FleetView,
  plan: Plan & { now?: number; version?: number },
): string {
  const now = plan.now ?? Date.now();
  const change: TrustChange = {
    v: 2,
    origin: view.origin,
    rpId: new URL(view.origin).hostname,
    version: plan.version ?? nextVersion(view),
    issuedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + CHANGE_MS).toISOString(),
    core: plan.core,
    passphrase: null,
    ...(plan.requireUv ? { requireUv: true as const } : {}),
    access: plan.access,
  };
  return b64url(new TextEncoder().encode(JSON.stringify(change)));
}

const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

export function decodeChange(text: string): TrustChange | null {
  try {
    const value: unknown = JSON.parse(
      new TextDecoder().decode(fromB64url(text)),
    );
    if (
      !isObject(value) ||
      value.v !== 2 ||
      !isObject(value.access) ||
      !(value.core === null || Array.isArray(value.core)) ||
      !(value.passphrase === null || isObject(value.passphrase))
    ) {
      return null;
    }
    return value as unknown as TrustChange;
  } catch {
    return null;
  }
}

export const twinOf = (view: FleetView, device: DeviceRecord) =>
  coreOf(view).find(
    (entry) => entry.id !== device.id && entry.publicKey === device.publicKey,
  ) ?? null;

export function admitChange(view: FleetView, device: DeviceRecord): Plan {
  const core = coreOf(view);
  if (twinOf(view, device)) {
    return { core: core.map(keyOf), access: currentAccess(view) };
  }
  const founding = core.length < 2;
  return {
    core: [...core, device].map(keyOf),
    access: Object.fromEntries(
      Object.entries(currentAccess(view)).map(([nodeId, ids]) => [
        nodeId,
        founding ? [...ids, device.id] : ids,
      ]),
    ),
  };
}

export function removeChange(view: FleetView, device: DeviceRecord): Plan {
  return {
    core: coreOf(view)
      .filter((entry) => entry.id !== device.id)
      .map(keyOf),
    access: Object.fromEntries(
      Object.entries(currentAccess(view)).map(([nodeId, ids]) => [
        nodeId,
        ids.filter((id) => id !== device.id),
      ]),
    ),
  };
}

export function accessChange(
  view: FleetView,
  desired: Record<string, string[]>,
): Plan {
  const current = currentAccess(view);
  return {
    core: null,
    access: Object.fromEntries(
      Object.entries(desired).filter(
        ([nodeId, ids]) => !sameSet(ids, current[nodeId] ?? []),
      ),
    ),
  };
}

export function syncChange(view: FleetView): Plan {
  return { core: coreOf(view).map(keyOf), access: currentAccess(view) };
}

export function firstTrusts(
  view: FleetView,
  nodeIds: string[],
  founder: string,
  now = Date.now(),
): string[] {
  const known = coreOf(view);
  const core =
    known.length > 0
      ? known
      : view.devices.filter((device) => device.id === founder);
  const access = core.length < 2 ? core.map((device) => device.id) : [];
  return nodeIds.map((nodeId) =>
    buildChange(view, {
      core: core.map(keyOf),
      requireUv: true,
      access: { [nodeId]: access },
      version: 1,
      now,
    }),
  );
}

export function describeChange(
  view: FleetView,
  change: TrustChange,
): ChangeSummary {
  const names = Object.fromEntries(
    view.devices.map((device) => [device.id, device.name]),
  );
  for (const key of change.core ?? []) names[key.id] ??= key.name;
  return summarizeChange({
    names,
    servers: Object.fromEntries(
      view.servers.map((server) => [server.node.id, server.node.name]),
    ),
    currentCore: coreOf(view).map((device) => device.id),
    currentAccess: Object.fromEntries(
      view.servers.map((server) => [
        server.node.id,
        accessIds(view.devices, server.trust),
      ]),
    ),
    change: {
      core: change.core?.map((key) => key.id) ?? null,
      access: change.access,
    },
  });
}

export function predictMissing(
  view: FleetView,
  change: TrustChange,
  approvers: string[],
): string | null {
  for (const [nodeId, access] of Object.entries(change.access)) {
    const trust =
      view.servers.find((server) => server.node.id === nodeId)?.trust ?? null;
    const result = evaluateQuorum({
      current: {
        core: coreIds(view.devices, trust),
        access: accessIds(view.devices, trust),
      },
      change: {
        core: change.core?.map((key) => key.id) ?? null,
        access,
      },
      approvals: approvers,
    });
    if (!result.ok) return result.reason;
  }
  return null;
}
