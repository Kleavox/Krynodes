import { useDevices, useOverview, useProposals, useServices } from "@/lib/api";
import {
  decodeChange,
  trustedServers,
  type FleetServer,
  type FleetView,
} from "@/lib/devices";
import { thisBrowser } from "@/lib/passkeys";
import type { DeviceRecord, ProposalRecord } from "@/types";

export interface Fleet {
  view: FleetView;
  devices: DeviceRecord[];
  core: DeviceRecord[];
  pending: DeviceRecord[];
  joining: string[];
  mine: string[];
  servers: FleetServer[];
  trusted: FleetServer[];
  proposals: ProposalRecord[];
  open: ProposalRecord[];
  name: (id: string) => string;
}

export function useFleet(poll = false): Fleet | null {
  const devices = useDevices(poll);
  const overview = useOverview();
  const services = useServices();
  const proposals = useProposals();
  if (!devices.data || !overview.data || !services.data || !proposals.data) {
    return null;
  }
  const trust = new Map(
    services.data.nodes.map((node) => [node.id, node.trust]),
  );
  const servers = overview.data.nodes
    .filter((node) => node.enrolled_at !== null && node.disabled_at === null)
    .map((node) => ({ node, trust: trust.get(node.id) ?? null }));
  const view: FleetView = {
    origin: window.location.origin,
    devices: devices.data.devices,
    servers,
  };
  const list = devices.data.devices;
  const known = new Set(thisBrowser());
  const names = new Map(list.map((device) => [device.id, device.name]));
  for (const proposal of proposals.data.proposals) {
    for (const key of decodeChange(proposal.change)?.core ?? []) {
      if (!names.has(key.id)) names.set(key.id, key.name);
    }
  }
  const version = (nodeId: string) =>
    servers.find((server) => server.node.id === nodeId)?.trust?.version ?? 0;
  const joining = proposals.data.proposals.flatMap((proposal) => {
    const change =
      proposal.status === "applied" ? decodeChange(proposal.change) : null;
    if (!change?.core) return [];
    const behind = Object.keys(change.access).some(
      (nodeId) => version(nodeId) < change.version,
    );
    return behind ? change.core.map((key) => key.id) : [];
  });
  return {
    view,
    devices: list,
    core: list.filter((device) => device.core),
    pending: list.filter((device) => !device.core),
    joining,
    mine: list
      .filter((device) => known.has(device.id))
      .map((device) => device.id),
    servers,
    trusted: trustedServers(view),
    proposals: proposals.data.proposals,
    open: proposals.data.proposals.filter(
      (proposal) => proposal.status === "open",
    ),
    name: (id) => names.get(id) ?? "An unknown passkey",
  };
}
