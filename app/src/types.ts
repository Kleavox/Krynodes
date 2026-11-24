import type { NetworkDocument, NetworkRule } from "@krynodes/protocol";

export interface Identity {
  id: string;
  email: string;
  username: string | null;
}

export type SessionVia = "access" | "standalone";

export interface SessionResponse {
  authenticated: boolean;
  via: SessionVia;
  identity?: Identity;
}

export type ActionKind = "trust" | "agent" | "host" | "network";

export interface ActionRow {
  id: string;
  nodeId: string;
  kind: ActionKind;
  name: string;
  action: string;
  title: string;
  status: "sent" | "running" | "done" | "failed";
  message: string | null;
  output: string | null;
  createdAt: string;
  finishedAt: string | null;
}

export interface FleetNode {
  id: string;
  name: string;
  hostname: string | null;
  os: string | null;
  arch: string | null;
  version: string | null;
  online: boolean;
  lastSeenAt: string | null;
  trust: { version: number; core: string[]; access: string[] } | null;
  update: string | null;
  kind: "server" | "laptop";
  address: string | null;
  via: string | null;
  ms: number | null;
  request: "requested" | "rejected" | null;
}

export interface Device {
  id: string;
  name: string;
  alg: number;
  publicKey: string;
  synced: boolean;
  createdAt: string;
  trusted: boolean;
}

export interface Enrollment {
  id: string;
  command: string;
  expiresAt: string;
}

export interface RegisterOptions {
  challenge: string;
  rpId: string;
  user: { id: string; name: string };
  exclude: string[];
  expiresAt: string;
}

interface NetworkMemberView {
  node: string;
  name: string;
  kind: "server" | "laptop";
  state: "in" | "leaving";
  address: string | null;
  key: string | null;
  signer: string | null;
  port: number | null;
  mtu: number | null;
  endpoint: string | null;
  nat: boolean;
  applied: number;
  failure: string | null;
  announced: { key: string; signature: string } | null;
  since: string;
  joinedAt: string | null;
}

export interface JoinRequest {
  node: string;
  name: string;
  kind: "server" | "laptop";
  hostname: string | null;
  os: string | null;
  key: string | null;
  signer: string | null;
  sealKey: string | null;
  ready: boolean;
  reason: string | null;
  since: string;
}

export interface NetworkView {
  network: {
    range: string;
    port: number;
    mtu: number;
    version: number;
    dns: string[] | null;
    deleted: boolean;
  } | null;
  members: NetworkMemberView[];
  requests: JoinRequest[];
  rejected: { node: string; name: string }[];
  allow: NetworkRule[];
  links: {
    a: string;
    b: string;
    answering: boolean;
    ms: number | null;
    since: string;
  }[];
}

interface PreparedKeys {
  key: string | null;
  signer: string | null;
  port: number | null;
  mtu: number | null;
}

export interface NetworkApplied {
  version: number;
  members: {
    node: string;
    name: string;
    applied: number;
    failure: string | null;
    online: boolean;
  }[];
}

export interface NetworkNext {
  document: NetworkDocument | null;
  hash: string | null;
  prepared: Record<string, PreparedKeys>;
  addresses: Record<string, string>;
  seen?: Record<string, string | null>;
  relayPorts: Record<string, Record<string, number>>;
}

export interface NetworkChange {
  id: string;
  at: string;
  change: string;
  detail: string | null;
  nodes: string[];
}

export interface LaptopCode {
  code: string;
  expiresAt: string;
  origin: string;
  endpoint: string;
  download: string;
}
