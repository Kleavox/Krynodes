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

export type ActionKind = "trust" | "agent" | "host";

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
