import type {
  BridgesReport,
  NetworkDocument,
  NetworkLink,
  PackagesReport,
  PendingRelease,
  StackNetwork,
  TailnetRule,
  TailscaleReport,
} from "@krynodes/protocol";

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

export type AddressOwner = "own" | "router";

export interface Address {
  label: string;
  family: 4 | 6;
  address: string;
  router: boolean;
  network: string | null;
  owner: AddressOwner | null;
}

export interface NodeRecord {
  id: string;
  name: string;
  hostname: string | null;
  architecture: string | null;
  operating_system: string | null;
  agent_version: string | null;
  last_seen_at: string | null;
  enrolled_at: string | null;
  disabled_at: string | null;
  interval_seconds: number;
  cpu_percent: number | null;
  memory_used_bytes: number | null;
  memory_total_bytes: number | null;
  disk_used_bytes: number | null;
  disk_total_bytes: number | null;
  load_1: number | null;
  uptime_seconds: number | null;
  created_at: string;
  update_requested_version: string | null;
  update_requested_at: string | null;
  update_attempts?: number;
  update_error?: string | null;
  auto_update: number;
  deleting?: "running" | "stopped" | null;
  addresses?: Address[] | null;
  connected_at?: string;
  grace_seconds?: number;
  updates?: UpdatesSummary | null;
  tailscale?: TailscaleReport | null;
  network?: {
    state: "waiting" | "in" | "leaving";
    address: string | null;
    port: number;
  } | null;
  quarantine?: { at: string; why: string; tailnet?: string[] } | null;
  warnings?: NodeWarning[];
}

export interface NodeWarning {
  id: string;
  kind: string;
  detail: Record<string, string>;
  at: string;
  cutAt: string | null;
}

export interface QuarantineStep {
  nodeId: string;
  nodeName: string;
  action: ActionVerb;
  status: ActionStatus;
  finishedAt: string | null;
}

export interface QuarantineRecord {
  id: string;
  why: string;
  at: string;
  releasedAt: string | null;
  releasedBy: string | null;
  tailnet: string[];
  address: string | null;
  knocks: { reporter: string; at: string; count: number }[];
  steps: QuarantineStep[];
  removed?: { at: string; by: string | null } | null;
}

export interface StoppedStack {
  project: string;
  at: string;
  tried: string[];
  count: number;
}

export interface QuarantineView {
  quarantine: QuarantineRecord | null;
  release: PendingRelease | null;
  stopped: StoppedStack[];
  changeThese: {
    stacks: string[];
    vault: VaultReport | null;
    tailscaleVault?: VaultReport | null;
    webAddresses: { hostname: string; project: string }[];
    trusted: {
      nodeId: string;
      nodeName: string;
      project: string;
      port: string;
    }[];
  };
}

interface NetworkPoint {
  nodeId: string;
  stack: string;
  target: string;
}

export interface NetworkServer {
  nodeId: string;
  name: string;
  state: "in" | "leaving";
  address: string | null;
  port: number;
  mtu: number | null;
  key: string;
  signer: string;
  endpoint: string | null;
  nat: boolean;
  announced: { key: string; signature: string } | null;
  since: string;
  joinedAt: string | null;
  points: { stack: string; target: string }[];
}

export interface NetworkChange {
  id: string;
  at: string;
  change: string;
  detail: string | null;
  requestedBy: string;
  deviceId: string | null;
}

export interface NetworkView {
  network: {
    range: string;
    port: number;
    mtu: number;
    version: number;
    createdAt: string;
    createdBy: string;
  } | null;
  version: number;
  document: NetworkDocument | null;
  body: string | null;
  quarantined: string[];
  wrongPorts: {
    nodeId: string;
    from: string | null;
    target: string | null;
    at: string;
  }[];
  members: NetworkServer[];
  waiting: {
    nodeId: string;
    name: string;
    key: string;
    signer: string;
    port: number;
    mtu: number | null;
    since: string;
  }[];
  links: { a: string; b: string; answering: boolean; since: string }[];
  live: Record<string, { at: number; links: NetworkLink[] }>;
  held: {
    address: string;
    nodeId: string | null;
    nodeName: string | null;
    points: NetworkPoint[];
  }[];
  changes: NetworkChange[];
}

export interface NetworkNext {
  addresses: { nodeId: string; address: string; name: string }[];
  held: NetworkView["held"];
}

export type AptReport = Extract<PackagesReport, { apt: true }>;
export type RestartFacts = NonNullable<AptReport["restart"]>;

export interface UpdatesSummary {
  waiting: number;
  security: number;
  held: number;
  checkedAt: string | null;
  restart: RestartFacts | null;
}

export interface PackagesResponse {
  report: PackagesReport | null;
  readAt: string | null;
}

interface ActionStep {
  at: string;
  done: number;
  total: number;
  line: string;
}

export type CheckKind = "HTTP" | "TCP" | "SERVICE" | "CONTAINER";
export type CheckStatus = "UNKNOWN" | "UP" | "DOWN" | "UNTRUSTED";

export interface CheckRecord {
  id: string;
  node_id: string;
  name: string;
  kind: CheckKind;
  target: string;
  enabled: number;
  status: CheckStatus;
  timeout_seconds: number;
  latency_ms: number | null;
  last_checked_at: string | null;
  consecutive_failures: number;
  last_message: string | null;
  public: number;
  public_note: string | null;
  auto_restart?: number;
  created_at: string;
  since?: string | null;
}

export interface Incident {
  id: string;
  check_id: string;
  node_id: string;
  status: "OPEN" | "RESOLVED";
  started_at: string;
  resolved_at: string | null;
  summary: string | null;
  check_name: string;
  node_name: string;
  update_status?: IncidentUpdateStatus | null;
}

export type IncidentUpdateStatus =
  "investigating" | "identified" | "monitoring" | "update";

export interface IncidentUpdate {
  id: string;
  status: IncidentUpdateStatus;
  message: string;
  author: string;
  createdAt: string;
}

export interface IncidentDetail {
  incident: Incident & { check_kind: string; check_target: string };
  results: CheckResult[];
  updates?: IncidentUpdate[];
  public?: boolean;
  actions?: ActionRecord[];
  lastGood?: { t: string; latencyMs: number | null } | null;
  quiet?: QuietSpan[];
}

export interface IncidentBoard {
  latest: Record<
    string,
    {
      at: string;
      updates: number;
      update: { status: IncidentUpdateStatus; message: string } | null;
      action: ActionRecord | null;
    }
  >;
  last30: { count: number; downMs: number };
}

export interface AgentRelease {
  version: string | null;
  checkedAt: string | null;
  updateCommand: string;
}

export interface Overview {
  nodes: NodeRecord[];
  checks: CheckRecord[];
  incidents: Incident[];
  agentRelease: AgentRelease;
  mail?: { failedAt: string; error: string } | null;
}

export interface Enrollment {
  id: string;
  enrollmentToken: string;
  enrollmentExpiresAt: string;
  command: string;
}

export type EnrollmentStatus =
  | { status: "pending" }
  | { status: "expired" }
  | { status: "used"; node: { id: string; name: string } | null };

export type MetricRange = "6h" | "24h" | "7d";

interface MetricPoint {
  t: string;
  cpu: number | null;
  memUsed: number | null;
  memTotal: number | null;
  diskUsed: number | null;
  diskTotal: number | null;
  load1: number | null;
  load5: number | null;
  load15: number | null;
  samples: number;
}

export interface NodeMetrics {
  range: MetricRange;
  bucketSeconds: number;
  from: string;
  to: string;
  points: MetricPoint[];
}

export interface RecentSlot {
  t: string;
  cpu: number | null;
  memPct: number | null;
  samples: number;
}

export interface RecentNode {
  slotSeconds: number;
  slots: RecentSlot[];
  quiet?: QuietSpan[];
}

export interface RecentMetrics {
  nodes: Record<string, RecentNode>;
}

export interface CheckResult {
  t: string;
  status: "UP" | "DOWN";
  latencyMs: number | null;
  message: string | null;
}

export interface QuietSpan {
  from: string;
  to: string | null;
  why: "offline" | "routine" | "quarantined";
}

interface CheckHistory {
  results: CheckResult[];
}

export interface CheckResults {
  windowSeconds: number;
  from: string;
  checks: Record<string, CheckHistory>;
  nodes?: Record<string, { quiet: QuietSpan[] }>;
}

export type ServiceKind = "systemd" | "docker";
export type ServiceState =
  "running" | "stopped" | "failed" | "starting" | "boot" | "unneeded";
export type ServiceAction = "start" | "stop" | "restart";
export type ActionKind =
  | ServiceKind
  | "compose"
  | "trust"
  | "host"
  | "vault"
  | "apt"
  | "network"
  | "bridge";
export type ActionVerb =
  | ServiceAction
  | "deploy"
  | "rollback"
  | "trust"
  | "reboot"
  | "logs"
  | "remove"
  | "purge"
  | "restore"
  | "create"
  | "autorestart"
  | "manual"
  | "heal"
  | "edit"
  | "read"
  | "export"
  | "expose"
  | "unexpose"
  | "adopt"
  | "reach"
  | "apply"
  | "undo"
  | "lockdown"
  | "unlock"
  | "scan"
  | "store"
  | "release"
  | "reshare"
  | "forget"
  | "install"
  | "uninstall"
  | "signin"
  | "refresh"
  | "find"
  | "preview"
  | "upgrade"
  | "hold"
  | "unhold"
  | "addrepo"
  | "droprepo"
  | "inspect"
  | "probe"
  | "test"
  | "prepare"
  | "unprepare"
  | "rekey"
  | "accept"
  | "block"
  | "unblock"
  | "drop"
  | "tighten"
  | "policy"
  | "save"
  | "key"
  | "join"
  | "admin";
export type DockerState = "ready" | "no-compose" | "missing";
export type BatchMode = "rolling" | "parallel";
export type ActionStatus =
  "queued" | "sent" | "done" | "failed" | "expired" | "cancelled" | "skipped";

export interface ServiceEntry {
  kind: ServiceKind;
  name: string;
  state: ServiceState;
  since: string | null;
  system: boolean;
}

export interface StackEntry {
  project: string;
  directory: string;
  running: number;
  total: number;
  compose: boolean;
  rollback: boolean;
  access?: "contained" | "full" | null;
  public?: string[];
  containers?: string[];
  network?: StackNetwork | null;
  title?: string | null;
  names?: Record<string, string> | null;
  services?: string[];
}

export interface Finding {
  id: string;
  severity: "serious" | "warning" | "note";
  detail: string;
}

interface Platform {
  family: "debian" | "rhel" | null;
  name: string;
  id?: string;
  version?: string;
  endOfLife?: string | null;
}

export interface SecurityReport {
  checkedAt: string;
  findings: Finding[];
  recipes: string[];
  lockdown: boolean;
  rebootHour: number | null;
  platform?: Platform;
  listeners?: {
    address: string;
    port: number;
    protocol: "tcp" | "udp";
    process: string;
  }[];
}

export interface WebAddress {
  hostname: string;
  project: string;
  service: string;
  port: number;
  mode: "allow" | "path" | "everyone";
  path: string | null;
}

interface VaultReport {
  set: string;
  holders: number;
  previous?: { set: string; holders: number };
}

export interface CloudflareSettings {
  zone: string;
  setId: string | null;
  aud: string | null;
  expiresAt: string | null;
}

export interface RemovedStack {
  project: string;
  directory: string;
  removedAt: string;
}

export interface NodeTrust {
  version: number;
  core: string[];
  access: string[];
}

interface ServiceNode {
  id: string;
  inventoryAt: string | null;
  refreshRequestedAt: string | null;
  services: ServiceEntry[];
  stacks: StackEntry[];
  removed?: RemovedStack[];
  trust: NodeTrust | null;
  docker?: DockerState | null;
  sealKey?: string | null;
  security?: SecurityReport | null;
  vault?: VaultReport | null;
  tailscaleVault?: VaultReport | null;
  webAddresses?: WebAddress[];
  bridges?: BridgesReport | null;
  leftovers?: string[];
}

export interface DeviceRecord {
  id: string;
  name: string;
  alg: number;
  publicKey: string;
  createdAt: string;
  lastUsedAt: string | null;
  verifies: boolean | null;
  synced?: boolean | null;
  fingerprint: string;
  core: boolean;
  owner?: string | null;
  mine?: boolean;
}

export interface DevicesResponse {
  devices: DeviceRecord[];
}

type ProposalStatus =
  "open" | "applied" | "expired" | "cancelled" | "superseded";

export interface ProposalRecord {
  id: string;
  change: string;
  title: string;
  status: ProposalStatus;
  approvals: string[];
  openedBy: string;
  openedAt: string;
  expiresAt: string;
  closedAt: string | null;
  missing: string | null;
}

export interface ChangeEntry {
  id: string;
  title: string;
  status: Exclude<ProposalStatus, "open">;
  version: number;
  targets: string[];
  openedBy: string;
  approvedBy: string[];
  openedAt: string;
  closedAt: string;
}

export type HistoryShow = "everything" | "actions" | "incidents" | "failed";

interface HistoryIncident {
  id: string;
  checkId: string;
  checkName: string;
  nodeId: string;
  nodeName: string;
  summary: string | null;
  startedAt: string;
  resolvedAt: string | null;
}

export type HistoryEntry =
  | { type: "action"; at: string; action: ActionRecord }
  | { type: "network"; at: string; change: NetworkChange }
  | {
      type: "incident";
      at: string;
      event: "opened" | "resolved";
      incident: HistoryIncident;
    };

export interface HistoryPage {
  entries: HistoryEntry[];
  next: string | null;
}

export interface AttentionItem {
  action: ActionRecord;
  incident: {
    id: string;
    checkName: string;
    summary: string | null;
    startedAt: string;
  } | null;
}

export interface ChangeHistory {
  changes: ChangeEntry[];
  next: string | null;
}

export interface ActionRecord {
  id: string;
  batchId: string;
  position: number;
  mode: BatchMode;
  nodeId: string;
  kind: ActionKind;
  name: string;
  action: ActionVerb;
  status: ActionStatus;
  requestedBy: string;
  requestedAt: string;
  deliverableAt: string | null;
  sentAt: string | null;
  finishedAt: string | null;
  exitCode: number | null;
  output: string | null;
  deviceId: string | null;
  progress?: ActionStep | null;
  peer?: string | null;
}

export interface ServicesResponse {
  nodes: ServiceNode[];
  actions: ActionRecord[];
}

export interface UsageShare {
  requests: number;
  reads: number;
  writes: number;
}

export interface UsageResponse {
  source: "cloudflare" | "estimate";
  configured: boolean;
  fetchedAt: string | null;
  error: string | null;
  account: (UsageShare & { objects: number }) | null;
  krynodes: UsageShare | null;
  budget: UsageShare;
  storage: { bytes: number | null; limit: number };
  quotas: UsageShare & { objects: number };
  resetAt: string;
}

export interface TailnetServer {
  nodeId: string;
  name: string;
  report: TailscaleReport | null;
  vault: VaultReport | null;
  signedIn: boolean;
  listeners?: NonNullable<SecurityReport["listeners"]>;
}

export interface TailnetConnected {
  tailnet: string;
  clientId: string;
  setId: string | null;
  rules: TailnetRule[];
  block: string | null;
  lines: string[];
  members: string[];
  savedAt: string | null;
  savedBy: string | null;
  connectedAt: string;
}

export type TailnetAlarm =
  | {
      id: string;
      kind: "device";
      at: string;
      device: { name: string; tag: string };
    }
  | {
      id: string;
      kind: "policy";
      at: string;
      change: {
        block: boolean;
        added: number;
        removed: number;
        lines: string[];
      };
    };

export interface TailscaleResponse {
  hook: string;
  connected: TailnetConnected | null;
  servers: TailnetServer[];
  alarms: TailnetAlarm[];
}
