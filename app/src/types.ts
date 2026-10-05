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
  connected_at?: string;
  grace_seconds?: number;
}

export type CheckKind = "HTTP" | "TCP" | "SERVICE";
export type CheckStatus = "UNKNOWN" | "UP" | "DOWN";

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
}

export interface IncidentDetail {
  incident: Incident & { check_kind: string; check_target: string };
  results: CheckResult[];
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

export interface CheckHistory {
  results: CheckResult[];
  up4h: number | null;
}

export interface CheckResults {
  windowSeconds: number;
  from: string;
  checks: Record<string, CheckHistory>;
}

export type ServiceKind = "systemd" | "docker";
export type ServiceState = "running" | "stopped" | "failed" | "starting";
export type ServiceAction = "start" | "stop" | "restart";
export type ActionKind = ServiceKind | "compose" | "trust" | "host";
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
  | "heal";
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
}

export interface DeviceRecord {
  id: string;
  name: string;
  alg: number;
  publicKey: string;
  createdAt: string;
  lastUsedAt: string | null;
  verifies: boolean | null;
  fingerprint: string;
  core: boolean;
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

export interface ActionHistory {
  actions: ActionRecord[];
  next: string | null;
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
