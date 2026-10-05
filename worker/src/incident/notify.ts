export interface IncidentNotice {
  nodeId: string;
  checkId: string | null;
  checkName: string | null;
  kind: "opened" | "resolved";
  summary: string;
  occurredAt: string;
  healing?: boolean;
}

export interface ServerChanges {
  nodeId: string;
  down: IncidentNotice[];
}

export interface MailBox {
  failures: Record<string, number>;
}

const HOUR_MS = 3_600_000;

export const emptyBox = (): MailBox => ({ failures: {} });

export const loadBox = (stored: Partial<MailBox> | undefined): MailBox =>
  stored?.failures && typeof stored.failures === "object"
    ? { failures: stored.failures }
    : emptyBox();

const keyOf = (notice: IncidentNotice) =>
  notice.checkId ?? `server:${notice.nodeId}`;

export function receive(
  stored: MailBox,
  notices: IncidentNotice[],
  now: number,
): { box: MailBox; send: ServerChanges[] } {
  const failures = Object.fromEntries(
    Object.entries(stored.failures).filter(([, at]) => now - at < HOUR_MS),
  );
  const servers = new Map<string, ServerChanges>();
  for (const notice of notices) {
    const key = keyOf(notice);
    if (notice.kind !== "opened" || failures[key] !== undefined) continue;
    failures[key] = now;
    const server = servers.get(notice.nodeId) ?? {
      nodeId: notice.nodeId,
      down: [],
    };
    server.down.push(notice);
    servers.set(notice.nodeId, server);
  }
  return { box: { failures }, send: [...servers.values()] };
}
