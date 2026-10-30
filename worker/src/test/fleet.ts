import type { DatabaseSync } from "node:sqlite";

import { OWNER } from "./seed";

export const V1 = "a1111111-1111-4111-8111-111111111111";
export const V2 = "a2222222-2222-4222-8222-222222222222";
export const V3 = "a3333333-3333-4333-8333-333333333333";
export const IO = "a4444444-4444-4444-8444-444444444444";
export const OLD = "a5555555-5555-4555-8555-555555555555";

export const keyOf = (n: number) =>
  btoa(String.fromCharCode(...new Array<number>(32).fill(n)));

export function seedFleet(
  sqlite: DatabaseSync,
  members: string[] = [V1, V2, V3],
): void {
  const names: Record<string, string> = {
    [V1]: "vps-1",
    [V2]: "vps-2",
    [V3]: "vps-3",
    [IO]: "server-2",
    [OLD]: "old",
  };
  for (const [id, name] of Object.entries(names)) {
    sqlite
      .prepare(
        `INSERT INTO nodes (id, owner_user_id, name, agent_token_hash, interval_seconds,
           enrolled_at, agent_version, tailscale)
         VALUES (?, ?, ?, ?, 60, '2026-09-01 00:00:00', ?, ?)`,
      )
      .run(
        id,
        OWNER,
        name,
        `hash-${id}`,
        id === OLD ? "0.6.14" : "0.7.0",
        id === V1
          ? JSON.stringify({
              installed: true,
              addresses: ["100.101.7.10", "fd7a:115c:a1e0::7"],
            })
          : null,
      );
  }
  sqlite
    .prepare(
      `INSERT INTO network (owner_user_id, cidr, port, mtu, version, document, stamp, created_at, created_by)
       VALUES (?, '10.88.0.0/24', 51820, 1420, 1, '{}', 's1', 'now', 'owner')`,
    )
    .run(OWNER);
  members.forEach((id, index) => {
    sqlite
      .prepare(
        `INSERT INTO network_members (node_id, state, address, port, key, signer, endpoint, nat, since)
         VALUES (?, 'in', ?, 51820, ?, ?, NULL, 0, 'now')`,
      )
      .run(id, `10.88.0.${index + 1}`, keyOf(index + 1), keyOf(index + 101));
  });
}

export const queued = (sqlite: DatabaseSync) =>
  sqlite
    .prepare(
      `SELECT node_id AS nodeId, kind, name, action, status, requested_by AS requestedBy,
              signed, attachment, deliverable_at AS deliverableAt
       FROM actions ORDER BY rowid`,
    )
    .all() as {
    nodeId: string;
    kind: string;
    name: string;
    action: string;
    status: string;
    requestedBy: string;
    signed: string | null;
    attachment: string | null;
    deliverableAt: string | null;
  }[];
