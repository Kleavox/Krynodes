import { agentSupported } from "@krynodes/protocol";

import { assertionSynced, fingerprint } from "../lib/webauthn";

export interface TrustReport {
  version: number;
  core: string[];
  access: string[];
  passphrase: boolean;
  requireUv: boolean;
}

interface FleetDevice {
  id: string;
  name: string;
  alg: number;
  publicKey: string;
  createdAt: string;
  lastUsedAt: string | null;
  removedAt: string | null;
  verifies: boolean | null;
  synced: boolean | null;
  fingerprint: string;
  account: string | null;
}

export interface FleetNode {
  id: string;
  name: string;
  agentVersion: string | null;
  report: TrustReport | null;
}

export interface Fleet {
  devices: FleetDevice[];
  nodes: FleetNode[];
  core: string[];
  ids: (prints: string[]) => string[];
}

export function readReport(text: string | null): TrustReport | null {
  if (!text) return null;
  try {
    const parsed = JSON.parse(text) as Partial<TrustReport>;
    return {
      version: parsed.version ?? 0,
      core: parsed.core ?? [],
      access: parsed.access ?? [],
      passphrase: parsed.passphrase ?? false,
      requireUv: parsed.requireUv ?? false,
    };
  } catch {
    return null;
  }
}

export const agentCurrent = (node: FleetNode) =>
  agentSupported(node.agentVersion);

export async function viewerPrints(
  db: D1Database,
  ownerId: string,
  email: string,
): Promise<Set<string>> {
  const devices = await db
    .prepare(
      `SELECT public_key FROM devices
       WHERE owner_user_id = ? AND account = ? AND removed_at IS NULL`,
    )
    .bind(ownerId, email)
    .all<{ public_key: string }>();
  return new Set(
    await Promise.all(
      devices.results.map((row) => fingerprint(row.public_key)),
    ),
  );
}

export const trusts = (report: TrustReport | null, prints: Set<string>) =>
  report?.access.some((print) => prints.has(print)) ?? false;

export async function loadFleet(
  db: D1Database,
  ownerId: string,
): Promise<Fleet> {
  const [devices, nodes] = await Promise.all([
    db
      .prepare(
        `SELECT id, name, alg, public_key, created_at, last_used_at, removed_at, verifies, synced, account
         FROM devices WHERE owner_user_id = ? ORDER BY created_at, id`,
      )
      .bind(ownerId)
      .all<{
        id: string;
        name: string;
        alg: number;
        public_key: string;
        created_at: string;
        last_used_at: string | null;
        removed_at: string | null;
        verifies: number | null;
        synced: number | null;
        account: string | null;
      }>(),
    db
      .prepare(
        `SELECT id, name, agent_version, trust_report FROM nodes
         WHERE owner_user_id = ? AND enrolled_at IS NOT NULL AND disabled_at IS NULL
         ORDER BY name, id`,
      )
      .bind(ownerId)
      .all<{
        id: string;
        name: string;
        agent_version: string | null;
        trust_report: string | null;
      }>(),
  ]);
  const listed = await Promise.all(
    devices.results.map(async (row) => ({
      id: row.id,
      name: row.name,
      alg: row.alg,
      publicKey: row.public_key,
      createdAt: row.created_at,
      lastUsedAt: row.last_used_at,
      removedAt: row.removed_at,
      verifies: row.verifies === null ? null : row.verifies === 1,
      synced: row.synced === null ? null : row.synced === 1,
      fingerprint: await fingerprint(row.public_key),
      account: row.account,
    })),
  );
  const listedNodes = nodes.results.map((row) => ({
    id: row.id,
    name: row.name,
    agentVersion: row.agent_version,
    report: readReport(row.trust_report),
  }));
  const ids = (prints: string[]) =>
    listed
      .filter((device) => prints.includes(device.fingerprint))
      .map((device) => device.id);
  const union = new Set(listedNodes.flatMap((node) => node.report?.core ?? []));
  return {
    devices: listed,
    nodes: listedNodes,
    core: ids([...union]),
    ids,
  };
}

export function syncedUpdates(
  db: D1Database,
  owner: string,
  grants: { credentialId: string; authenticatorData: string }[],
): D1PreparedStatement[] {
  return grants.map((grant) =>
    db
      .prepare(
        "UPDATE devices SET synced = ? WHERE id = ? AND owner_user_id = ?",
      )
      .bind(
        assertionSynced(grant.authenticatorData) ? 1 : 0,
        grant.credentialId,
        owner,
      ),
  );
}
