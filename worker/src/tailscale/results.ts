const ownerOf = (slot: string) =>
  `(SELECT owner_user_id FROM nodes WHERE id = ${slot})`;

export function tailnetStatements(
  db: D1Database,
  input: {
    owner: string;
    kind: string;
    connect?: { tailnet: string; clientId: string; webhookSecret?: string };
    device: string;
    at: string;
  },
): D1PreparedStatement[] {
  if (input.kind === "disconnect") {
    return [
      db
        .prepare("DELETE FROM tailscale WHERE owner_user_id = ?")
        .bind(input.owner),
      db
        .prepare("DELETE FROM tailscale_alarms WHERE owner_user_id = ?")
        .bind(input.owner),
    ];
  }
  if (!input.connect) return [];
  return [
    db
      .prepare(
        `INSERT INTO tailscale (owner_user_id, tailnet, client_id, webhook_secret, connected_at, connected_by)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT (owner_user_id) DO UPDATE SET
           tailnet = excluded.tailnet, client_id = excluded.client_id,
           webhook_secret = COALESCE(NULLIF(excluded.webhook_secret, ''), tailscale.webhook_secret)`,
      )
      .bind(
        input.owner,
        input.connect.tailnet,
        input.connect.clientId,
        input.connect.webhookSecret ?? "",
        input.at,
        input.device,
      ),
    db
      .prepare(
        `UPDATE tailscale_alarms SET cleared_at = ?1
         WHERE owner_user_id = ?2 AND kind = 'policy' AND cleared_at IS NULL`,
      )
      .bind(input.at, input.owner),
  ];
}

function parsedOutput(output: string): Record<string, unknown> {
  try {
    const value = JSON.parse(output) as unknown;
    return value && typeof value === "object"
      ? (value as Record<string, unknown>)
      : {};
  } catch {
    return {};
  }
}

const strings = (value: unknown): string[] =>
  Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];

function deviceIds(value: unknown): string[] | null {
  if (!Array.isArray(value)) return null;
  return value.flatMap((item: unknown) =>
    typeof item === "string"
      ? [item]
      : item && typeof (item as { id?: unknown }).id === "string"
        ? [(item as { id: string }).id]
        : [],
  );
}

function clearGone(
  db: D1Database,
  nodeId: string,
  devices: string[] | null,
  at: string,
): D1PreparedStatement[] {
  if (devices === null) return [];
  return [
    db
      .prepare(
        `UPDATE tailscale_alarms SET cleared_at = ?1
         WHERE owner_user_id = ${ownerOf("?2")} AND kind = 'device'
           AND cleared_at IS NULL
           AND device NOT IN (SELECT value FROM json_each(?3))`,
      )
      .bind(at, nodeId, JSON.stringify(devices)),
  ];
}

export function tailscaleResults(
  db: D1Database,
  nodeId: string,
  action: { id: string; action: string; batch_id: string },
  args: Record<string, string>,
  at: string,
  output: string,
): D1PreparedStatement[] {
  const parsed = parsedOutput(output);
  switch (action.action) {
    case "store":
      return args.set
        ? [
            db
              .prepare(
                `UPDATE tailscale SET set_id = ?1
                 WHERE owner_user_id = ${ownerOf("?2")}
                   AND set_id IS NOT ?1
                   AND (SELECT COUNT(*) FROM actions
                        WHERE batch_id = ?3 AND action = 'store' AND status = 'done') >= ?4`,
              )
              .bind(
                args.set,
                nodeId,
                action.batch_id,
                Number(args.holders) > 1 ? 2 : 1,
              ),
          ]
        : [];
    case "save":
      if (parsed.saved !== true) return [];
      return [
        db
          .prepare(
            `UPDATE tailscale SET rules = ?1, block = ?2, lines = ?3, etag = ?4, members = ?5,
               saved_at = ?6, saved_by = (SELECT device_id FROM actions WHERE id = ?7)
             WHERE owner_user_id = ${ownerOf("?8")}`,
          )
          .bind(
            args.rules ?? "[]",
            typeof parsed.block === "string" ? parsed.block : null,
            JSON.stringify(strings(parsed.lines)),
            typeof parsed.etag === "string" ? parsed.etag : null,
            JSON.stringify(strings(parsed.members)),
            at,
            action.id,
            nodeId,
          ),
        ...clearGone(db, nodeId, deviceIds(parsed.devices), at),
      ];
    case "policy":
      return clearGone(db, nodeId, deviceIds(parsed.devices), at);
    case "join":
      return typeof parsed.id === "string"
        ? [
            db
              .prepare(
                "INSERT OR REPLACE INTO tailscale_nodes (node_id, device, joined_at) VALUES (?, ?, ?)",
              )
              .bind(nodeId, parsed.id, at),
          ]
        : [];
    case "remove":
      return [
        db
          .prepare(
            `UPDATE quarantines SET timeline = json_set(timeline, '$.removed',
               json_object('at', ?1, 'by', (SELECT device_id FROM actions WHERE id = ?2)))
             WHERE node_id = ?3 AND released_at IS NULL
               AND node_id IN (SELECT id FROM nodes WHERE owner_user_id = ${ownerOf("?4")})`,
          )
          .bind(at, action.id, args.node ?? "", nodeId),
        db
          .prepare(
            `DELETE FROM tailscale_nodes WHERE node_id = ?1
               AND node_id IN (SELECT id FROM nodes WHERE owner_user_id = ${ownerOf("?2")})`,
          )
          .bind(args.node ?? "", nodeId),
      ];
  }
  return [];
}
