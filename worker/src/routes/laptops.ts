import type { MiddlewareHandler } from "hono";

import { randomToken, sha256 } from "../lib/crypto";
import { liveRange, readNetwork } from "../network/document";
import { agentOrigin, type KrynodesApp, type KrynodesEnv } from "./shared";

const LAPTOP_CODE_MS = 10 * 60_000;

const LAPTOP_SETUP = JSON.stringify({ laptop: true });

export function registerLaptopRoutes(
  app: KrynodesApp,
  requireOperator: MiddlewareHandler<KrynodesEnv>,
): void {
  app.post("/api/laptops", requireOperator, async (context) => {
    const db = context.env.DB;
    const owner = context.get("identity").id;
    if (!liveRange(await readNetwork(db, owner))) {
      return context.json(
        { code: "NO_NETWORK", message: "Create the private network first." },
        409,
      );
    }
    const code = randomToken();
    const expiresAt = new Date(Date.now() + LAPTOP_CODE_MS).toISOString();
    await db
      .prepare(
        `INSERT INTO enrollment_tokens (id, owner_user_id, token_hash, expires_at, setup)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .bind(
        crypto.randomUUID(),
        owner,
        await sha256(code),
        expiresAt,
        LAPTOP_SETUP,
      )
      .run();
    return context.json(
      {
        code,
        expiresAt,
        origin: context.env.PUBLIC_ORIGIN,
        endpoint: agentOrigin(context.env),
      },
      201,
    );
  });

  app.delete("/api/laptops/:id", requireOperator, async (context) => {
    const db = context.env.DB;
    const id = context.req.param("id");
    const laptop = await db
      .prepare(
        `SELECT n.name, m.state FROM nodes n
         LEFT JOIN network_members m ON m.node_id = n.id
         WHERE n.id = ? AND n.owner_user_id = ? AND n.kind = 'laptop'`,
      )
      .bind(id, context.get("identity").id)
      .first<{ name: string; state: string | null }>();
    if (!laptop) return context.json({ code: "NOT_FOUND" }, 404);
    if (laptop.state === "in") {
      return context.json(
        {
          code: "NETWORK_MEMBER",
          message: `Remove ${laptop.name} from the private network first.`,
        },
        409,
      );
    }
    await db
      .prepare(
        `DELETE FROM nodes WHERE id = ?1
           AND NOT EXISTS (SELECT 1 FROM network_members WHERE node_id = ?1 AND state = 'in')`,
      )
      .bind(id)
      .run();
    return context.body(null, 204);
  });
}
