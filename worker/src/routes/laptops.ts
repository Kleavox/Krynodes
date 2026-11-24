import { readAgentRelease } from "../agent/releases";
import type { KrynodesApp } from "../env";
import { announce, dropNode } from "../fleet/client";
import { createEnrollment, DOWNLOADS } from "./enrollments";
import { agentOrigin, networkMember } from "./shared";

export function registerLaptopRoutes(app: KrynodesApp): void {
  app.post("/api/laptops", async (context) => {
    const { version } = await readAgentRelease(context.env.DB);
    if (!version) {
      return context.json(
        {
          code: "NO_RELEASE",
          message:
            "Krynodes has not found an agent release yet. Check for one, then add the laptop.",
        },
        409,
      );
    }
    const created = await createEnrollment(context, "laptop");
    if (created instanceof Response) return created;
    return context.json(
      {
        code: created.token,
        expiresAt: created.expiresAt,
        origin: context.env.PUBLIC_ORIGIN,
        endpoint: agentOrigin(context.env),
        download: `${DOWNLOADS}/agent-v${version}/krynodes-windows-amd64.exe`,
      },
      201,
    );
  });

  app.delete("/api/laptops/:id", async (context) => {
    const db = context.env.DB;
    const id = context.req.param("id");
    const laptop = await db
      .prepare("SELECT name FROM nodes WHERE id = ? AND kind = 'laptop'")
      .bind(id)
      .first<{ name: string }>();
    if (!laptop) return context.json({ code: "NOT_FOUND" }, 404);
    const deleted = await db
      .prepare(
        "DELETE FROM nodes WHERE id = ?1 AND NOT EXISTS (SELECT 1 FROM network_members WHERE node_id = ?1 AND state = 'in')",
      )
      .bind(id)
      .run();
    if (!deleted.meta.changes) return networkMember(context, laptop.name);
    await dropNode(context.env, id);
    await announce(context.env, ["fleet", "network"]);
    return context.json({ removed: true });
  });
}
