import { checkAgentRelease, readAgentRelease } from "../agent/releases";
import type { KrynodesApp } from "../env";

export function registerReleaseRoutes(app: KrynodesApp): void {
  app.get("/api/release", async (context) =>
    context.json(await readAgentRelease(context.env.DB)),
  );

  app.post("/api/release/check", async (context) =>
    context.json(await checkAgentRelease(context.env)),
  );
}
