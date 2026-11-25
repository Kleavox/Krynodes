import { checkAgentRelease } from "./agent/releases";
import { app } from "./app";
import type { Env } from "./env";
import { clearOldOutput } from "./routes/actions";

export { FleetHub } from "./fleet/hub";

export default {
  fetch: app.fetch,
  scheduled: (_controller, env, context) => {
    context.waitUntil(checkAgentRelease(env));
    context.waitUntil(clearOldOutput(env.DB));
  },
} satisfies ExportedHandler<Env>;
