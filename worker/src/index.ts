import { checkAgentRelease } from "./agent/releases";
import { app } from "./app";
import type { Env } from "./env";

export { FleetHub } from "./fleet/hub";

export default {
  fetch: app.fetch,
  scheduled: (_controller, env, context) => {
    context.waitUntil(checkAgentRelease(env));
  },
} satisfies ExportedHandler<Env>;
