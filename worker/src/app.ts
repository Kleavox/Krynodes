import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";

import type { KrynodesEnv } from "./env";
import { upgradeInto } from "./fleet/client";
import { securityHeaders } from "./lib/security-headers";
import {
  requireGuardInProduction,
  requireOperator,
  resolveSession,
} from "./lib/session";
import { registerActionRoutes } from "./routes/actions";
import { registerAgentRoutes } from "./routes/agent";
import { registerDeviceRoutes } from "./routes/devices";
import { registerEnrollmentRoutes } from "./routes/enrollments";
import { registerLaptopRoutes } from "./routes/laptops";
import { registerNetworkRoutes } from "./routes/network";
import { registerNodeRoutes } from "./routes/nodes";
import { registerReleaseRoutes } from "./routes/release";

const app = new Hono<KrynodesEnv>();

app.onError((error, context) => {
  console.error("[kry]", error);
  return context.json(
    {
      code: "INTERNAL_ERROR",
      message: "Krynodes could not complete the request.",
    },
    500,
  );
});

app.use("*", securityHeaders({ referrerPolicy: "same-origin" }));

app.use("*", async (context, next) => {
  requireGuardInProduction(context.env);
  await next();
});

app.use(
  "/api/*",
  bodyLimit({
    maxSize: 2 * 1024 * 1024,
    onError: (context) =>
      context.json(
        { code: "TOO_LARGE", message: "That request is too large." },
        413,
      ),
  }),
);

app.use("/api/*", async (context, next) => {
  if (
    (["POST", "PUT", "PATCH", "DELETE"].includes(context.req.method) ||
      context.req.header("upgrade")?.toLowerCase() === "websocket") &&
    !context.req.path.startsWith("/api/agent/")
  ) {
    const origin = context.req.header("origin");
    const site = context.req.header("sec-fetch-site");
    const own = new URL(context.env.PUBLIC_ORIGIN).origin;
    if (
      (origin && origin !== own) ||
      (site && site !== "same-origin" && site !== "none")
    ) {
      return context.json(
        {
          code: "CROSS_SITE",
          message: "Changes are accepted only from the Krynodes dashboard.",
        },
        403,
      );
    }
  }
  await next();
});

app.get("/health", (context) => context.json({ service: "kry", status: "ok" }));

app.get("/api/session", async (context) => {
  const { via, identity } = await resolveSession(context.req.raw, context.env);
  return identity
    ? context.json({ authenticated: true, via, identity })
    : context.json({ authenticated: false, via });
});

registerAgentRoutes(app);

app.use("/api/*", requireOperator);

registerEnrollmentRoutes(app);
registerNodeRoutes(app);
registerDeviceRoutes(app);
registerActionRoutes(app);
registerReleaseRoutes(app);
registerNetworkRoutes(app);
registerLaptopRoutes(app);

app.get("/api/live", async (context) => {
  if (context.req.header("upgrade")?.toLowerCase() !== "websocket") {
    return context.json({ code: "UPGRADE_REQUIRED" }, 426);
  }
  return upgradeInto(context.env, context.req.raw, "/watch");
});

app.all("/api/*", (context) =>
  context.json({ code: "NOT_FOUND", message: "No such endpoint." }, 404),
);

app.all("*", (context) => context.env.ASSETS.fetch(context.req.raw));

export { app };
