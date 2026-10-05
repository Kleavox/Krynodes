import type { MiddlewareHandler } from "hono";

export function securityHeaders(options: {
  referrerPolicy: string;
  csp?: string;
}): MiddlewareHandler {
  return async (context, next) => {
    await next();
    context.header("Referrer-Policy", options.referrerPolicy);
    context.header("Strict-Transport-Security", "max-age=31536000");
    context.header("X-Content-Type-Options", "nosniff");
    context.header("X-Frame-Options", "DENY");
    context.header(
      "Permissions-Policy",
      "camera=(), microphone=(), geolocation=()",
    );
    if (options.csp) {
      const type = context.res.headers.get("content-type") ?? "";
      if (
        type.includes("text/html") &&
        !context.res.headers.has("content-security-policy")
      ) {
        context.header("Content-Security-Policy", options.csp);
      }
    }
  };
}
