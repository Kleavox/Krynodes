export interface Env {
  ASSETS: Fetcher;
  DB: D1Database;
  ENVIRONMENT: "development" | "production";
  PUBLIC_ORIGIN: string;
  AGENT_ORIGIN?: string;
  FROM_EMAIL: string;
  ALERT_EMAIL?: string;
  EMAIL?: SendEmail;
  AGENT_RATE_LIMIT?: RateLimit;
  ACCESS_TEAM_DOMAIN?: string;
  ACCESS_AUD?: string;
  CF_ACCOUNT_ID?: string;
  CF_ANALYTICS_TOKEN?: string;
  KRY_D1_ID?: string;
  KRY_SCRIPTS?: string;
  FLEET?: DurableObjectNamespace;
}
