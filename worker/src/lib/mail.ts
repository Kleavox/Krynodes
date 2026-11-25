import type { Env } from "../env";

const COLOR = {
  bg: "#0c0c10",
  card: "#14141a",
  border: "#282831",
  fg: "#ececf1",
  muted: "#92929f",
  primary: "#8b7bff",
  destructive: "#ed7477",
};

const SANS =
  "font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif";
const MONO =
  "font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace";

interface Layout {
  title: string;
  preheader: string;
  badge: string;
  heading: string;
  intro: string;
  rows: [string, string][];
  action: { label: string; href: string };
}

export interface DownCheck {
  name: string;
  container: string;
  since: string;
}

export function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function utcTime(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : `${date.toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

function render(layout: Layout, origin: string): string {
  const rows = layout.rows
    .map(
      ([label, value]) => `
                <tr>
                  <td width="1%" style="padding:10px 16px 10px 0;border-top:1px solid ${COLOR.border};${MONO};font-size:11px;color:${COLOR.muted};white-space:nowrap;vertical-align:top">${escapeHtml(label)}</td>
                  <td style="padding:10px 0;border-top:1px solid ${COLOR.border};${MONO};font-size:13px;line-height:1.5;color:${COLOR.fg};word-break:break-all">${escapeHtml(value)}</td>
                </tr>`,
    )
    .join("");
  const host = new URL(origin).host;

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <meta name="color-scheme" content="dark">
    <meta name="supported-color-schemes" content="dark">
    <title>${escapeHtml(layout.title)}</title>
  </head>
  <body style="margin:0;padding:0;background:${COLOR.bg}">
    <div style="display:none;max-height:0;overflow:hidden;opacity:0">${escapeHtml(layout.preheader)}</div>
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="${COLOR.bg}" style="background:${COLOR.bg}">
      <tr>
        <td align="center" style="padding:40px 16px">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:560px">
            <tr>
              <td style="padding:0 4px 20px;${SANS};font-size:15px;font-weight:600;color:${COLOR.fg}">
                Krynodes
              </td>
            </tr>
            <tr>
              <td bgcolor="${COLOR.card}" style="padding:28px;background:${COLOR.card};border:1px solid ${COLOR.border};border-radius:8px">
                <span style="display:inline-block;padding:3px 10px;border:1px solid ${COLOR.border};border-radius:999px;${MONO};font-size:11px;line-height:1.5;color:${COLOR.fg}"><span style="color:${COLOR.destructive}">&#9679;</span>&nbsp;${escapeHtml(layout.badge)}</span>
                <h1 style="margin:16px 0 8px;${SANS};font-size:22px;line-height:1.3;font-weight:600;color:${COLOR.fg}">${escapeHtml(layout.heading)}</h1>
                <p style="margin:0 0 20px;${SANS};font-size:14px;line-height:1.6;color:${COLOR.muted}">${escapeHtml(layout.intro)}</p>
                <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border-bottom:1px solid ${COLOR.border}">${rows}
                </table>
                <p style="margin:24px 0 0">
                  <a href="${escapeHtml(layout.action.href)}" style="display:inline-block;padding:12px 16px;background:${COLOR.primary};border-radius:6px;${SANS};font-size:14px;font-weight:600;color:${COLOR.bg};text-decoration:none">${escapeHtml(layout.action.label)}</a>
                </p>
              </td>
            </tr>
            <tr>
              <td style="padding:16px 4px 0;${SANS};font-size:12px;line-height:1.6;color:${COLOR.muted}">Sent by Krynodes at ${escapeHtml(host)}.</td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>`;
}

function plainText(layout: Layout): string {
  return [
    layout.heading,
    layout.intro,
    layout.rows.map(([label, value]) => `${label}: ${value}`).join("\n"),
    `${layout.action.label}: ${layout.action.href}`,
  ].join("\n\n");
}

export const mailReady = (env: Env): boolean =>
  Boolean(env.EMAIL && env.ALERT_EMAIL && env.FROM_EMAIL);

async function deliver(env: Env, layout: Layout): Promise<void> {
  if (!env.EMAIL || !env.ALERT_EMAIL || !env.FROM_EMAIL) {
    console.log("[kry email] not configured", { subject: layout.title });
    return;
  }
  await env.EMAIL.send({
    to: env.ALERT_EMAIL,
    from: { name: "Krynodes", email: env.FROM_EMAIL },
    subject: layout.title.replace(/\p{Cc}/gu, ""),
    html: render(layout, env.PUBLIC_ORIGIN),
    text: plainText(layout),
  });
}

const plural = (count: number, word: string) =>
  `${count} ${word}${count === 1 ? "" : "s"}`;

export async function sendCheckDownEmail(
  env: Env,
  mail: { nodeName: string; checks: DownCheck[] },
): Promise<void> {
  const { nodeName, checks } = mail;
  const heading = `${nodeName}: ${plural(checks.length, "check")} down`;
  const intro = `${checks.length === 1 ? "A container" : "Containers"} on ${nodeName} went down and did not come back within five minutes.`;
  await deliver(env, {
    title: `[Krynodes] ${heading}`,
    preheader: intro,
    badge: "Down",
    heading,
    intro,
    rows: [
      ["Server", nodeName],
      ...checks.map((check): [string, string] => [
        check.name,
        `${check.container} · down since ${utcTime(check.since)}`,
      ]),
    ],
    action: {
      label: "Open Checks",
      href: new URL("/checks", env.PUBLIC_ORIGIN).toString(),
    },
  });
}

export async function sendOfflineEmail(
  env: Env,
  mail: { nodeName: string; lastSeen: string },
): Promise<void> {
  const { nodeName } = mail;
  const heading = `${nodeName} is offline`;
  const intro = `${nodeName} stopped reporting and has not been back for five minutes. Its checks cannot run until it is back.`;
  await deliver(env, {
    title: `[Krynodes] ${heading}`,
    preheader: intro,
    badge: "Offline",
    heading,
    intro,
    rows: [
      ["Server", nodeName],
      ["Last report", utcTime(mail.lastSeen)],
    ],
    action: {
      label: "Open Fleet",
      href: new URL("/", env.PUBLIC_ORIGIN).toString(),
    },
  });
}
