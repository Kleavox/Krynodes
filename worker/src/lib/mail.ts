import type { Env } from "../env";

interface CheckChange {
  checkName: string | null;
  summary: string;
  occurredAt: string;
  healing?: boolean;
  disk?: boolean;
}

const COLOR = {
  bg: "#0c0c0e",
  card: "#141417",
  border: "#27272d",
  fg: "#ededf0",
  muted: "#8a8a94",
  primary: "#8b7bff",
  destructive: "#f0616d",
};

const SANS =
  "font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif";
const MONO =
  "font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace";

interface Layout {
  title: string;
  preheader: string;
  badge: { label: string; color: string };
  heading: string;
  intro: string;
  rows: [string, string][];
  action: { label: string; href: string };
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
                  <td width="1%" style="padding:10px 16px 10px 0;border-top:1px solid ${COLOR.border};${MONO};font-size:11px;letter-spacing:0.06em;text-transform:uppercase;color:${COLOR.muted};white-space:nowrap;vertical-align:top">${escapeHtml(label)}</td>
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
                <span style="display:inline-block;width:10px;height:10px;margin-right:8px;border-radius:3px;background:${COLOR.primary};vertical-align:middle"></span>Krynodes
              </td>
            </tr>
            <tr>
              <td bgcolor="${COLOR.card}" style="padding:28px;background:${COLOR.card};border:1px solid ${COLOR.border};border-radius:8px">
                <span style="display:inline-block;padding:3px 10px;border:1px solid ${COLOR.border};border-radius:999px;${MONO};font-size:11px;line-height:1.5;color:${COLOR.fg}"><span style="color:${layout.badge.color}">&#9679;</span>&nbsp;${escapeHtml(layout.badge.label)}</span>
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

async function deliver(env: Env, layout: Layout): Promise<void> {
  if (!env.EMAIL || !env.ALERT_EMAIL) {
    console.log("[kry email] not configured", { subject: layout.title });
    return;
  }
  await env.EMAIL.send({
    to: env.ALERT_EMAIL,
    from: { name: "Krynodes", email: env.FROM_EMAIL },
    subject: layout.title,
    html: render(layout, env.PUBLIC_ORIGIN),
    text: plainText(layout),
  });
}

const incidentsLink = (env: Env) => ({
  label: "Open incidents",
  href: new URL("/incidents", env.PUBLIC_ORIGIN).toString(),
});

const names = (changes: CheckChange[]) =>
  changes.map((change) => change.checkName).join(", ");

const plural = (count: number, word: string) =>
  `${count} ${word}${count === 1 ? "" : "s"}`;

function serverParts(changes: CheckChange[]) {
  const full = changes.find((change) => change.disk);
  const offline = changes.find(
    (change) => change.checkName === null && !change.disk,
  );
  const down = changes.filter((change) => change.checkName !== null);
  const parts = [
    ...(offline ? ["offline"] : []),
    ...(full ? [`disk ${full.summary}`] : []),
    ...(down.length > 0
      ? [`${plural(down.length, "check")} down — ${names(down)}`]
      : []),
  ];
  return { full, offline, down, parts };
}

export async function sendFleetEmail(
  env: Env,
  servers: { nodeName: string; down: CheckChange[] }[],
): Promise<void> {
  const listed = servers.map((server) => ({
    name: server.nodeName,
    ...serverParts(server.down),
  }));
  const allOffline = listed.every(
    (server) => server.offline && server.parts.length === 1,
  );
  const heading = `${plural(listed.length, "server")} ${allOffline ? "offline" : "need a look"}`;
  const intro = allOffline
    ? "These servers stopped reporting at the same time. When many go at once, the cause is often their network or provider."
    : "These servers went offline, filled their disk or have checks that kept failing.";
  await deliver(env, {
    title: `[Krynodes] ${heading}`,
    preheader: intro,
    badge: { label: allOffline ? "Offline" : "Down", color: COLOR.destructive },
    heading,
    intro,
    rows: listed.map((server): [string, string] => [
      server.name,
      server.parts.join(" · "),
    ]),
    action: {
      label: "Open the fleet",
      href: new URL("/", env.PUBLIC_ORIGIN).toString(),
    },
  });
}

export async function sendServerEmail(
  env: Env,
  message: { nodeId: string; nodeName: string; down: CheckChange[] },
): Promise<void> {
  const { nodeId, nodeName } = message;
  const { full, offline, down, parts } = serverParts(message.down);
  const heading = `${nodeName}: ${parts.join(" · ")}`;
  const intro = offline
    ? `${nodeName} stopped reporting. Its checks cannot run until it is back.`
    : down.length > 0
      ? `Checks on ${nodeName} kept failing and opened incidents.`
      : `The disk on ${nodeName} is almost full. Services start failing when it runs out.`;
  await deliver(env, {
    title: `[Krynodes] ${heading}`,
    preheader: intro,
    badge: offline
      ? { label: "Offline", color: COLOR.destructive }
      : down.length > 0
        ? { label: "Down", color: COLOR.destructive }
        : { label: "Disk", color: COLOR.destructive },
    heading,
    intro,
    rows: [
      ["Server", nodeName],
      ...(offline
        ? [["Last report", utcTime(offline.occurredAt)] as [string, string]]
        : []),
      ...(full
        ? [
            ["Disk", `${full.summary} · since ${utcTime(full.occurredAt)}`] as [
              string,
              string,
            ],
          ]
        : []),
      ...down.map((change): [string, string] => [
        change.checkName ?? nodeName,
        `${change.summary} · since ${utcTime(change.occurredAt)}${change.healing ? " · restarting it automatically" : ""}`,
      ]),
    ],
    action:
      down.length === 0
        ? {
            label: `Open ${nodeName}`,
            href: new URL(`/nodes/${nodeId}`, env.PUBLIC_ORIGIN).toString(),
          }
        : incidentsLink(env),
  });
}

export async function sendSecurityEmail(
  env: Env,
  message: {
    nodeId: string;
    nodeName: string;
    findings: { detail: string }[];
  },
): Promise<void> {
  const { nodeId, nodeName, findings } = message;
  const heading = `${nodeName}: ${plural(findings.length, "serious security finding")}`;
  const intro = `The security check on ${nodeName} found something that needs attention.`;
  await deliver(env, {
    title: `[Krynodes] ${heading}`,
    preheader: intro,
    badge: { label: "Security", color: COLOR.destructive },
    heading,
    intro,
    rows: [
      ["Server", nodeName],
      ...findings.map((finding): [string, string] => [
        "Finding",
        finding.detail,
      ]),
    ],
    action: {
      label: `Open ${nodeName}`,
      href: new URL(`/nodes/${nodeId}`, env.PUBLIC_ORIGIN).toString(),
    },
  });
}

export async function sendTokenEmail(
  env: Env,
  message: { expiresAt: string },
): Promise<void> {
  const date = new Date(message.expiresAt).toLocaleDateString("en-GB", {
    day: "numeric",
    month: "short",
    year: "numeric",
    timeZone: "UTC",
  });
  const heading = `The Cloudflare token expires on ${date}`;
  const intro =
    "After that, Krynodes can no longer open or close Web addresses. Make a new token in Cloudflare and paste it under Settings, Cloudflare.";
  await deliver(env, {
    title: `[Krynodes] ${heading}`,
    preheader: intro,
    badge: { label: "Token", color: COLOR.primary },
    heading,
    intro,
    rows: [["Expires", date]],
    action: {
      label: "Open Cloudflare settings",
      href: new URL("/settings/cloudflare", env.PUBLIC_ORIGIN).toString(),
    },
  });
}

export async function sendProposalEmail(
  env: Env,
  message: { title: string; openedBy: string },
): Promise<void> {
  const detail =
    "A trusted device opened this change. It needs more approvals before it reaches your servers.";
  await deliver(env, {
    title: `[Krynodes] Waiting for approval: ${message.title}`,
    preheader: detail,
    badge: { label: "Waiting for approval", color: COLOR.primary },
    heading: message.title,
    intro: detail,
    rows: [
      ["Change", message.title],
      ["Opened by", message.openedBy],
    ],
    action: {
      label: "Open Trusted devices",
      href: new URL("/devices", env.PUBLIC_ORIGIN).toString(),
    },
  });
}
