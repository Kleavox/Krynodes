import { escapeHtml } from "../lib/mail";
import type { Bar, Service, ServiceState, StatusView, Summary } from "./data";

const STATE_LABEL: Record<ServiceState, string> = {
  up: "Up",
  down: "Down",
  nodata: "No data",
  paused: "Paused",
};

const MONTHS = [
  "Jan",
  "Feb",
  "Mar",
  "Apr",
  "May",
  "Jun",
  "Jul",
  "Aug",
  "Sep",
  "Oct",
  "Nov",
  "Dec",
];

const WEEKDAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

function clock(ms: number): string {
  const date = new Date(ms);
  return `${String(date.getUTCHours()).padStart(2, "0")}:${String(date.getUTCMinutes()).padStart(2, "0")}`;
}

function when(ms: number, now: number): string {
  const sameDay = Math.floor(ms / 86_400_000) === Math.floor(now / 86_400_000);
  return `${sameDay ? "" : `${weekday(ms)} `}${clock(ms)}`;
}

function weekday(ms: number): string {
  return `${WEEKDAYS[new Date(ms).getUTCDay()]}, ${shortDate(ms)}`;
}

function shortDate(ms: number): string {
  const date = new Date(ms);
  return `${date.getUTCDate()} ${MONTHS[date.getUTCMonth()]}`;
}

interface Clock {
  when(ms: number, now: number): string;
  clock(ms: number): string;
  weekday(ms: number): string;
  zone: string;
}

const UTC: Clock = { when, clock, weekday, zone: " UTC" };

const LOCAL: Clock = {
  when: (ms) => `{w:${ms}}`,
  clock: (ms) => `{c:${ms}}`,
  weekday: (ms) => `{d:${ms}}`,
  zone: "",
};

export const LOCAL_TIMES = String.raw`(()=>{const z=Intl.DateTimeFormat().resolvedOptions().timeZone;const M=["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];const F=Intl.DateTimeFormat("en-US",{timeZone:z,weekday:"short",year:"numeric",month:"numeric",day:"numeric",hour:"2-digit",minute:"2-digit",hourCycle:"h23"});const p=m=>Object.fromEntries(F.formatToParts(m).map(x=>[x.type,x.value]));const c=q=>q.hour+":"+q.minute;const d=q=>q.weekday+", "+q.day+" "+M[q.month-1];const k=q=>q.year+"-"+q.month+"-"+q.day;const f={c,d,t:q=>q.day+" "+M[q.month-1]+" "+q.year+", "+c(q),w:q=>(k(q)===k(p(Date.now()))?"":d(q)+" ")+c(q)};const fill=s=>s.replace(/\{([cdtw]):(\d+)\}/g,(_,x,n)=>f[x](p(Number(n))));for(const e of document.querySelectorAll("[data-local]")){const v=fill(e.getAttribute("data-local"));if(e.tagName==="TIME")e.textContent=v;else e.setAttribute("data-tip",v)}for(const e of document.querySelectorAll("[data-zone]"))e.textContent="Times are in your time zone ("+z+")."})();`;

function moment(ms: number): string {
  return `<time datetime="${new Date(ms).toISOString()}" data-local="{t:${ms}}">${dateTime(ms)} UTC</time>`;
}

function dateTime(ms: number): string {
  const date = new Date(ms);
  const hours = String(date.getUTCHours()).padStart(2, "0");
  const minutes = String(date.getUTCMinutes()).padStart(2, "0");
  return `${shortDate(ms)} ${date.getUTCFullYear()}, ${hours}:${minutes}`;
}

const MONO = `ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace`;

const STYLE = `
:root{color-scheme:dark;--bg:#0c0c10;--card:#14141a;--border:#282831;--fg:#ececf1;--muted:#92929f;--up:#5dcb9a;--partial:#ebba62;--down:#ed7477}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{max-width:760px;margin:0 auto;padding:40px 16px 56px}
h1{margin:0;font-size:24px;font-weight:600;letter-spacing:-0.01em}
.banner{margin:16px 0 0;padding:14px 16px;border:1px solid var(--border);border-radius:10px;background:var(--card);font-weight:500}
.banner-up{color:var(--up);border-color:rgba(93,203,154,.35)}
.banner-down{color:var(--down);border-color:rgba(237,116,119,.45)}
.banner-nodata{color:var(--muted)}
h2{margin:40px 0 12px;font:500 13px/1.4 ${MONO};color:var(--muted)}
.services{list-style:none;margin:0;padding:0;border:1px solid var(--border);border-radius:10px;background:var(--card)}
.service{padding:16px}
.service+.service{border-top:1px solid var(--border)}
.head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}
.name{min-width:0}
h3{margin:0;font-size:15px;font-weight:600;overflow-wrap:anywhere}
.note{margin:2px 0 0;color:var(--muted);font-size:13px;overflow-wrap:anywhere}
.meta{display:flex;flex:none;align-items:center;gap:8px}
.state{flex:none;padding:5px 8px;border:1px solid var(--border);border-radius:999px;font:500 12px/1 ${MONO}}
.state-up{color:var(--up)}
.state-down{color:var(--down);border-color:rgba(237,116,119,.45)}
.state-nodata,.state-paused{color:var(--muted)}
.range{position:absolute;opacity:0;pointer-events:none}
.section-head{display:flex;align-items:flex-end;justify-content:space-between;gap:12px;margin:40px 0 12px}
.section-head h2{margin:0}
.tabs{display:inline-flex;gap:2px;padding:2px;border:1px solid var(--border);border-radius:8px;background:var(--card)}
.tabs label{padding:4px 10px;border-radius:6px;font:500 12px/1.4 ${MONO};color:var(--muted);cursor:pointer}
.tabs label:hover{color:var(--fg)}
#range-day:checked~.section-head label[for=range-day],#range-90:checked~.section-head label[for=range-90]{background:var(--border);color:var(--fg)}
#range-day:focus-visible~.section-head label[for=range-day],#range-90:focus-visible~.section-head label[for=range-90]{outline:2px solid #8b7bff;outline-offset:1px}
.view-90{display:none}
#range-90:checked~.services .view-day{display:none}
#range-90:checked~.services .view-90{display:block}
.bars{display:flex;gap:2px;height:28px;margin-top:12px}
.bar{position:relative;flex:1;min-width:0;border-radius:2px}
.bar:hover{filter:brightness(1.3)}
.bar:hover::after,.tip:hover::after,.tip:focus::after{content:attr(data-tip);position:absolute;bottom:calc(100% + 8px);left:50%;transform:translateX(-50%);z-index:2;padding:5px 8px;border:1px solid var(--border);border-radius:6px;background:#1e1e26;color:var(--fg);font:12px/1.3 ${MONO};white-space:nowrap;pointer-events:none}
.bar:nth-child(-n+8):hover::after{left:0;transform:none}
.bar:nth-last-child(-n+8):hover::after{left:auto;right:0;transform:none}
.tip{position:relative;border-radius:4px;cursor:help;text-decoration:underline dotted;text-underline-offset:3px}
.tip:hover{color:var(--fg)}
.tip:hover::after,.tip:focus::after{white-space:pre;text-align:left}
.tip:focus{outline:none}
.tip:focus-visible{outline:2px solid #8b7bff;outline-offset:2px}
.bar-up{background:rgba(93,203,154,.85)}
.bar-partial{background:var(--partial)}
.bar-down{background:var(--down)}
.bar-nodata,.bar-paused{background:var(--border)}
.legend{display:flex;justify-content:space-between;gap:8px;margin-top:6px;font:11px/1.4 ${MONO};color:var(--muted)}
.narrow{display:none}
.basis{margin:8px 0 0;color:var(--muted);font-size:12px}
footer{margin-top:40px;color:var(--muted);font:12px/1.5 ${MONO}}
.paused{margin:16px 0 0;padding:14px 16px;border:1px solid rgba(139,123,255,.45);border-radius:10px;background:var(--card)}
.paused p{margin:0;color:var(--muted);font-size:14px}
.paused strong{color:var(--fg)}
.resume{display:inline-block;margin-top:12px;padding:8px 14px;border-radius:8px;background:#8b7bff;color:#0c0c10;font-weight:600;text-decoration:none}
.resume:hover{background:#9d8fff}
@media (max-width:560px){.view-90 .bar:nth-child(-n+60){display:none}.view-90 .bar:nth-child(n+61):nth-child(-n+68):hover::after{left:0;transform:none}.wide{display:none}.narrow{display:inline}}
`;

export function formatDuration(ms: number): string {
  const minutes = Math.floor(ms / 60_000);
  if (minutes < 1) return "<1m";
  const days = Math.floor(minutes / 1440);
  const hours = Math.floor((minutes % 1440) / 60);
  const rest = minutes % 60;
  if (days > 0) return hours > 0 ? `${days}d ${hours}h` : `${days}d`;
  if (hours > 0) return rest > 0 ? `${hours}h ${rest}m` : `${hours}h`;
  return `${rest}m`;
}

export function banner(services: Service[]): {
  text: string;
  tone: ServiceState;
} {
  if (services.length === 0)
    return { text: "Nothing to Show Yet", tone: "nodata" };
  const down = services.filter((service) => service.state === "down").length;
  if (down > 0) {
    return {
      text: `${down} ${down === 1 ? "service" : "services"} down`,
      tone: "down",
    };
  }
  if (
    services.every(
      (service) => service.state === "nodata" || service.state === "paused",
    )
  ) {
    return { text: "No Recent Data", tone: "nodata" };
  }
  const silent = services.filter(
    (service) => service.state === "nodata",
  ).length;
  if (silent > 0) {
    return {
      text: `${silent} ${silent === 1 ? "service has" : "services have"} no recent data`,
      tone: "nodata",
    };
  }
  return { text: "All Systems Operational", tone: "up" };
}

function uptimeText(value: number | null): string {
  return value === null
    ? "--"
    : `${(Math.floor(value * 100) / 100).toFixed(2)}%`;
}

function barText(bar: Bar): string {
  if (bar.state === "nodata") return "No Data";
  if (bar.state === "paused") return "Paused";
  if (bar.state === "up") return "Up";
  return `Down ${formatDuration(bar.downMs)}`;
}

function dayTip(day: Bar): string {
  return `${weekday(day.start)} · ${barText(day)}`;
}

function hourTip(hour: Bar, now: number, c: Clock): string {
  return `${c.when(hour.start, now)}–${c.clock(hour.start + 3_600_000)}${c.zone} · ${barText(hour)}`;
}

function summaryTip(
  info: Summary,
  value: number | null,
  since: string,
  last: (ms: number) => string,
): string {
  if (value === null) return `${since}\nNo Data Yet`;
  if (info.lastDown === null) return `${since}\nNo Downtime Recorded`;
  return [
    since,
    `Down ${formatDuration(info.downMs)}`,
    `Last Down ${last(info.lastDown)}`,
  ].join("\n");
}

function recentTip(service: Service, now: number, c: Clock): string {
  return summaryTip(
    service.recentInfo,
    service.recentUptime,
    `Since ${c.when(service.recentInfo.since, now)}${c.zone}`,
    (ms) => `${c.when(ms, now)}${c.zone}`,
  );
}

function longTip(service: Service, c: Clock): string {
  return summaryTip(
    service.longInfo,
    service.uptime,
    `Since ${weekday(service.longInfo.since)}`,
    (ms) => `${c.weekday(ms)} ${c.clock(ms)}${c.zone}`,
  );
}

function tips(tip: (c: Clock) => string): string {
  const utc = tip(UTC);
  const local = tip(LOCAL);
  return `data-tip="${escapeHtml(utc)}"${local === utc ? "" : ` data-local="${escapeHtml(local)}"`}`;
}

function uptimeTip(value: number | null, tip: (c: Clock) => string): string {
  return `<span class="tip" tabindex="0" ${tips(tip)}>${uptimeText(value)} uptime</span>`;
}

function bar(state: string, tip: (c: Clock) => string): string {
  return `<span class="bar bar-${state}" ${tips(tip)}></span>`;
}

function serviceItem(service: Service, now: number): string {
  const daySummary = `${service.name}: ${uptimeText(service.recentUptime)} uptime over 24 hours`;
  const longSummary = `${service.name}: ${uptimeText(service.uptime)} uptime over 90 days`;
  const hours = service.recent
    .map((hour) => bar(hour.state, (c) => hourTip(hour, now, c)))
    .join("");
  const days = service.days
    .map((day) => bar(day.state, () => dayTip(day)))
    .join("");
  return `<li class="service">
<div class="head"><div class="name"><h3>${escapeHtml(service.name)}</h3>${
    service.note ? `<p class="note">${escapeHtml(service.note)}</p>` : ""
  }</div><div class="meta"><span class="state state-${service.state}">${STATE_LABEL[service.state]}</span></div></div>
<div class="view view-day"><div class="bars" role="img" aria-label="${escapeHtml(daySummary)}">${hours}</div>
<div class="legend"><span>24 hours ago</span>${uptimeTip(service.recentUptime, (c) => recentTip(service, now, c))}<span>Now</span></div></div>
<div class="view view-90"><div class="bars" role="img" aria-label="${escapeHtml(longSummary)}">${days}</div>
<div class="legend"><span><span class="wide">90 days ago</span><span class="narrow">30 days ago</span></span>${uptimeTip(service.uptime, (c) => longTip(service, c))}<span>Today</span></div></div>
</li>`;
}

const FAVICON = `data:image/svg+xml,${encodeURIComponent(
  '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><style>path{stroke:#5b47e6}circle{fill:#8b7bff}@media (prefers-color-scheme:dark){path{stroke:#8b7bff}circle{fill:#bab8ff}}</style><path d="M6 3.75v16.5M6 12 17.75 5M6 12l11.75 7" fill="none" stroke-width="3" stroke-linecap="round"/><circle cx="6" cy="12" r="3.1"/><circle cx="17.75" cy="5" r="2.75"/><circle cx="17.75" cy="19" r="2.75"/></svg>',
)}`;

export const REFRESH_ROUNDS = 2;
const REFRESH_SECONDS = 600;

export function personalize(
  html: string,
  round: number,
  renderedAt: number,
): string {
  const paused = round >= REFRESH_ROUNDS;
  const refresh = paused
    ? ""
    : `<meta http-equiv="refresh" content="${REFRESH_SECONDS};url=/?r=${round + 1}">`;
  const notice = paused
    ? `<div class="paused" role="status"><p><strong>Updates paused.</strong> This page stopped refreshing after ${(REFRESH_ROUNDS * REFRESH_SECONDS) / 60} minutes. The data below is from ${moment(renderedAt)}.</p><a class="resume" href="/">Resume Updates</a></div>`
    : "";
  return html
    .replace("<!--refresh-->", refresh)
    .replace("<!--paused-->", notice);
}

export function renderStatus(view: StatusView, now: number): string {
  const head = banner(view.services);
  const services =
    view.services.length > 0
      ? `<ul class="services">${view.services.map((service) => serviceItem(service, now)).join("")}</ul>`
      : "";
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<!--refresh-->
<meta name="robots" content="noindex, nofollow">
<meta name="color-scheme" content="dark">
<title>Service status</title>
<link rel="icon" type="image/svg+xml" href="${FAVICON}">
<style>${STYLE}</style>
</head>
<body>
<main>
<input type="radio" name="range" id="range-day" class="range" checked>
<input type="radio" name="range" id="range-90" class="range">
<h1>Service status</h1>
<!--paused-->
<p class="banner banner-${head.tone}">${head.text}</p>
<div class="section-head"><h2>Services</h2><div class="tabs" role="group" aria-label="Range"><label for="range-day">24 Hours</label><label for="range-90">90 Days</label></div></div>
${services}
<p class="basis">Uptime counts the time a service was up or down. Orange means part of a bar was down, red most of it, grey no data or paused. <span data-zone="">Times are UTC.</span></p>
<footer>Monitored by Krynodes · updated ${moment(now)}</footer>
</main>
<script>${LOCAL_TIMES}</script>
</body>
</html>`;
}
