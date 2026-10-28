import { TAILSCALE, type TailscaleReport } from "@krynodes/protocol";
import { agentSupported, MIN_AGENT_VERSION } from "@krynodes/protocol/versions";

import type {
  ActionRecord,
  AptReport,
  NodeRecord,
  PackagesResponse,
  RestartFacts,
  SecurityReport,
  UpdatesSummary,
} from "../types";
import { formatPrint } from "./devices";
import {
  formatBytes,
  nodeState,
  parseTimestamp,
  shortDate,
  stampTime,
  timeAgo,
} from "./format";
import { fromUtcHour } from "./security";
import { isPending, RECIPE_TITLES } from "./services";

const DAY_MS = 86_400_000;
const EXPIRY_WARN_DAYS = 14;
const MONTHS = new Intl.DateTimeFormat("en-GB", {
  day: "numeric",
  month: "short",
  year: "numeric",
});

type Mark = "+" | "!" | "✓" | "−" | "↑" | "·" | "✕";

export interface Line {
  mark: Mark;
  title: string;
  detail: string[];
}

interface Change {
  name: string;
  version: string;
}

interface Port {
  port: number;
  protocol: string;
  open?: boolean;
}

export interface InstallPreview {
  what: "install";
  name: string;
  installs: Change[];
  upgrades: Change[];
  removes: string[];
  download: number | null;
  disk: number | null;
  services: { unit: string; ports: Port[] | null }[];
  unread: boolean;
  firewall: string | null;
  refused: string | null;
}

export interface RemovePreview {
  what: "remove" | "purge";
  name: string;
  removes: string[];
  stops: string[];
  refused: string | null;
}

export interface UpgradePreview {
  what: "upgrade";
  upgrades: Change[];
  adds: Change[];
  restarts: string[];
}

export interface RepoPreview {
  what: "addrepo";
  name: string;
  uri: string;
  suites: string[];
  components: string[];
  file: string;
  key: { fingerprint: string; user: string } | null;
  answers: boolean;
  packages: string[];
  count: number;
  refused: string | null;
}

export interface Match {
  name: string;
  version: string;
  summary: string;
  from: string | null;
  installed: string | null;
}

export interface Outcome {
  upgraded: string[];
  moved: { name: string; from: string; to: string }[];
  added: string[];
  removed: string[];
  took: number;
  waited: number;
  holder?: string;
  repaired: boolean;
  kept: string[];
  left?: string[];
  failed?: string;
  tail?: string[];
  restarted?: string[];
  stacks?: { project: string; running: number; total: number }[];
  old?: string[];
  listeners?: {
    address: string;
    port: number;
    protocol: string;
    process: string;
  }[];
}

const list = (items: string[]) =>
  new Intl.ListFormat("en-GB", { type: "conjunction" }).format(items);

const count = (amount: number, word: string, many = `${word}s`) =>
  `${amount} ${amount === 1 ? word : many}`;

const unitName = (unit: string) => unit.replace(/\.service$/u, "");

const uses = (names: string[]) => (names.length === 1 ? "uses" : "use");

export function tookText(seconds: number): string {
  const total = Math.max(0, Math.round(seconds));
  if (total < 60) return `${total}s`;
  const rest = total % 60;
  return rest === 0
    ? `${Math.floor(total / 60)}m`
    : `${Math.floor(total / 60)}m ${rest}s`;
}

function parsed<T>(text: string | null): T | null {
  if (!text) return null;
  try {
    return JSON.parse(text) as T;
  } catch {
    return null;
  }
}

export const outcomeOf = (action: Pick<ActionRecord, "output">) =>
  parsed<Outcome>(action.output);

export const agentNeeded = (node: Pick<NodeRecord, "agent_version">) =>
  agentSupported(node.agent_version)
    ? null
    : `Needs agent ${MIN_AGENT_VERSION} or newer · it runs ${node.agent_version ?? "--"}`;

export function packagesBlocker(
  node: Pick<
    NodeRecord,
    | "name"
    | "agent_version"
    | "disabled_at"
    | "enrolled_at"
    | "last_seen_at"
    | "interval_seconds"
  >,
  trusted: boolean,
  now: number,
): string | null {
  if (!agentSupported(node.agent_version)) {
    return `Needs agent ${MIN_AGENT_VERSION}`;
  }
  if (nodeState(node, now) !== "online") {
    return `Waits until ${node.name} is back online`;
  }
  return trusted ? null : "Not Trusted Yet";
}

const kernelNewer = (restart: RestartFacts) =>
  restart.running !== null &&
  restart.newest !== null &&
  restart.running !== restart.newest;

function restartReason(restart: RestartFacts): string {
  if (kernelNewer(restart)) return "Restart for the new kernel";
  if (!restart.file && restart.services.length > 0) {
    const names = restart.services.map(unitName);
    return names.length <= 2
      ? `${list(names)} ${uses(names)} old libraries`
      : `${names.length} services use old libraries`;
  }
  return "Restart to finish the update";
}

export function updatesLine(
  summary: UpdatesSummary | null | undefined,
  now: number,
): { text: string; restart: string | null } | null {
  if (!summary) return null;
  const text =
    summary.waiting === 0
      ? "Up to date"
      : [
          `${summary.waiting} waiting`,
          summary.security > 0 ? `${summary.security} security` : null,
          summary.checkedAt
            ? `checked ${timeAgo(summary.checkedAt, now)}`
            : null,
        ]
          .filter(Boolean)
          .join(" · ");
  return {
    text,
    restart: summary.restart ? restartReason(summary.restart) : null,
  };
}

export function updatesHeader(report: AptReport): string {
  const security = report.updates.filter((update) => update.security).length;
  const held = report.updates.filter((update) => update.held).length;
  return [
    "Updates",
    report.updates.length === 0
      ? "Up to date"
      : `${report.updates.length} waiting`,
    security > 0 ? `${security} security` : null,
    held > 0 ? `${held} held` : null,
  ]
    .filter(Boolean)
    .join(" · ");
}

export function updateRow(update: AptReport["updates"][number]): {
  tag: "Security" | "Held Back" | "Held" | null;
  versions: string;
  note: string | null;
} {
  if (update.held) {
    return {
      tag: "Held",
      versions: update.from,
      note: `Stays at ${update.from} by your choice. Upgrade All and the daily security updates leave it. · ${update.to} out`,
    };
  }
  const versions = `${update.from} → ${update.to}`;
  if (update.back) {
    const { adds, removes } = update.back;
    return {
      tag: "Held Back",
      versions,
      note:
        removes.length > 0
          ? `Would remove ${list(removes)}. Upgrade All leaves it.`
          : `Needs ${adds.length === 1 ? "a new package" : "new packages"}, ${list(adds)}. Upgrade All brings ${adds.length === 1 ? "it" : "them"} along and says so first.`,
    };
  }
  return { tag: update.security ? "Security" : null, versions, note: null };
}

export function packagesHeader(
  node: Pick<
    NodeRecord,
    "name" | "disabled_at" | "enrolled_at" | "last_seen_at" | "interval_seconds"
  >,
  response: PackagesResponse | undefined,
  now: number,
): { line: string; offline: string | null; noApt: string | null } {
  const report = response?.report ?? null;
  const offline =
    nodeState(node, now) === "offline"
      ? `Read ${timeAgo(response?.readAt ?? null, now)} · ${node.name} is offline`
      : null;
  if (!report) {
    return { line: `${node.name} · not read yet`, offline, noApt: null };
  }
  if (!report.apt) {
    return {
      line: `${node.name} · ${report.system || "--"}`,
      offline,
      noApt: `Packages works with apt: Debian, Ubuntu and Raspberry Pi OS. ${node.name} runs ${report.system || "another system"}.`,
    };
  }
  return {
    line: [
      node.name,
      report.system,
      `${report.installed} installed`,
      report.checkedAt
        ? `checked ${timeAgo(report.checkedAt, now)}`
        : "checked --",
    ].join(" · "),
    offline,
    noApt: null,
  };
}

export function shownPackages(
  report: AptReport,
  options: { all: boolean; query: string },
): AptReport["packages"] {
  const query = options.query.trim().toLowerCase();
  return report.packages.filter(
    (entry) =>
      (options.all || entry.by !== null) &&
      (!query || entry.name.includes(query)),
  );
}

const rebootAt = (
  security: Pick<SecurityReport, "recipes" | "rebootHour"> | null | undefined,
  offsetMinutes: number,
) =>
  security?.recipes.includes("reboot-window") && security.rebootHour !== null
    ? `${String(fromUtcHour(security.rebootHour, offsetMinutes)).padStart(2, "0")}:00`
    : null;

export function restartFacts(
  restart: RestartFacts,
  now: number,
): { since: string; read: string } {
  const services = restart.services.map(unitName);
  const sources = [
    kernelNewer(restart)
      ? "the running kernel against the installed one"
      : null,
    restart.file ? "/run/reboot-required" : null,
    services.length > 0 ? "the libraries running services use" : null,
  ].filter((source): source is string => source !== null);
  const read =
    sources.length <= 1
      ? sources.join("")
      : `${sources.slice(0, -1).join(", ")}, and ${sources.at(-1)}`;
  return {
    since: `since ${stampTime(restart.since, now)}`,
    read: [
      kernelNewer(restart)
        ? `Running kernel ${restart.running}, newest installed ${restart.newest}.`
        : null,
      services.length > 0
        ? `${list(services)} still ${uses(services)} old libraries.`
        : null,
      sources.length > 0 ? `Read from the server: ${read}.` : null,
    ]
      .filter(Boolean)
      .join(" "),
  };
}

export function restartLine(
  security: Pick<SecurityReport, "recipes" | "rebootHour"> | null | undefined,
  offsetMinutes = new Date().getTimezoneOffset(),
): string {
  const at = rebootAt(security, offsetMinutes);
  return at
    ? `Restarts at ${at} by Restart When Needed`
    : "Restart When Needed is off; restart it yourself";
}

export function onTheirOwn(
  report: AptReport,
  security: Pick<SecurityReport, "recipes" | "rebootHour"> | null | undefined,
  now: number,
  offsetMinutes = new Date().getTimezoneOffset(),
): { security: Line; restarts: Line } {
  const at = rebootAt(security, offsetMinutes);
  return {
    security: report.security.on
      ? {
          mark: "✓",
          title: "Installed every day",
          detail: [
            `unattended-upgrades · last ran ${report.security.lastRan ? stampTime(report.security.lastRan, now) : "--"}`,
          ],
        }
      : { mark: "·", title: "Off", detail: [] },
    restarts: at
      ? { mark: "✓", title: `At ${at} by Restart When Needed`, detail: [] }
      : {
          mark: "·",
          title: "Never on their own",
          detail: ["You restart with Restart Server"],
        },
  };
}

export function packageAttention(
  node: Pick<NodeRecord, "updates" | "tailscale">,
  security:
    | Pick<SecurityReport, "recipes" | "rebootHour" | "findings">
    | null
    | undefined,
  now: number,
  offsetMinutes = new Date().getTimezoneOffset(),
): { reasons: string[]; notes: string[] } {
  const reasons: string[] = [];
  const notes: string[] = [];
  const updates = node.updates;
  if (updates?.restart) {
    if (rebootAt(security, offsetMinutes)) {
      notes.push(restartLine(security, offsetMinutes));
    } else {
      reasons.push("Restart Needed");
    }
  }
  if (
    updates &&
    updates.security > 0 &&
    security?.findings.some((finding) => finding.id === "updates-off")
  ) {
    reasons.push(`${count(updates.security, "security update")} waiting`);
  }
  const expiry =
    node.tailscale?.keyExpiry && !tagged(node.tailscale)
      ? parseTimestamp(node.tailscale.keyExpiry)
      : null;
  if (expiry !== null && expiry <= now) {
    reasons.push("Tailscale key expired");
  } else if (expiry !== null && expiry - now <= EXPIRY_WARN_DAYS * DAY_MS) {
    notes.push(
      `Tailscale key expires in ${count(Math.ceil((expiry - now) / DAY_MS), "day")}`,
    );
  }
  return { reasons, notes };
}

export function busyText(
  action: Pick<ActionRecord, "kind" | "name" | "action" | "progress">,
): string | null {
  if (action.kind !== "apt" && !namesServer(action)) return null;
  const doing: Partial<Record<ActionRecord["action"], string>> = {
    upgrade: "Upgrading packages",
    install: `Installing ${action.name}`,
    remove: `Removing ${action.name}`,
    purge: `Removing ${action.name}`,
    refresh: "Checking for updates",
    addrepo: `Adding the ${action.name} repository`,
    droprepo: `Removing the ${action.name} repository`,
    hold: `Holding ${action.name}`,
    unhold: `Releasing the hold on ${action.name}`,
    signin: "Signing in to Tailscale",
  };
  const step = action.progress;
  return (
    [
      doing[action.action] ?? null,
      step && step.total > 0 ? `${step.done} of ${step.total}` : null,
    ]
      .filter(Boolean)
      .join(" · ") || null
  );
}

export interface TailscaleLine {
  lines: string[];
  warn: boolean;
  action: "Sign In" | "Sign In Again" | null;
  after: string | null;
}

const tagged = (report: TailscaleReport) =>
  report.tags?.includes(TAILSCALE.tag) ?? false;

export function tailscaleLine(
  report: TailscaleReport,
  name: string,
  now: number,
): TailscaleLine {
  if (report.state === "stopped") {
    return {
      lines: [
        "tailscaled is not running",
        "Start it from Services. Signing in waits until it runs.",
      ],
      warn: true,
      action: null,
      after: null,
    };
  }
  if (report.state === "running" && tagged(report)) {
    return {
      lines: [
        report.addresses[0] ?? "--",
        ...(report.name ? [report.name] : []),
        `${TAILSCALE.tag} · key never expires`,
      ],
      warn: false,
      action: null,
      after: null,
    };
  }
  const expiry = report.keyExpiry ? parseTimestamp(report.keyExpiry) : null;
  if (expiry !== null && expiry <= now) {
    return {
      lines: [`Key expired ${shortDate(expiry)} · ${name} left your tailnet`],
      warn: true,
      action: "Sign In Again",
      after: null,
    };
  }
  if (report.state === "needs-login") {
    return {
      lines: ["Installed, not signed in"],
      warn: false,
      action: "Sign In",
      after: null,
    };
  }
  if (expiry !== null && expiry - now <= EXPIRY_WARN_DAYS * DAY_MS) {
    return {
      lines: [
        `Key expires in ${count(Math.ceil((expiry - now) / DAY_MS), "day")}`,
      ],
      warn: true,
      action: "Sign In Again",
      after: `, or turn off key expiry for ${name} in Tailscale's admin console`,
    };
  }
  return {
    lines: [
      report.addresses[0] ?? "--",
      ...(report.name ? [report.name] : []),
      expiry === null
        ? "Key does not expire"
        : `Key expires ${MONTHS.format(expiry)}`,
    ],
    warn: false,
    action: null,
    after: null,
  };
}

export const signedIn = (
  start: TailscaleReport,
  current: TailscaleReport | null | undefined,
) =>
  current?.state === "running" &&
  (start.state !== "running" || current.keyExpiry !== start.keyExpiry);

export const signInRows = (name: string, again: boolean) =>
  again
    ? [`${name} keeps its other Tailscale settings`]
    : [`${name} keeps its own DNS`, "Tailscale SSH stays off"];

export function signedInLines(report: TailscaleReport, name: string): Line[] {
  const expiry = report.keyExpiry ? parseTimestamp(report.keyExpiry) : null;
  return [
    {
      mark: "✓",
      title: `${name} is on your tailnet`,
      detail: [
        [report.addresses[0] ?? "--", report.name].filter(Boolean).join(" · "),
      ],
    },
    expiry === null
      ? { mark: "·", title: "Its Tailscale key does not expire", detail: [] }
      : {
          mark: "·",
          title: `Its Tailscale key expires on ${MONTHS.format(expiry)}`,
          detail: [
            `Krynodes tells you ${EXPIRY_WARN_DAYS} days before. Or turn off key expiry for ${name} in Tailscale's admin console.`,
          ],
        },
  ];
}

function portsDetail(
  ports: Port[] | null,
  firewall: string | null,
  nodeName: string,
): string {
  if (ports === null) return "Its ports show once it runs.";
  if (ports.length === 0) return "It opens no port.";
  const numbers = list(ports.map((port) => String(port.port)));
  const listens = `It listens on ${ports.length === 1 ? "port" : "ports"} ${numbers}.`;
  if (!firewall) {
    return `${listens} No firewall on ${nodeName} keeps it closed from outside.`;
  }
  return ports.every((port) => port.open === true)
    ? `${listens} ${firewall} on ${nodeName} lets it in from outside.`
    : `${listens} ${firewall} on ${nodeName} keeps it closed from outside until you open the port.`;
}

export function installLines(
  preview: InstallPreview,
  nodeName: string,
): Line[] {
  if (preview.refused) {
    return [{ mark: "!", title: preview.refused, detail: [] }];
  }
  const changes = [
    ...preview.upgrades.map((change): Line => ({
      mark: "↑",
      title: `Upgrades ${change.name} to ${change.version}`,
      detail: [],
    })),
    ...preview.removes.map((name): Line => ({
      mark: "−",
      title: `Removes ${name}`,
      detail: [],
    })),
  ];
  return [
    {
      mark: "+",
      title: `Installs ${count(preview.installs.length, "package")}`,
      detail: [
        preview.installs.map((change) => change.name).join(", "),
        `${formatBytes(preview.download)} to download, ${formatBytes(preview.disk)} on disk`,
      ],
    },
    ...preview.services.map((service): Line => ({
      mark: "!",
      title: `Starts ${service.unit} right away, and at every boot`,
      detail: [portsDetail(service.ports, preview.firewall, nodeName)],
    })),
    ...(preview.unread
      ? [
          {
            mark: "·" as const,
            title: "Too large to read beforehand",
            detail: [
              "The services it starts and their ports show once it runs.",
            ],
          },
        ]
      : []),
    ...(changes.length > 0
      ? changes
      : [
          {
            mark: "✓" as const,
            title: "Removes nothing, replaces nothing",
            detail: [],
          },
        ]),
  ];
}

export function removeChoices(
  name: string,
  nodeName: string,
): { id: "remove" | "purge"; title: string; detail: string }[] {
  const tailscale = name === "tailscale";
  return [
    {
      id: "remove",
      title: "Remove",
      detail: tailscale
        ? "Keeps /var/lib/tailscale, so installing it again brings back the same machine on your tailnet"
        : "Keeps its settings and data, so installing it again picks them up",
    },
    {
      id: "purge",
      title: "Remove with Settings",
      detail: tailscale
        ? `Also deletes /var/lib/tailscale. ${nodeName} has to log in to Tailscale again as a new machine.`
        : "Also deletes its settings and data.",
    },
  ];
}

export function removeLines(
  preview: RemovePreview,
  context: {
    nodeName: string;
    repository: boolean;
    tailscale?: TailscaleReport | null;
    publicAddress?: string | null;
  },
): Line[] {
  if (preview.refused) {
    return [{ mark: "!", title: preview.refused, detail: [] }];
  }
  const tailnet =
    preview.removes.includes("tailscale") &&
    context.tailscale?.state === "running";
  const address = context.tailscale?.addresses[0];
  const stops = preview.stops
    .filter((unit) => !(tailnet && unit === "tailscaled.service"))
    .map(unitName);
  return [
    {
      mark: "−",
      title: `Removes ${list(preview.removes)}`,
      detail: context.repository
        ? ["Its repository stays under Sources until you remove it there"]
        : [],
    },
    ...(stops.length > 0
      ? [{ mark: "!" as const, title: `Stops ${list(stops)}`, detail: [] }]
      : []),
    ...(tailnet
      ? [
          {
            mark: "!" as const,
            title: `${context.nodeName} leaves your tailnet`,
            detail: [
              [
                address
                  ? `SSH to ${address} stops working${context.publicAddress ? `; use the public address ${context.publicAddress} instead.` : "."}`
                  : null,
                "Krynodes keeps its own connection.",
              ]
                .filter(Boolean)
                .join(" "),
            ],
          },
        ]
      : []),
  ];
}

export function upgradeLines(
  preview: UpgradePreview,
  context: {
    nodeName: string;
    report: AptReport;
    stacks: string[];
    reached?: string[];
  },
): { header: string; lines: Line[] } {
  const neededBy = (name: string) =>
    context.report.updates.find((update) => update.back?.adds.includes(name))
      ?.name;
  const adds = preview.adds.map((change) => change.name);
  const needer = adds.length > 0 ? neededBy(adds[0]!) : undefined;
  const restarts = preview.restarts.map(unitName);
  const others = restarts.filter(
    (unit) => unit !== "docker" && unit !== "tailscaled",
  );
  const reached = context.reached ?? [];
  return {
    header: `${count(preview.upgrades.length, "update")}. Nothing is removed.`,
    lines: [
      ...(preview.upgrades.length > 0
        ? [
            {
              mark: "↑" as const,
              title: list(preview.upgrades.map((change) => change.name)),
              detail:
                adds.length > 0
                  ? [
                      `plus ${count(adds.length, "new package")}${needer ? ` ${needer} needs` : ""}: ${adds.join(", ")}`,
                    ]
                  : [],
            },
          ]
        : []),
      ...(restarts.includes("docker")
        ? [
            {
              mark: "!" as const,
              title: "Docker restarts",
              detail: [
                [
                  context.stacks.length > 0
                    ? `Every stack on ${context.nodeName} stops for a few seconds: ${list(context.stacks)}.`
                    : `Containers on ${context.nodeName} stop for a few seconds.`,
                  reached.length > 0
                    ? `Other servers that reach ${list(reached)} lose ${reached.length === 1 ? "it" : "them"} meanwhile.`
                    : null,
                ]
                  .filter(Boolean)
                  .join(" "),
              ],
            },
          ]
        : []),
      ...(restarts.includes("tailscaled")
        ? [
            {
              mark: "!" as const,
              title: "tailscaled restarts",
              detail: [
                `The Tailscale link to ${context.nodeName} drops for a moment. Krynodes keeps its own connection.`,
              ],
            },
          ]
        : []),
      ...(others.length > 0
        ? [
            {
              mark: "!" as const,
              title: `${list(others)} ${others.length === 1 ? "restarts" : "restart"}`,
              detail: [],
            },
          ]
        : []),
      ...context.report.updates
        .filter((update) => update.held)
        .map((update): Line => ({
          mark: "·",
          title: `Leaves ${update.name} at ${update.from}, held by you.`,
          detail: [],
        })),
      ...context.report.updates
        .filter(
          (update) => !update.held && (update.back?.removes.length ?? 0) > 0,
        )
        .map((update): Line => ({
          mark: "·",
          title: `Leaves ${update.name} at ${update.from}: it would remove ${list(update.back!.removes)}.`,
          detail: [],
        })),
    ],
  };
}

export function repoLines(preview: RepoPreview, system: string): Line[] {
  if (preview.refused) {
    return [{ mark: "!", title: preview.refused, detail: [] }];
  }
  const distro = system.split(" ")[0] || "the system";
  const shown = preview.packages.join(", ");
  const more = preview.count - preview.packages.length;
  return [
    preview.key
      ? {
          mark: "✓",
          title: `Key fetched over HTTPS · ${preview.key.user || "no owner named"}`,
          detail: [
            formatPrint(preview.key.fingerprint),
            "Compare it with the one on the vendor's site before you add it.",
          ],
        }
      : { mark: "!", title: "The key could not be read", detail: [] },
    preview.answers
      ? {
          mark: "✓",
          title: `The address answers for ${list(preview.suites)} · ${count(preview.count, "package")}${preview.count > 0 ? `: ${shown}${more > 0 ? ` and ${more} more` : ""}` : ""}`,
          detail: [],
        }
      : {
          mark: "!",
          title: `The address does not answer for ${list(preview.suites)}`,
          detail: [],
        },
    {
      mark: "+",
      title: `Writes ${preview.file} and its key`,
      detail: [
        `The key is trusted for this repository only, never for ${distro}'s own packages.`,
      ],
    },
  ];
}

export function finishedLines(
  action: Pick<ActionRecord, "action" | "name" | "output" | "status">,
  context: {
    nodeName: string;
    stacks?: { project: string; running: number; total: number }[];
    tailscale?: TailscaleReport | null;
  },
): Line[] {
  const outcome = outcomeOf(action);
  if (!outcome) {
    return action.status === "failed" || action.status === "expired"
      ? [{ mark: "✕", title: action.output || "It did not finish", detail: [] }]
      : [];
  }
  const restarted = (outcome.restarted ?? []).map(unitName);
  const stacks = context.stacks ?? [];
  const back = stacks.filter((stack) => stack.running === stack.total);
  const down = stacks.filter((stack) => stack.running !== stack.total);
  const old = (outcome.old ?? []).map(unitName);
  const lines: Line[] = [];
  if (outcome.repaired) {
    lines.push({
      mark: "✓",
      title: "Finished an earlier apt run that was cut off",
      detail: [],
    });
  }
  if (outcome.waited > 0) {
    lines.push({
      mark: "✓",
      title: `Waited ${outcome.waited}s for ${outcome.holder ?? "another program"} to finish`,
      detail: [],
    });
  }
  if (outcome.failed) {
    lines.push({ mark: "✕", title: outcome.failed, detail: [] });
    if (action.action === "install" && outcome.added.length > 0) {
      lines.push(
        outcome.left && outcome.left.length > 0
          ? {
              mark: "!",
              title: `Still on ${context.nodeName}: ${list(outcome.left)}`,
              detail: ["Removing what this install added failed too."],
            }
          : {
              mark: "✓",
              title: `Removed what it had added: ${list(outcome.added)}`,
              detail: [],
            },
      );
    }
  } else if (action.action === "upgrade") {
    lines.push({
      mark: "✓",
      title: [
        `Upgraded ${outcome.upgraded.length}`,
        outcome.added.length > 0 ? `added ${outcome.added.length}` : null,
      ]
        .filter(Boolean)
        .join(", "),
      detail: [tookText(outcome.took)],
    });
  } else if (action.action === "install") {
    lines.push({
      mark: "✓",
      title: `Installed ${count(outcome.added.length, "package")}`,
      detail: [outcome.added.join(", "), tookText(outcome.took)],
    });
  } else {
    lines.push({
      mark: "✓",
      title: `Removed ${list(outcome.removed)}${action.action === "purge" ? " with its settings" : ""}`,
      detail: [tookText(outcome.took)],
    });
  }
  for (const file of outcome.kept) {
    lines.push({
      mark: "·",
      title: `Kept your ${file}; the new default is beside it`,
      detail: [],
    });
  }
  if (restarted.includes("docker")) {
    lines.push(
      down.length > 0
        ? {
            mark: "!",
            title: `Docker restarted · ${list(down.map((stack) => stack.project))} ${down.length === 1 ? "is" : "are"} not running yet`,
            detail: [],
          }
        : {
            mark: "✓",
            title:
              back.length > 0
                ? `Docker restarted · ${list(back.map((stack) => stack.project))} ${back.length === 1 ? "is" : "are"} running again`
                : "Docker restarted",
            detail: [],
          },
    );
  }
  const others = restarted.filter((unit) => unit !== "docker");
  if (others.length > 0) {
    lines.push({ mark: "·", title: `Restarted ${list(others)}`, detail: [] });
  }
  for (const listener of outcome.listeners ?? []) {
    lines.push({
      mark: "!",
      title: `${listener.process || "A new program"} listens on port ${listener.port}/${listener.protocol}`,
      detail: [],
    });
  }
  if (
    action.action === "install" &&
    action.name === "tailscale" &&
    !outcome.failed
  ) {
    if (context.tailscale && context.tailscale.state !== "stopped") {
      lines.push({
        mark: "✓",
        title: "tailscaled is running, and starts at every boot",
        detail: [],
      });
    }
    if (context.tailscale?.state !== "running") {
      lines.push({
        mark: "!",
        title: `${context.nodeName} is not on your tailnet yet`,
        detail: ["Sign it in from here. No terminal needed."],
      });
    }
  }
  if (old.length > 0) {
    lines.push({
      mark: "!",
      title: "Restart Needed",
      detail: [
        `${list(old)} still ${uses(old)} old libraries. Restart Server, or restart just ${list(old)} from Services.`,
      ],
    });
  }
  return lines;
}

const OUTCOMES = new Set<ActionRecord["action"]>([
  "install",
  "upgrade",
  "remove",
  "purge",
]);

export function changedLines(outcome: Outcome): Line[] {
  const lines: Line[] = [
    ...outcome.moved.map((move) => ({
      mark: "↑" as const,
      title: `${move.name} ${move.from} → ${move.to}`,
      detail: [],
    })),
    ...outcome.added.map((name) => ({
      mark: "+" as const,
      title: name,
      detail: [],
    })),
    ...outcome.removed.map((name) => ({
      mark: "−" as const,
      title: name,
      detail: [],
    })),
  ];
  return lines.length > 0
    ? lines
    : [
        {
          mark: "·",
          title: "Nothing changed: apt stopped before unpacking anything.",
          detail: [],
        },
      ];
}

export function historyLines(
  action: Pick<ActionRecord, "kind" | "action" | "name" | "output" | "status">,
  nodeName: string,
): Line[] | null {
  const outcome =
    action.kind === "apt" && OUTCOMES.has(action.action)
      ? outcomeOf(action)
      : null;
  if (!outcome) return null;
  if (outcome.failed) return changedLines(outcome);
  const changed =
    outcome.moved.length + outcome.added.length + outcome.removed.length > 0;
  return [
    ...(changed ? changedLines(outcome) : []),
    ...finishedLines(action, { nodeName, stacks: outcome.stacks }),
  ];
}

export function retryDialog(
  action: Pick<ActionRecord, "action" | "name">,
):
  | { kind: "upgrade" }
  | { kind: "install"; name: string }
  | { kind: "remove"; name: string } {
  if (action.action === "upgrade") return { kind: "upgrade" };
  return action.action === "install"
    ? { kind: "install", name: action.name }
    : { kind: "remove", name: action.name };
}

export function aptOutput(
  action: Pick<ActionRecord, "kind" | "output">,
): string | null {
  const outcome = action.kind === "apt" ? outcomeOf(action) : null;
  return outcome?.tail?.join("\n") ?? outcome?.failed ?? action.output;
}

export function jobLines(
  action: Pick<ActionRecord, "kind" | "action" | "name" | "output" | "status">,
  context: Parameters<typeof finishedLines>[1],
): Line[] {
  if (OUTCOMES.has(action.action)) return finishedLines(action, context);
  if (action.status === "failed" || action.status === "expired") {
    return [
      { mark: "✕", title: action.output || "It did not finish", detail: [] },
    ];
  }
  if (action.status !== "done") return [];
  if (action.action === "addrepo") {
    const file = parsed<{ file?: string }>(action.output)?.file;
    return [
      {
        mark: "✓",
        title: `Added the ${action.name} repository`,
        detail: file ? [file] : [],
      },
    ];
  }
  const said: Partial<Record<ActionRecord["action"], string>> = {
    droprepo: `Removed the ${action.name} repository`,
    refresh: "Checked for updates",
    signin: "Asked tailscaled to sign in",
  };
  return [{ mark: "✓", title: said[action.action] ?? "Done", detail: [] }];
}

export interface VendorPaste {
  name: string | null;
  release: string | null;
  components: string | null;
  uri: string | null;
  key: string | null;
  list: string | null;
}

const RELEASE_HERE = "@release@";

export function parseVendorPaste(text: string): VendorPaste {
  const plain = text.replace(
    /\$\([^()]*(?:\([^()]*\)[^()]*)*\)|\$\{[^}]*\}|\$[A-Z_]+/gu,
    RELEASE_HERE,
  );
  const urls = [...plain.matchAll(/https:\/\/[^\s'"|<>\\]+/gu)].map(
    (match) => match[0]!,
  );
  const deb =
    /(?:^|["'\s])deb\s+(?:\[[^\]]*\]\s+)?(https:\/\/\S+)\s+(\S+)(?:\s+([^"'\n|]+))?/mu.exec(
      plain,
    );
  const listUrl = urls.find((url) => /\.list$/u.test(url)) ?? null;
  const key =
    urls.find(
      (url) =>
        url !== listUrl &&
        (/\.(?:gpg|asc|key)$/u.test(url) || /\/(?:gpg|key)$/u.test(url)),
    ) ?? null;
  const uri =
    deb?.[1]?.replace(/\/$/u, "") ??
    (listUrl ? listUrl.slice(0, listUrl.lastIndexOf("/")) : null);
  const suite = deb?.[2];
  const release =
    suite && !suite.includes(RELEASE_HERE)
      ? suite
      : (/\/([a-z]+)\.[^/]*\.list$/u.exec(listUrl ?? "")?.[1] ?? null);
  const target =
    /sources\.list\.d\/([a-z0-9][a-z0-9.-]*)\.(?:list|sources)/u.exec(
      plain,
    )?.[1];
  const host = uri ? new URL(uri).hostname.split(".") : [];
  return {
    name: target ?? (host.length >= 2 ? host.at(-2)! : null),
    release,
    components: deb?.[3]?.trim() || null,
    uri,
    key,
    list: deb ? null : listUrl,
  };
}

export function jobTitle(
  action: Pick<ActionRecord, "name" | "action">,
  nodeName: string,
): string {
  const titles: Partial<Record<ActionRecord["action"], string>> = {
    upgrade: `Upgrading packages on ${nodeName}`,
    install: `Installing ${action.name} on ${nodeName}`,
    remove: `Removing ${action.name} from ${nodeName}`,
    purge: `Removing ${action.name} from ${nodeName}`,
    refresh: `Checking for updates on ${nodeName}`,
    addrepo: `Adding the ${action.name} repository on ${nodeName}`,
    droprepo: `Removing the ${action.name} repository from ${nodeName}`,
    signin: `Signing ${nodeName} in to Tailscale`,
  };
  return titles[action.action] ?? nodeName;
}

export function runningJob(
  action: Pick<
    ActionRecord,
    "kind" | "name" | "action" | "sentAt" | "requestedAt" | "progress"
  >,
  nodeName: string,
  now: number,
): { title: string; step: string | null } {
  const since = parseTimestamp(action.sentAt ?? action.requestedAt);
  const step = action.progress;
  return {
    title: `${jobTitle(action, nodeName)} · ${tookText((now - since) / 1000)}`,
    step: step
      ? step.total > 0
        ? `${step.done} of ${step.total} · ${step.line}`
        : step.line
      : null,
  };
}

export function packageText(
  action: Pick<ActionRecord, "kind" | "name" | "action" | "output">,
  nodeName?: string,
): string | null {
  if (action.kind === "host" && action.action === "signin") {
    return `Sign in ${nodeName ?? "the server"} to Tailscale`;
  }
  if (action.kind !== "apt") return null;
  const name = action.name;
  switch (action.action) {
    case "install":
      return `Install ${name}`;
    case "upgrade": {
      const outcome = outcomeOf(action);
      const moved = outcome
        ? outcome.upgraded.length + outcome.added.length
        : 0;
      return moved > 0
        ? `Upgrade ${count(moved, "package")}`
        : "Upgrade packages";
    }
    case "hold": {
      const version = action.output?.split(" ")[2];
      return version ? `Hold ${name} at ${version}` : `Hold ${name}`;
    }
    case "unhold":
      return `Release the hold on ${name}`;
    case "addrepo":
      return `Add the ${name} repository`;
    case "droprepo":
      return `Remove the ${name} repository`;
    case "remove":
      return `Remove ${name}`;
    case "purge":
      return `Remove ${name} with its settings`;
    case "refresh":
      return "Check for updates";
    case "find":
      return `Search for ${name}`;
    case "preview":
      return `Try ${name}`;
    default:
      return null;
  }
}

export const namesServer = (action: Pick<ActionRecord, "kind" | "action">) =>
  action.kind === "host" && action.action === "signin";

export const repoName = (file: string) =>
  (file.split("/").at(-1) ?? file).replace(/\.(?:sources|list)$/u, "");

const QUESTION = new Set<ActionRecord["action"]>(["find", "preview"]);

export const runningPackages = (actions: ActionRecord[], nodeId: string) =>
  actions.filter(
    (action) =>
      action.nodeId === nodeId &&
      isPending(action) &&
      (action.kind === "apt" || namesServer(action)) &&
      !QUESTION.has(action.action),
  );

export type PackageChoice = "hold" | "unhold" | "remove";

export function packageMenu(entry: AptReport["packages"][number]): {
  note: string | null;
  items: PackageChoice[];
} {
  const hold: PackageChoice = entry.held ? "unhold" : "hold";
  if (entry.feature) {
    return {
      note:
        entry.feature === "docker"
          ? "Krynodes installed it for Docker"
          : entry.feature === "network"
            ? "Krynodes installed it for the private network; it goes when the server leaves"
            : `Turn off ${RECIPE_TITLES[entry.feature] ?? entry.feature} to remove it`,
      items: [hold],
    };
  }
  return {
    note: null,
    items: entry.name === "openssh-server" ? [hold] : [hold, "remove"],
  };
}

export function packageCommands(
  nodes: Pick<NodeRecord, "id" | "name" | "updates">[],
  servers: { nodeId: string; names: string[] }[],
  search: string,
): { key: string; value: string; label: string; to: string }[] {
  const term = search.trim().toLowerCase();
  const pages = nodes
    .filter((node) => node.updates)
    .map((node) => ({
      key: `packages|${node.id}`,
      value: `packages updates apt ${node.name}`,
      label: `Packages · ${node.name}`,
      to: `/nodes/${node.id}/packages`,
    }));
  if (term.length < 2) return pages;
  const names = new Map(nodes.map((node) => [node.id, node.name]));
  const found = servers.flatMap((server) => {
    const nodeName = names.get(server.nodeId);
    if (nodeName === undefined) return [];
    return server.names
      .filter((name) => name.includes(term))
      .map((name) => ({
        key: `package|${server.nodeId}|${name}`,
        value: `package ${name} ${nodeName}`,
        label: `${name} · ${nodeName}`,
        to: `/nodes/${server.nodeId}/packages?q=${encodeURIComponent(name)}&show=all`,
      }));
  });
  return [...pages, ...found.slice(0, 20)];
}
