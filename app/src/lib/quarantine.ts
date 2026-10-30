import {
  codeOf,
  QUARANTINE,
  releaseText,
  type PendingRelease,
  type QuarantineSettings,
} from "@krynodes/protocol";

import type {
  ActionRecord,
  NodeRecord,
  NodeWarning,
  QuarantineRecord,
  QuarantineStep,
  QuarantineView,
  StoppedStack,
} from "../types";
import { systemName } from "./confine";
import { parseTimestamp, shortDate, stampTime } from "./format";
import { planRemoval, type VaultName, type VaultNode } from "./vault";

export const REPORTED = "Reported by the server itself, may not be true";

export const QUARANTINE_INTRO =
  "What Krynodes does on its own when a server looks broken into. It only ever takes access away; giving it back always asks for your passkey.";

const QUARANTINED_REASON = "Quarantined · release it from the server";

const SECONDS = new Intl.DateTimeFormat("en-GB", {
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hourCycle: "h23",
});

function secondTime(value: string, now: number): string {
  const at = parseTimestamp(value);
  const time = SECONDS.format(at);
  return new Date(at).toDateString() === new Date(now).toDateString()
    ? time
    : `${shortDate(at)} ${time}`;
}

const listOf = (names: string[]) =>
  names.length < 2
    ? names.join("")
    : `${names.slice(0, -1).join(", ")} and ${names.at(-1)}`;

const places = (count: number) => `${count} place${count === 1 ? "" : "s"}`;

function warningWords(warning: NodeWarning, now: number) {
  const value = (key: string) => warning.detail[key] || "--";
  switch (warning.kind) {
    case "ssh-key":
      return {
        title: `New SSH key for ${value("user")}, not added through Krynodes`,
        detail: value("key"),
      };
    case "ssh-login":
      return {
        title: `${value("user")} signed in with a key not from Krynodes`,
        detail: `${value("key")} · from ${value("from")}`,
      };
    case "user":
      return {
        title: `New user ${value("user")}, not added through Krynodes`,
        detail: null,
      };
    case "sudo":
      return {
        title: "New sudo rule, not added through Krynodes",
        detail: value("rule"),
      };
    case "port":
      return {
        title: value("port").includes("-")
          ? `Temporary UDP ports ${value("port").replace(/\/udp$/u, "")} on a public address, not through Krynodes`
          : `${value("port")} opened on a public address, not through Krynodes`,
        detail: `Process ${value("process")}`,
      };
    case "firewall":
      return {
        title: "Firewall rule added, not through Krynodes",
        detail: value("rule"),
      };
    case "confinement":
      return {
        title: `${systemName(warning.detail.system === "apparmor" ? "apparmor" : "selinux")} denied ${value("program")}`,
        detail: `${value("type")} · ${value("wanted")}`,
      };
    case "rule":
      return {
        title: "Krynodes' firewall rule was removed, and put back",
        detail: `${value("chain")} · ${value("rule")}`,
      };
    default:
      return {
        title: "The agent went quiet while the server is up",
        detail: `Last report ${warning.detail.lastReport ? stampTime(warning.detail.lastReport, now) : "--"} · seen by ${value("seenBy")}`,
      };
  }
}

export function warningStrip(
  warning: NodeWarning,
  nodeName: string,
  now: number,
): { title: string; detail: string | null; cutoff: string } {
  const { title, detail } = warningWords(warning, now);
  const cutoff =
    warning.cutAt === null
      ? `Warn Only is set, so ${nodeName} stays on the network until you cut it off.`
      : parseTimestamp(warning.cutAt) > now
        ? `${nodeName} is cut off from the network at ${stampTime(warning.cutAt, now)} unless you say it was you.`
        : `${nodeName} is being cut off from the network.`;
  return {
    title: `${title} · ${stampTime(warning.at, now)}`,
    detail,
    cutoff,
  };
}

const ACCEPTS = [
  "ssh-key",
  "ssh-login",
  "user",
  "sudo",
  "port",
  "firewall",
  "confinement",
];

export const acceptsWarning = (kind: string) => ACCEPTS.includes(kind);

export const planWithout = (
  nodes: VaultNode[],
  suspect: string,
  setId: string | null,
  addresses = false,
  name: VaultName = "cloudflare",
) =>
  planRemoval(
    nodes.map((node) =>
      node.id === suspect ? { ...node, reachable: false, online: false } : node,
    ),
    suspect,
    setId,
    addresses,
    name,
    true,
  );

export function quarantineReasons(
  node: Pick<NodeRecord, "quarantine" | "warnings">,
  now: number,
): { quarantined: boolean; reasons: string[] } {
  if (node.quarantine)
    return { quarantined: true, reasons: [QUARANTINED_REASON] };
  const first = node.warnings?.[0];
  return {
    quarantined: false,
    reasons: first ? [warningStrip(first, "", now).title] : [],
  };
}

export function quarantineCard(
  quarantine: { at: string; why: string },
  nodeName: string,
  tailnet: string[],
  now: number,
) {
  return {
    chip: "Quarantined",
    title: `Cut off from the network at ${stampTime(quarantine.at, now)} · ${quarantine.why}`,
    body: `Every other server dropped ${nodeName} and blocks its WireGuard key${tailnet.length > 0 ? " and its Tailscale address" : ""} for good. Krynodes sends it nothing and refuses every action except reading.`,
    next: "Really broken into? Reinstall it and enroll it again. A false alarm? Release it from the server itself.",
  };
}

const COUNTED = ["", "one", "two", "three", "four", "five"];

const waiting = (step: QuarantineStep) =>
  step.status === "queued" || step.status === "sent";

const mark = (step: QuarantineStep) =>
  step.status === "done" ? "✓" : waiting(step) ? "…" : "✕";

export function whatHappened(
  record: QuarantineRecord,
  now: number,
  nodeName = "it",
  devices: { id: string; name: string }[] = [],
): { time: string; lead: string | null; text: string }[] {
  const where = record.address ?? "it";
  const lines: { at: string; lead: string | null; text: string }[] =
    record.knocks.map((knock) => ({
      at: knock.at,
      lead: null,
      text: `${knock.reporter} saw ${where} knock on ${knock.count} closed ports`,
    }));
  lines.push({
    at: record.at,
    lead: "Quarantined",
    text:
      record.knocks.length >= 2
        ? `${COUNTED[record.knocks.length] ?? record.knocks.length} servers agree`
        : record.why.replace(/^(Nobody|You|Reported) /u, (word) =>
            word.toLowerCase(),
          ),
  });
  const groups = new Map<string, QuarantineStep[]>();
  for (const step of record.steps) {
    groups.set(step.action, [...(groups.get(step.action) ?? []), step]);
  }
  for (const [action, steps] of groups) {
    const finished = steps
      .map((step) => step.finishedAt)
      .filter((at): at is string => at !== null)
      .sort();
    const at = finished.at(-1) ?? record.at;
    if (action === "lockdown") {
      const step = steps[0]!;
      lines.push({
        at,
        lead: null,
        text: `Lock Down on ${step.nodeName} ${
          step.status === "done"
            ? "✓ reported by the server itself"
            : waiting(step)
              ? "· waiting for it to report"
              : "✕ failed"
        }`,
      });
    } else if (action === "drop") {
      lines.push({
        at,
        lead: null,
        text: steps
          .map((step) =>
            step.status === "done"
              ? `${step.nodeName} ✓ dropped it`
              : waiting(step)
                ? `${step.nodeName} drops it when it reports`
                : `${step.nodeName} ✕ did not drop it`,
          )
          .join(" · "),
      });
    } else if (action === "block") {
      lines.push({
        at,
        lead: null,
        text: `Blocked ${record.tailnet[0] ?? "--"} on Tailscale · ${steps
          .map((step) => `${step.nodeName} ${mark(step)}`)
          .join(" ")}`,
      });
    }
  }
  if (record.removed) {
    const by = devices.find((device) => device.id === record.removed!.by);
    lines.push({
      at: record.removed.at,
      lead: null,
      text: `Removed ${nodeName} from your tailnet · ${by?.name ?? "--"}`,
    });
  }
  return lines
    .map((line, index) => ({ line, index }))
    .sort(
      (a, b) =>
        parseTimestamp(a.line.at) - parseTimestamp(b.line.at) ||
        a.index - b.index,
    )
    .map(({ line }) => ({
      time: secondTime(line.at, now),
      lead: line.lead,
      text: line.text,
    }));
}

type ChangeAction =
  | { kind: "reshare"; label: "Reshare Without It" }
  | { kind: "unexpose"; label: "Remove Web Addresses" }
  | { kind: "remove"; label: "Remove from Tailnet" }
  | { kind: "console"; label: "Admin Console ↗" };

export interface ChangeRow {
  id: string;
  title: string;
  tag: string | null;
  note: string | null;
  action: ChangeAction | null;
}

const RESHARE_NOTE =
  "One piece alone opens nothing. Reshare so the old piece is worthless.";

export function changeThese(
  view: QuarantineView,
  nodeName: string,
  connected = false,
): { title: string; rows: ChangeRow[] } {
  const { stacks, vault, tailscaleVault, webAddresses, trusted } =
    view.changeThese;
  const tailnet = view.quarantine?.removed
    ? []
    : (view.quarantine?.tailnet ?? []);
  const rows: ChangeRow[] = [
    ...(stacks.length > 0
      ? [
          {
            id: "stacks",
            title: `Secrets of ${listOf(stacks)}`,
            tag: null,
            note: `Secrets sent to stacks on ${nodeName}. Each compose file names them.`,
            action: null,
          },
        ]
      : []),
    ...trusted.map((entry) => ({
      id: `trusted:${entry.nodeId}:${entry.project}:${entry.port}`,
      title: `${entry.nodeName} · ${entry.port}`,
      tag: entry.project,
      note: `Trusted ${nodeName}. Change the password ${nodeName} used to sign in.`,
      action: null,
    })),
    ...(vault && vault.holders > 0
      ? [
          {
            id: "vault",
            title: "Cloudflare token",
            tag: `${nodeName} held 1 of ${vault.holders} pieces`,
            note: RESHARE_NOTE,
            action: { kind: "reshare", label: "Reshare Without It" } as const,
          },
        ]
      : []),
    ...(webAddresses.length > 0
      ? [
          {
            id: "web",
            title: webAddresses.map((entry) => entry.hostname).join(", "),
            tag: null,
            note: `Still points at ${nodeName}'s tunnel`,
            action: {
              kind: "unexpose",
              label: "Remove Web Addresses",
            } as const,
          },
        ]
      : []),
    ...(tailnet.length > 0
      ? [
          {
            id: "tailnet",
            title: "Tailscale",
            tag: `${nodeName} is on your tailnet as ${tailnet[0]}`,
            note: connected
              ? "Your servers block it already, and your rules never let a server reach your devices. Remove it, so its Tailscale key opens nothing at all."
              : "Your servers block it already. Remove it in Tailscale's admin console, so its Tailscale key opens nothing anywhere else on your tailnet.",
            action: connected
              ? ({ kind: "remove", label: "Remove from Tailnet" } as const)
              : ({ kind: "console", label: "Admin Console ↗" } as const),
          },
        ]
      : []),
    ...(tailscaleVault && tailscaleVault.holders > 0
      ? [
          {
            id: "tailscale-vault",
            title: "Tailscale credential",
            tag: `${nodeName} held 1 of ${tailscaleVault.holders} pieces`,
            note: RESHARE_NOTE,
            action: { kind: "reshare", label: "Reshare Without It" } as const,
          },
        ]
      : []),
  ];
  return {
    title: `Change These · ${nodeName} could read or reach them`,
    rows:
      rows.length > 0
        ? rows
        : [
            {
              id: "none",
              title: "Nothing Krynodes knows of",
              tag: null,
              note: null,
              action: null,
            },
          ],
  };
}

export const TAILSCALE_CONSOLE = "https://login.tailscale.com/admin/machines";

export const tailnetRemoved = (record: QuarantineRecord, now: number) =>
  record.removed
    ? {
        title: "Removed from your tailnet",
        detail: `${stampTime(record.removed.at, now)} · Sign it in again after Release`,
      }
    : null;

export function tailnetBlock(
  record: QuarantineRecord | null | undefined,
  nodeName: string,
) {
  const nodeIds = [
    ...new Set(
      (record?.steps ?? [])
        .filter((step) => step.action === "block")
        .map((step) => step.nodeId),
    ),
  ];
  if (!record || nodeIds.length === 0 || record.tailnet.length === 0) {
    return null;
  }
  return {
    nodeIds,
    addresses: record.tailnet.join(" "),
    text: `Your servers stop blocking ${record.tailnet[0]} once ${nodeName} is deleted. Remove it from your tailnet first.`,
    console: TAILSCALE_CONSOLE,
  };
}

const RESHARE_VERBS = ["release", "reshare", "store"];

export const resharing = (actions: ActionRecord[]) =>
  actions.some(
    (action) =>
      action.kind === "vault" &&
      RESHARE_VERBS.includes(action.action) &&
      (action.status === "queued" || action.status === "sent"),
  );

export function releaseInputs(
  record: QuarantineRecord,
  release: PendingRelease,
  nodeId: string,
  nodeName: string,
  reported: { locked: boolean; sealKeys: Record<string, string> },
) {
  const block = tailnetBlock(record, nodeName);
  return {
    blocked: block?.nodeIds ?? [],
    addresses: block?.addresses ?? "",
    unlock:
      reported.locked ||
      record.steps.some(
        (step) =>
          step.action === "lockdown" &&
          step.nodeId === nodeId &&
          step.status === "done",
      ),
    sealKeys: { ...reported.sealKeys, [nodeId]: release.seal },
  };
}

const QUARANTINE_ACTIONS = [
  "Refresh Services",
  "Release Server",
  "Remove from Network",
  "Delete Node",
] as const;

export function actionsFor(
  node: Pick<NodeRecord, "quarantine" | "network">,
): (typeof QUARANTINE_ACTIONS)[number][] | null {
  if (!node.quarantine) return null;
  return QUARANTINE_ACTIONS.filter(
    (action) =>
      action !== "Remove from Network" || node.network?.state === "in",
  );
}

export function releaseSteps(nodeName: string) {
  return {
    title: `Release ${nodeName}`,
    intro: `This trusts ${nodeName} again. The code shows you were on the server; it does not show the server is clean.`,
    run: `On ${nodeName}, run`,
    command: "sudo kry release-code",
    type: "Type the code it shows",
    lasts: `works for ${QUARANTINE.codeMinutes} minutes`,
    keys: `${nodeName} makes new keys: WireGuard, sealing and its sign-in to Krynodes. The old ones stay blocked, and secrets are sealed to the new ones.`,
  };
}

export async function releaseCode(release: PendingRelease): Promise<string> {
  return codeOf(
    new Uint8Array(
      await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(releaseText(release)),
      ),
    ),
  );
}

export async function releaseCodeProblem(
  typed: string,
  release: PendingRelease | null,
  nodeName: string,
  now: number,
): Promise<{ code: string; problem: string | null }> {
  const bare = typed.toUpperCase().replace(/[^A-Z2-7]/gu, "");
  const code = `${bare.slice(0, 5)}-${bare.slice(5)}`;
  if (bare.length !== 10) {
    return {
      code,
      problem: "The code has ten letters and digits, such as 7K43Q-MZ2PA.",
    };
  }
  if (!release) {
    return {
      code,
      problem: `Run sudo kry release-code on ${nodeName} first.`,
    };
  }
  if (parseTimestamp(release.expires) <= now) {
    return {
      code,
      problem: `That code has ended. Run sudo kry release-code on ${nodeName} again.`,
    };
  }
  return {
    code,
    problem:
      (await releaseCode(release)) === code
        ? null
        : `That is not the code ${nodeName} showed. Type it again.`,
  };
}

export function stoppedRow(
  stack: StoppedStack,
  nodeName: string,
  names: Record<string, string>,
  now: number,
) {
  const count = Math.max(stack.count, stack.tried.length);
  const shown = stack.tried.map((place) => {
    const [address = "", rest = ""] = place.split(/:(.*)/su);
    return `${names[address] ?? address}:${rest}`;
  });
  const denied = stack.why === "confinement";
  return {
    title: denied
      ? `Stopped by Krynodes at ${stampTime(stack.at, now)}: SELinux or AppArmor denied one of its containers`
      : `Stopped by Krynodes at ${stampTime(stack.at, now)}: a container tried ${count > 0 ? places(count) : "-- places"} it was not given`,
    places:
      shown.length === 0
        ? "--"
        : denied
          ? stack.tried.join(", ")
          : `${shown.join(", ")}${count > shown.length ? " …" : ""}`,
    note: `${nodeName} is still trusted. Only this stack was stopped, and it stays stopped after a reboot. Change its secrets before you start it again.`,
  };
}

type SettingKey = keyof QuarantineSettings;

interface SettingRow<K extends SettingKey> {
  key: K;
  title: string;
  note: string;
  later: string | null;
  choices: { value: QuarantineSettings[K]; label: string }[];
}

export function settingsRows(
  member: boolean,
): [
  SettingRow<"cutoff">,
  SettingRow<"scan">,
  SettingRow<"agree">,
  SettingRow<"stop">,
] {
  const later = member ? null : "Applies once servers share a network.";
  return [
    {
      key: "cutoff",
      title: "Cut off after a warning",
      note: "New SSH keys, users or sudo rules, ports opened outside Krynodes, an agent that goes quiet while the server is up",
      later: null,
      choices: QUARANTINE.cutoff.map((value) => ({
        value,
        label: value === null ? "Warn Only" : `After ${value} Minutes`,
      })),
    },
    {
      key: "scan",
      title: "Counts as a Scan",
      note: "Closed ports or servers knocked on in one minute. One wrong port knocked again and again is a setting mistake, and only sends a warning.",
      later,
      choices: QUARANTINE.scan.map((value) => ({
        value,
        label: `${value} or More`,
      })),
    },
    {
      key: "agree",
      title: "Cut off from every server",
      note: "A server that is knocked on always drops the knocker for itself",
      later,
      choices: QUARANTINE.agree.map((value) => ({
        value,
        label:
          value === 1 ? "When 1 Server Sees It" : `When ${value} Servers Agree`,
      })),
    },
    {
      key: "stop",
      title: "Stop a stack that knocks",
      note: "A Contained container that tries places it was not given",
      later,
      choices: [
        { value: true, label: "At Once" },
        { value: false, label: "Warn Only" },
      ],
    },
  ];
}

export function fleetQuarantine(
  node: Pick<NodeRecord, "quarantine">,
  now: number,
) {
  if (!node.quarantine) return null;
  return {
    chip: `Quarantined · ${stampTime(node.quarantine.at, now)}`,
    attention: QUARANTINED_REASON,
    meters: "Reported by the Server Itself",
    footer: "Checks Not Trusted",
  };
}

const ACTION_TEXT: Record<string, string> = {
  "network:drop": "Drop a quarantined server",
  "network:tighten": "Count scans more strictly",
  "host:tailscale:block": "Block a quarantined server on Tailscale",
  "host:tailscale:unblock": "Stop blocking a released server on Tailscale",
  "host:server:accept": "Accept a change as yours",
  "host:server:release": "Release the server with new keys",
};

export const quarantineActionText = (
  action: Pick<ActionRecord, "kind" | "name" | "action">,
): string | null =>
  ACTION_TEXT[`${action.kind}:${action.action}`] ??
  ACTION_TEXT[`${action.kind}:${action.name}:${action.action}`] ??
  null;
