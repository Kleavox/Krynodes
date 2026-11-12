import { SELINUX_BOOLEAN } from "@krynodes/protocol";
import { SECURITY_AGENT } from "@krynodes/protocol/versions";

import type { ActionRecord, Confinement, DenialsView } from "../types";

import type { CommandTarget } from "./passkeys";

export type ConfineStep =
  "denials" | "manage" | "on" | "containers" | "uncontain" | "boolean";

export const systemName = (system: Confinement["system"] | undefined) =>
  system === "selinux"
    ? "SELinux"
    : system === "apparmor"
      ? "AppArmor"
      : "SELinux or AppArmor";

const count = (value: number | null) => (value === null ? "--" : value);

function modeText(found: Confinement): [string, string?] {
  if (found.mode === "kernel-off") {
    return found.restart ? ["Off"] : ["Off", "Needs a restart"];
  }
  if (found.system === "selinux") {
    return [
      found.mode === "enforcing"
        ? "Enforcing"
        : found.mode === "permissive"
          ? "Permissive"
          : found.mode === "disabled"
            ? "Off"
            : "--",
    ];
  }
  if (found.mode === "on") {
    return [
      "On",
      found.complain
        ? `${count(found.enforced)} enforced, ${found.complain} in complain`
        : `${count(found.enforced)} ${found.enforced === 1 ? "profile" : "profiles"} enforced`,
    ];
  }
  return [found.mode === "off" ? "Off" : "--"];
}

export function confinementRow(
  found: Confinement | undefined,
  booleans = false,
): {
  title: string;
  status: string;
  line: string | null;
  actions: ConfineStep[];
} {
  if (!found) {
    return {
      title: systemName(null),
      status: `Needs agent ${SECURITY_AGENT} or newer`,
      line: null,
      actions: [],
    };
  }
  if (!found.system) {
    return {
      title: systemName(null),
      status: "Not available",
      line: null,
      actions: [],
    };
  }
  const [status, detail] = modeText(found);
  const line =
    [
      detail,
      found.restart && "Restart to finish",
      found.managed && "Managed by Krynodes",
    ]
      .filter(Boolean)
      .join(" · ") || null;
  const selinux = found.system === "selinux";
  const running = selinux && found.mode === "enforcing" && !found.restart;
  const actions: ConfineStep[] = found.managed
    ? [
        "denials",
        ...(running && found.docker === false ? ["containers" as const] : []),
        ...(running && found.docker === true ? ["uncontain" as const] : []),
        ...(running && booleans ? ["boolean" as const] : []),
      ]
    : [
        "denials",
        (selinux && found.mode === "enforcing") ||
        (!selinux && found.mode === "on" && !found.complain)
          ? "manage"
          : "on",
      ];
  return { title: systemName(found.system), status, line, actions };
}

const listed = (names: string[]) => new Intl.ListFormat("en").format(names);

function denialsSoFar(denials: DenialsView, name: string): string {
  if (denials.count === null) return "Denials in the last 24 hours: --";
  if (denials.count === 0) return "No denials in the last 24 hours.";
  return `${denials.count} ${denials.count === 1 ? "denial" : "denials"} in the last 24 hours. What was denied stops working once ${name} enforces.`;
}

function turnOnLine(found: Confinement): string {
  const labels =
    "Krynodes first labels the SSH port and the SSH keys of users who log in with a key, so SSH keeps working.";
  if (found.system === "selinux") {
    const relabel = `The first boot labels every file and restarts once more. ${labels}`;
    return found.mode === "kernel-off"
      ? `SELinux is off when the server boots. Krynodes turns it on in the boot settings and sets it to enforcing, and it finishes when you restart the server. ${relabel}`
      : found.mode === "disabled"
        ? `SELinux is set to enforcing and finishes when you restart the server. ${relabel}`
        : `SELinux starts enforcing now. ${labels}`;
  }
  if (found.mode === "on" && found.complain) {
    return `The ${found.complain} profiles in complain mode start enforcing now.`;
  }
  return found.mode === "kernel-off"
    ? "AppArmor is off when the server boots. Krynodes turns it on in the boot settings, and it starts when you restart the server."
    : "Krynodes installs AppArmor if it is missing and turns it on now.";
}

const STAYS = "It stays on: Krynodes needs it on every server.";

export function confineText(
  step: Exclude<ConfineStep, "denials" | "boolean">,
  found: Confinement,
  nodeName: string,
  denials: DenialsView,
  stacks: string[],
): { title: string; button: string; destructive: boolean; lines: string[] } {
  const name = systemName(found.system);
  const acting = `From then on a denied container stops its stack, and ${name} switched off outside Krynodes quarantines the server.`;
  const unconfined =
    found.system === "selinux" && found.docker === false
      ? [
          "Containers are not confined until you choose Confine Containers on this row.",
        ]
      : [];
  const restarting = stacks.length === 0 ? null : listed(stacks);
  switch (step) {
    case "manage":
      return {
        title: `Let Krynodes manage ${name} on ${nodeName}?`,
        button: "Let Krynodes Manage",
        destructive: false,
        lines: [`${name} stays as it is.`, acting, ...unconfined, STAYS],
      };
    case "on":
      return {
        title: `Turn on ${name} on ${nodeName}?`,
        button: "Turn On",
        destructive: false,
        lines: [
          turnOnLine(found),
          acting,
          denialsSoFar(denials, name),
          ...unconfined,
          STAYS,
        ],
      };
    case "containers":
      return {
        title: `Confine containers on ${nodeName}?`,
        button: "Confine Containers",
        destructive: false,
        lines: [
          restarting
            ? `Docker restarts with SELinux on, and every stack starts again with its own label: ${restarting}.`
            : "Docker restarts with SELinux on. No stacks run on this server.",
          "Undo is one click: Stop Confining Containers restarts Docker without it.",
        ],
      };
    case "uncontain":
      return {
        title: `Stop confining containers on ${nodeName}?`,
        button: "Stop Confining",
        destructive: true,
        lines: [
          restarting
            ? `Docker restarts without SELinux, and every stack starts again unconfined: ${restarting}.`
            : "Docker restarts without SELinux. No stacks run on this server.",
        ],
      };
  }
}

export const BOOLEAN_LINE =
  "Krynodes sets it for good and marks the change first, so it does not quarantine the server.";

export const booleanProblem = (name: string) =>
  name === "" || SELINUX_BOOLEAN.test(name)
    ? null
    : "A boolean is lowercase letters, digits and _, like httpd_can_network_connect.";

export const booleanTarget = (
  nodeId: string,
  name: string,
  on: boolean,
): CommandTarget => ({
  nodeId,
  kind: "host",
  name: "confinement",
  args: { name, on: on ? "1" : "0" },
});

export function denialLines(denials: DenialsView) {
  return {
    summary: `${denials.count === null ? "--" : denials.count === 0 ? "None" : denials.count} in the last 24 hours`,
    rows: denials.lines.map((line) => ({ ...line, stack: line.stack ?? "--" })),
  };
}

const ACTION_TEXT: Partial<Record<ActionRecord["action"], string>> = {
  apply: "Turn on SELinux or AppArmor",
  undo: "Undo SELinux or AppArmor",
  containers: "Change whether SELinux confines containers",
  boolean: "Change an SELinux boolean",
};

export const confinementActionText = (
  action: Pick<ActionRecord, "kind" | "name" | "action">,
) =>
  action.kind === "host" && action.name === "confinement"
    ? (ACTION_TEXT[action.action] ?? null)
    : null;
