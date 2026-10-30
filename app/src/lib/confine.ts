import { SECURITY_AGENT } from "@krynodes/protocol/versions";

import type { ActionRecord, Confinement, DenialsView } from "../types";

export type ConfineStep =
  "denials" | "manage" | "on" | "containers" | "uncontain" | "undo";

export const systemName = (system: Confinement["system"] | undefined) =>
  system === "selinux"
    ? "SELinux"
    : system === "apparmor"
      ? "AppArmor"
      : "SELinux or AppArmor";

const count = (value: number | null) => (value === null ? "--" : value);

function modeText(found: Confinement): string {
  if (found.system === "selinux") {
    return found.mode === "enforcing"
      ? "Enforcing"
      : found.mode === "permissive"
        ? "Permissive"
        : found.mode === "disabled"
          ? "Off"
          : "--";
  }
  if (found.mode === "on") {
    return found.complain
      ? `On · ${count(found.enforced)} enforced, ${found.complain} in complain`
      : `On · ${count(found.enforced)} ${found.enforced === 1 ? "profile" : "profiles"} enforced`;
  }
  if (found.mode === "kernel-off" && !found.restart) {
    return "Off · needs a restart";
  }
  return found.mode === "off" || found.mode === "kernel-off" ? "Off" : "--";
}

export function confinementRow(found: Confinement | undefined): {
  title: string;
  text: string;
  actions: ConfineStep[];
} {
  if (!found) {
    return {
      title: systemName(null),
      text: `Needs agent ${SECURITY_AGENT} or newer`,
      actions: [],
    };
  }
  if (!found.system) {
    return { title: systemName(null), text: "Not available", actions: [] };
  }
  const text = [
    modeText(found),
    found.restart && "restart to finish",
    found.managed && "managed by Krynodes",
  ]
    .filter(Boolean)
    .join(" · ");
  const selinux = found.system === "selinux";
  const actions: ConfineStep[] = found.managed
    ? [
        "denials",
        ...(selinux && found.docker === false ? ["containers" as const] : []),
        ...(selinux && found.docker === true ? ["uncontain" as const] : []),
        "undo",
      ]
    : [
        "denials",
        (selinux && found.mode === "enforcing") ||
        (!selinux && found.mode === "on" && !found.complain)
          ? "manage"
          : "on",
      ];
  return { title: systemName(found.system), text, actions };
}

export function confinementNote(found: Confinement | undefined): string | null {
  if (found?.system === "selinux") {
    return found.mode === "permissive"
      ? "SELinux is permissive"
      : found.mode === "disabled"
        ? "SELinux is off"
        : null;
  }
  return found?.system === "apparmor" &&
    (found.mode === "off" || found.mode === "kernel-off")
    ? "AppArmor is off"
    : null;
}

const listed = (names: string[]) => new Intl.ListFormat("en").format(names);

function denialsSoFar(denials: DenialsView, name: string): string {
  if (denials.count === null) return "Denials in the last 24 hours: --";
  if (denials.count === 0) return "No denials in the last 24 hours.";
  return `${denials.count} ${denials.count === 1 ? "denial" : "denials"} in the last 24 hours. What was denied stops working once ${name} enforces.`;
}

function turnOnLines(found: Confinement): { first: string; undo: string } {
  const labels =
    "Krynodes first labels the SSH port and the home folders of users who log in with a key, so SSH keeps working.";
  if (found.system === "selinux") {
    return {
      first:
        found.mode === "disabled"
          ? `SELinux is set to enforcing and finishes when you restart the server. The first boot labels every file and restarts once more. ${labels}`
          : `SELinux starts enforcing now. ${labels}`,
      undo: "Undo is one click and stops SELinux enforcing.",
    };
  }
  if (found.mode === "on" && found.complain) {
    return {
      first: `The ${found.complain} profiles in complain mode start enforcing now.`,
      undo: "Undo is one click and puts them back in complain mode.",
    };
  }
  return {
    first:
      found.mode === "kernel-off"
        ? "AppArmor is off when the server boots. Krynodes turns it on in the boot settings, and it starts when you restart the server."
        : "Krynodes installs AppArmor if it is missing and turns it on now.",
    undo: "Undo is one click and stops Krynodes managing it; AppArmor stays on.",
  };
}

export function confineText(
  step: Exclude<ConfineStep, "denials">,
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
        lines: [
          `${name} stays as it is.`,
          acting,
          ...unconfined,
          "Undo is one click and only stops Krynodes managing it.",
        ],
      };
    case "on": {
      const { first, undo } = turnOnLines(found);
      return {
        title: `Turn on ${name} on ${nodeName}?`,
        button: "Turn On",
        destructive: false,
        lines: [
          first,
          acting,
          denialsSoFar(denials, name),
          ...unconfined,
          undo,
        ],
      };
    }
    case "undo":
      return {
        title: `Undo ${name} on ${nodeName}?`,
        button: "Undo",
        destructive: true,
        lines: [
          found.system === "selinux"
            ? "SELinux goes back to how Krynodes found it: permissive if it was permissive or off, enforcing if it already was. Krynodes stops acting on its denials."
            : "Profiles Krynodes moved to enforce go back to complain mode; AppArmor stays on. Krynodes stops acting on its denials.",
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
};

export const confinementActionText = (
  action: Pick<ActionRecord, "kind" | "name" | "action">,
) =>
  action.kind === "host" && action.name === "confinement"
    ? (ACTION_TEXT[action.action] ?? null)
    : null;
