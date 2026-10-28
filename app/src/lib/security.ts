import type { Finding, SecurityReport } from "../types";

import { RECIPE_TITLES } from "./services";

export interface RecipeChoice {
  id: string;
  title: string;
  applied: boolean;
  outside: boolean;
  blocked: string | null;
  hint: string | null;
}

const HINTS: Record<string, string> = {
  "free-port-53": "Only for a DNS server such as AdGuard.",
};

const HIDDEN = new Set(["dns-stub"]);

const SEVERITY_ORDER = { serious: 0, warning: 1, note: 2 };

export const shownFindings = (report: SecurityReport) =>
  report.findings
    .filter((finding) => !HIDDEN.has(finding.id))
    .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

const OFF_FINDING: Record<string, string> = {
  "security-updates": "updates-off",
  fail2ban: "fail2ban-off",
  firewall: "firewall-off",
  "no-root-login": "root-login",
};

export const findingTone = (finding: Finding) =>
  finding.id === "ssh-keys"
    ? "ok"
    : finding.severity === "serious"
      ? "bad"
      : finding.severity === "warning"
        ? "warn"
        : "idle";

const ORDER = [
  "security-updates",
  "reboot-window",
  "ssh-keys-only",
  "no-root-login",
  "fail2ban",
  "firewall",
  "free-port-53",
];

const RECOMMENDED = [
  "security-updates",
  "reboot-window",
  "ssh-keys-only",
  "fail2ban",
  "firewall",
];

const has = (report: SecurityReport, id: string) =>
  report.findings.some((finding) => finding.id === id);

const keyedUsers = (report: SecurityReport) =>
  report.findings
    .find((finding) => finding.id === "ssh-keys")
    ?.detail.replace(/^SSH keys for /u, "")
    .split(", ");

function blockedText(id: string, report: SecurityReport): string | null {
  if (id === "ssh-keys-only" && has(report, "ssh-no-keys")) {
    return "First let root or a sudo user log in over SSH with a key.";
  }
  if (
    id === "no-root-login" &&
    !(keyedUsers(report) ?? []).some((user) => user !== "root")
  ) {
    return "First let a sudo user other than root log in over SSH with a key.";
  }
  return null;
}

export function worst(
  report: SecurityReport | null | undefined,
): "serious" | "warning" | "ok" | null {
  if (!report) return null;
  if (report.findings.some((finding) => finding.severity === "serious")) {
    return "serious";
  }
  if (report.findings.some((finding) => finding.severity === "warning")) {
    return "warning";
  }
  return "ok";
}

export function recipeChoices(report: SecurityReport): RecipeChoice[] {
  return ORDER.filter(
    (id) =>
      id !== "free-port-53" ||
      has(report, "dns-stub") ||
      report.recipes.includes(id),
  ).map((id) => {
    const applied = report.recipes.includes(id);
    const off = OFF_FINDING[id];
    return {
      id,
      title: RECIPE_TITLES[id] ?? id,
      applied,
      outside:
        !applied &&
        off !== undefined &&
        !has(report, off) &&
        (id !== "no-root-login" || has(report, "ssh-keys")),
      blocked: applied ? null : blockedText(id, report),
      hint:
        id === "no-root-login"
          ? applied
            ? null
            : protectionDetail(id, report)
          : (HINTS[id] ?? null),
    };
  });
}

export function recommended(report: SecurityReport): string[] {
  return recipeChoices(report)
    .filter(
      (choice) =>
        RECOMMENDED.includes(choice.id) &&
        !choice.applied &&
        !choice.outside &&
        !choice.blocked,
    )
    .map((choice) => choice.id);
}

export function protectionsText(report: SecurityReport): string {
  const choices = recipeChoices(report);
  const on = choices.filter((choice) => choice.applied).length;
  const outside = choices.filter((choice) => choice.outside).length;
  const off = choices.length - on - outside;
  return [
    "Protections",
    on > 0 ? `${on} on` : null,
    outside > 0 ? `${outside} on outside Krynodes` : null,
    off > 0 ? `${off} off` : null,
  ]
    .filter(Boolean)
    .join(" · ");
}

export function firewallPorts(report: SecurityReport): string[] {
  const detail =
    report.findings.find((finding) => finding.id === "public-ports")?.detail ??
    "";
  return [...detail.matchAll(/(\d{1,5}\/(?:tcp|udp))/gu)].map(
    (match) => match[1]!,
  );
}

export const rangeLines = (text: string) =>
  text
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line !== "");

export const toUtcHour = (hour: number, offsetMinutes: number) =>
  ((((hour * 60 + offsetMinutes) / 60) % 24) + 24) % 24;

export const fromUtcHour = (hour: number, offsetMinutes: number) =>
  ((((hour * 60 - offsetMinutes) / 60) % 24) + 24) % 24;

export const protectionsNotice = (report: SecurityReport) =>
  report.platform?.family === null
    ? "Protections support Debian, Ubuntu and RHEL-family servers."
    : null;

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

export function updatesUntil(report: SecurityReport): string | null {
  if (!report.platform) return null;
  const [year, month, day] = report.platform.endOfLife?.split("-") ?? [];
  return year && month && day
    ? `Updates until ${Number(day)} ${MONTHS[Number(month) - 1]} ${year}`
    : "Updates until --";
}

export const firewallName = (report: SecurityReport) =>
  report.platform?.family === "rhel" ? "firewalld" : "ufw";

export function protectionDetail(id: string, report: SecurityReport): string {
  const rhel = report.platform?.family === "rhel";
  const keyed = keyedUsers(report);
  const admins = (keyed ?? []).filter((user) => user !== "root");
  const details: Record<string, string> = {
    "security-updates": `Installs security updates every day with ${rhel ? "dnf" : "unattended-upgrades"}.`,
    "reboot-window":
      "When an update needs a restart, the server restarts at the hour you choose, at most once a day.",
    "ssh-keys-only": `${
      keyed
        ? `SSH stops accepting passwords. ${new Intl.ListFormat("en").format(keyed)} keep logging in with their keys; an account without a key loses SSH.`
        : "SSH stops accepting passwords; keys keep working."
    } If you get locked out, Krynodes can turn passwords back on.`,
    "no-root-login": `SSH stops letting root log in.${
      admins.length > 0
        ? ` ${new Intl.ListFormat("en").format(admins)} ${admins.length === 1 ? "keeps logging in with a key and uses sudo" : "keep logging in with a key and use sudo"}.`
        : ""
    } If you get locked out, Krynodes can turn root login back on.`,
    fail2ban: rhel
      ? "Blocks addresses that keep failing to log in over SSH. Installs fail2ban from EPEL where the system needs it."
      : "Blocks addresses that keep failing to log in over SSH.",
    firewall: `Turns on ${firewallName(report)} and keeps SSH and the ports you tick open. Ports published by Docker are not affected.`,
    "free-port-53":
      "Stops systemd-resolved from holding port 53, so a DNS server such as AdGuard can use it.",
  };
  return details[id] ?? "";
}
