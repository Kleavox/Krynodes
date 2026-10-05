import type { SecurityReport } from "../types";

import { RECIPE_TITLES } from "./services";

export interface RecipeChoice {
  id: string;
  title: string;
  applied: boolean;
  blocked: string | null;
}

const ORDER = [
  "security-updates",
  "reboot-window",
  "ssh-keys-only",
  "fail2ban",
  "firewall",
  "free-port-53",
];

const RECOMMENDED = [
  "security-updates",
  "reboot-window",
  "ssh-keys-only",
  "fail2ban",
];

const has = (report: SecurityReport, id: string) =>
  report.findings.some((finding) => finding.id === id);

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
    return {
      id,
      title: RECIPE_TITLES[id] ?? id,
      applied,
      blocked:
        id === "ssh-keys-only" && !applied && has(report, "ssh-no-keys")
          ? "Add an SSH key for root or a sudo user first."
          : null,
    };
  });
}

export function recommended(report: SecurityReport): string[] {
  return recipeChoices(report)
    .filter(
      (choice) =>
        RECOMMENDED.includes(choice.id) && !choice.applied && !choice.blocked,
    )
    .map((choice) => choice.id);
}

export function firewallPorts(report: SecurityReport): string[] {
  const detail =
    report.findings.find((finding) => finding.id === "public-ports")?.detail ??
    "";
  return [...detail.matchAll(/(\d{1,5}\/(?:tcp|udp))/gu)].map(
    (match) => match[1]!,
  );
}

export const toUtcHour = (hour: number, offsetMinutes: number) =>
  ((((hour * 60 + offsetMinutes) / 60) % 24) + 24) % 24;

export const fromUtcHour = (hour: number, offsetMinutes: number) =>
  ((((hour * 60 - offsetMinutes) / 60) % 24) + 24) % 24;
