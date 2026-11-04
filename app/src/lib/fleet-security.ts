import type { Finding, SecurityReport } from "../types";

import { confinementRow } from "./confine";
import { firewallState } from "./firewall";
import {
  attentionOf,
  firewallName,
  protectionsNotice,
  recipeChoices,
} from "./security";

export function securityAttention<T>(
  entries: { node: T; report: SecurityReport }[],
): { node: T; finding: Finding }[] {
  return entries
    .flatMap(({ node, report }) =>
      attentionOf(report).map((finding) => ({ node, finding })),
    )
    .sort(
      (a, b) =>
        Number(b.finding.severity === "serious") -
        Number(a.finding.severity === "serious"),
    );
}

export function securitySummary(report: SecurityReport) {
  const choices = recipeChoices(report);
  const kept = choices.filter(
    (choice) => choice.id !== "firewall" && !choice.unavailable,
  );
  const on = kept.filter((choice) => choice.applied || choice.outside).length;
  const wall = firewallState(
    report,
    choices.find((choice) => choice.id === "firewall")!,
  );
  const open = report.firewall?.closed ? report.firewall.open.length : 0;
  const found = report.confinement?.system
    ? confinementRow(report.confinement)
    : null;
  return {
    protections: protectionsNotice(report)
      ? "Not supported"
      : on === kept.length
        ? `All ${on} On`
        : `${on} of ${kept.length} On`,
    firewall: [
      firewallName(report),
      wall.status,
      open > 0 && `${open} ${open === 1 ? "port" : "ports"}`,
    ]
      .filter(Boolean)
      .join(" · "),
    confinement: found ? { title: found.title, status: found.status } : null,
    toCheck: attentionOf(report).length,
  };
}
