import { ChevronRight } from "lucide-react";
import { Link } from "react-router";

import { SecurityShield } from "@/components/security-mark";
import { Button } from "@/components/ui/button";
import { agentCurrent } from "@/lib/devices";
import { securitySummary } from "@/lib/fleet-security";
import { timeAgo } from "@/lib/format";
import { updatesUntil } from "@/lib/security";
import { cn } from "@/lib/utils";
import type { NodeRecord, SecurityReport } from "@/types";

export const bodyId = (nodeId: string) => `security-${nodeId}`;

export const checkedLine = (report: SecurityReport, seen: number) =>
  [
    report.platform?.name,
    `Checked ${timeAgo(report.checkedAt, seen)}`,
    updatesUntil(report),
  ]
    .filter(Boolean)
    .join(" · ");

function Cell({
  label,
  value,
  className,
}: {
  label: string;
  value: string;
  className: string;
}) {
  return (
    <span
      className={cn("hidden shrink-0 font-mono text-xs lg:block", className)}
    >
      <span className="block text-[11px] text-muted-foreground">{label}</span>
      {value}
    </span>
  );
}

export function SecurityRowHead({
  node,
  report,
  seen,
  open,
  checking,
  onToggle,
  onCheck,
}: {
  node: NodeRecord;
  report: SecurityReport | undefined;
  seen: number;
  open: boolean;
  checking: boolean;
  onToggle: () => void;
  onCheck: () => void;
}) {
  const current = agentCurrent(node);
  const summary = current && report ? securitySummary(report) : null;
  const confined = summary?.confinement;
  const checkNow = (
    <Button
      variant="ghost"
      size="sm"
      className="relative z-10 h-9 md:h-8"
      disabled={checking}
      onClick={onCheck}
    >
      Check Now
    </Button>
  );
  return (
    <div className="relative flex items-center gap-3 px-3 py-3 text-sm">
      <span className="flex w-3.5 shrink-0">
        {current && <SecurityShield report={report} />}
      </span>
      <span className="min-w-0 flex-1">
        {summary ? (
          <button
            type="button"
            aria-expanded={open}
            aria-controls={bodyId(node.id)}
            onClick={onToggle}
            className="block max-w-full truncate text-left font-medium outline-none after:absolute after:inset-0 focus-visible:after:ring-2 focus-visible:after:ring-ring focus-visible:after:ring-inset"
          >
            {node.name}
          </button>
        ) : (
          <Link
            to={`/nodes/${node.id}`}
            className="block truncate font-medium underline-offset-4 hover:underline"
          >
            {node.name}
          </Link>
        )}
        <span className="block font-mono text-[11px] break-words text-muted-foreground">
          {!current ? (
            "Agent too old to report security"
          ) : !report || !summary ? (
            "No security report yet"
          ) : (
            <>
              <span className="hidden lg:inline">
                {checkedLine(report, seen)}
              </span>
              <span className="lg:hidden">
                {[
                  `Protections ${summary.protections}`,
                  summary.firewall,
                  confined && `${confined.title} ${confined.status}`,
                ]
                  .filter(Boolean)
                  .join(" · ")}
              </span>
            </>
          )}
        </span>
      </span>
      {summary && (
        <>
          <Cell
            label="Protections"
            value={summary.protections}
            className="w-28"
          />
          <Cell label="Firewall" value={summary.firewall} className="w-56" />
          {confined ? (
            <Cell
              label={confined.title}
              value={confined.status}
              className="w-24"
            />
          ) : (
            <span className="hidden w-24 shrink-0 lg:block" />
          )}
        </>
      )}
      <span className="flex w-24 shrink-0 justify-end">
        {current && (!summary || open) ? (
          checkNow
        ) : summary ? (
          <span
            className={cn(
              "font-mono text-[11px] whitespace-nowrap",
              summary.toCheck > 0 ? "text-warning" : "text-muted-foreground",
            )}
          >
            {summary.toCheck > 0 ? `${summary.toCheck} to check` : "All clear"}
          </span>
        ) : null}
      </span>
      {summary ? (
        <ChevronRight
          aria-hidden="true"
          className={cn(
            "size-4 shrink-0 text-muted-foreground transition-transform",
            open && "rotate-90",
          )}
        />
      ) : (
        <span className="size-4 shrink-0" />
      )}
    </div>
  );
}
