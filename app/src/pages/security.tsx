import { RefreshCw } from "lucide-react";
import { useEffect } from "react";
import { Link, useSearchParams } from "react-router";

import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import { StatusDot } from "@/components/status";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { FindingRow, ServerSecurity } from "@/features/nodes/security-panel";
import {
  bodyId,
  checkedLine,
  SecurityRowHead,
} from "@/features/nodes/security-row";
import { useNetwork, useOverview, useScan, useServices } from "@/lib/api";
import { agentCurrent } from "@/lib/devices";
import { securityAttention } from "@/lib/fleet-security";
import { inside, networkHint } from "@/lib/network";
import { cn } from "@/lib/utils";

export function SecurityPage() {
  const overview = useOverview();
  const services = useServices();
  const view = useNetwork().data;
  const scan = useScan();
  const [params, setParams] = useSearchParams();
  const open = params.get("server");
  const ready = !!overview.data && !!services.data;

  useEffect(() => {
    if (ready && open) {
      document
        .getElementById(`server-${open}`)
        ?.scrollIntoView({ block: "nearest" });
    }
  }, [ready, open]);

  if (!overview.data || !services.data) {
    return (
      <>
        <PageHeader title="Security" />
        <Skeleton className="h-64" />
      </>
    );
  }

  const nodes = overview.data.nodes.filter(
    (node) => node.enrolled_at !== null && node.disabled_at === null,
  );
  const seen = overview.dataUpdatedAt;
  const entries = services.data.nodes;
  const entryOf = (id: string) => entries.find((item) => item.id === id);
  const reporting = nodes.filter(agentCurrent);
  const attention = securityAttention(
    reporting.flatMap((node) => {
      const report = entryOf(node.id)?.security;
      return report ? [{ node, report }] : [];
    }),
  );
  const serious = attention.some(
    ({ finding }) => finding.severity === "serious",
  );
  const hintOf = (nodeId: string) =>
    networkHint(
      entryOf(nodeId)?.stacks ?? [],
      !!view && inside(view).some((member) => member.nodeId === nodeId),
    );
  const toggle = (id: string) =>
    setParams(
      (current) => {
        const next = new URLSearchParams(current);
        if (next.get("server") === id) next.delete("server");
        else next.set("server", id);
        return next;
      },
      { replace: true },
    );

  return (
    <>
      <PageHeader
        title="Security"
        actions={
          reporting.length > 0 && (
            <Button
              variant="outline"
              disabled={scan.isPending}
              onClick={() => scan.mutate(reporting.map((node) => node.id))}
            >
              <RefreshCw aria-hidden="true" />
              Check All
            </Button>
          )
        }
      />

      {nodes.length === 0 ? (
        <EmptyState
          title="No Servers Yet"
          body="Enroll a server from Fleet. Its security appears here after its first check."
          action={
            <Button asChild>
              <Link to="/">Open Fleet</Link>
            </Button>
          }
        />
      ) : (
        <div className="space-y-6">
          {attention.length === 0 ? (
            <p className="flex items-center gap-2 rounded-lg border bg-card px-3 py-2.5 text-sm text-muted-foreground">
              <StatusDot tone="ok" />
              Nothing needs attention.
            </p>
          ) : (
            <section
              aria-labelledby="security-attention"
              className={cn(
                "rounded-lg border bg-card",
                serious ? "border-destructive/40" : "border-warning/40",
              )}
            >
              <h2
                id="security-attention"
                className="flex items-center gap-2 px-3 py-2.5 text-sm font-medium"
              >
                <StatusDot tone={serious ? "bad" : "warn"} />
                Needs Attention
                <span className="font-mono text-xs font-normal text-muted-foreground">
                  {attention.length}
                </span>
              </h2>
              <ul className="divide-y border-t text-sm">
                {attention.map(({ node, finding }) => (
                  <FindingRow
                    key={`${node.id}|${finding.id}`}
                    node={node}
                    finding={finding}
                    hint={hintOf(node.id)}
                    server
                  />
                ))}
              </ul>
            </section>
          )}
          <ul
            aria-label="Servers"
            className="divide-y rounded-lg border bg-card"
          >
            {nodes.map((node) => {
              const entry = entryOf(node.id);
              const report = entry?.security ?? undefined;
              const expanded =
                open === node.id && agentCurrent(node) && !!report;
              return (
                <li
                  key={node.id}
                  id={`server-${node.id}`}
                  className="scroll-mt-16"
                >
                  <SecurityRowHead
                    node={node}
                    report={report}
                    seen={seen}
                    open={expanded}
                    checking={
                      scan.isPending && !!scan.variables?.includes(node.id)
                    }
                    onToggle={() => toggle(node.id)}
                    onCheck={() => scan.mutate([node.id])}
                  />
                  {expanded && entry && report && (
                    <div
                      id={bodyId(node.id)}
                      className="space-y-6 border-t px-3 py-4"
                    >
                      <p className="font-mono text-[11px] text-muted-foreground lg:hidden">
                        {checkedLine(report, seen)}
                      </p>
                      <ServerSecurity
                        node={node}
                        entry={entry}
                        report={report}
                        seen={seen}
                      />
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        </div>
      )}
    </>
  );
}
