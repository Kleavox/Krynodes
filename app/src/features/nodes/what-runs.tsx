import { ChevronRight, RefreshCw } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router";

import { Busy } from "@/components/busy";
import { StatusDot } from "@/components/status";
import { Button } from "@/components/ui/button";
import {
  CheckRow,
  useCheckView,
  type CheckView,
} from "@/features/checks/check-row";
import {
  DeployDialog,
  type DeployRequest,
} from "@/features/deploy/deploy-dialog";
import { StackRow } from "@/features/deploy/stack-list";
import {
  ActionDialog,
  type ActionRequest,
} from "@/features/services/action-dialog";
import { ProblemFix } from "@/features/services/needs-attention";
import {
  KindLabel,
  ServiceRows,
  TrustLink,
} from "@/features/services/service-list";
import {
  useHistoryAttention,
  useOverview,
  useQuarantine,
  useRefreshServices,
  useServices,
} from "@/lib/api";
import { serverOperation } from "@/lib/operations";
import { refreshPending } from "@/lib/services";
import {
  serverLists,
  servicesAttention,
  type ServerList,
  type ServiceProblem,
} from "@/lib/stacks";
import { cn } from "@/lib/utils";
import {
  foldedUnitsText,
  incidentNote,
  whatRuns,
  type RunCard,
} from "@/lib/what-runs";
import type { NodeRecord, StoppedStack } from "@/types";

import { StoppedStackNote } from "./quarantine-panels";

const SECTION_TITLE = "text-xs font-medium text-muted-foreground";

function FoldedUnits({
  card,
  list,
  seen,
  locked,
  onRequest,
}: {
  card: RunCard;
  list: ServerList;
  seen: number;
  locked?: string;
  onRequest: (request: ActionRequest) => void;
}) {
  const [open, setOpen] = useState(false);
  const members = card.units.flatMap(
    (unit) =>
      list.members.find(
        (member) =>
          member.entry.kind === "systemd" && member.entry.name === unit,
      ) ?? [],
  );
  return (
    <div>
      <button
        type="button"
        aria-expanded={open}
        onClick={() => setOpen(!open)}
        className="flex min-h-12 w-full min-w-0 items-center gap-2 px-3 py-2 text-left"
      >
        <ChevronRight
          aria-hidden="true"
          className={cn(
            "size-4 shrink-0 text-muted-foreground transition-transform",
            open && "rotate-90",
          )}
        />
        <StatusDot tone="ok" />
        <span className="min-w-0 truncate font-medium">
          {foldedUnitsText(card.units)}
        </span>
        <KindLabel kind="systemd" />
        <span className="shrink-0 font-mono text-xs text-muted-foreground">
          All Running
        </span>
      </button>
      {open && (
        <ServiceRows
          members={members}
          seen={seen}
          trusted={list.trusted}
          branch
          locked={locked}
          onRequest={onRequest}
        />
      )}
    </div>
  );
}

function Card({
  card,
  list,
  problem,
  stopped,
  node,
  view,
  seen,
  locked,
  onRequest,
  onDeploy,
}: {
  card: RunCard;
  stopped: StoppedStack | undefined;
  node: NodeRecord;
  list: ServerList;
  problem: ServiceProblem | undefined;
  view: CheckView;
  seen: number;
  locked?: string;
  onRequest: (request: ActionRequest) => void;
  onDeploy: (request: DeployRequest) => void;
}) {
  const stack =
    card.kind === "stack"
      ? list.stacks.find((item) => item.member.stack.project === card.name)
      : undefined;
  const member =
    card.kind !== "stack" && card.name
      ? list.members.find(
          (item) =>
            item.entry.kind === card.kind && item.entry.name === card.name,
        )
      : undefined;
  return (
    <article
      className={cn(
        "rounded-lg border bg-card",
        card.problem && "border-destructive/40",
      )}
    >
      {stack ? (
        <ul>
          <StackRow
            item={stack}
            seen={seen}
            locked={locked}
            onRequest={onRequest}
            onDeploy={onDeploy}
          />
        </ul>
      ) : member ? (
        <ServiceRows
          members={[member]}
          seen={seen}
          trusted={list.trusted}
          locked={locked}
          onRequest={onRequest}
        />
      ) : (
        <FoldedUnits
          card={card}
          list={list}
          seen={seen}
          locked={locked}
          onRequest={onRequest}
        />
      )}
      {stopped && (
        <StoppedStackNote node={node} stack={stopped} now={view.now} />
      )}
      {problem && !locked && (
        <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-2 border-t px-3 py-2">
          <p className="min-w-0 font-mono text-xs break-words text-destructive">
            {problem.reason}
          </p>
          <ProblemFix problem={problem} onDeploy={onDeploy} />
        </div>
      )}
      {card.checks.length > 0 && (
        <ul className="divide-y border-t">
          {card.checks.map((check) => (
            <CheckRow key={check.id} check={check} view={view} />
          ))}
        </ul>
      )}
      {card.incident && (
        <Link
          to={`/incidents/${card.incident.id}`}
          className={cn(
            "flex items-center justify-between gap-2 border-t px-3 py-2 font-mono text-xs hover:bg-card-hover",
            card.incident.status === "OPEN"
              ? "text-destructive"
              : "text-muted-foreground",
          )}
        >
          <span className="min-w-0 truncate">
            {incidentNote(card.incident, view.now)}
            {card.incident.summary && ` · ${card.incident.summary}`}
          </span>
          <span className="shrink-0 text-primary">Incident →</span>
        </Link>
      )}
    </article>
  );
}

export function WhatRuns({ node, seen }: { node: NodeRecord; seen: number }) {
  const services = useServices();
  const overview = useOverview();
  const attention = useHistoryAttention();
  const refresh = useRefreshServices();
  const view = useCheckView();
  const stopped = useQuarantine(node.id).data?.stopped ?? [];
  const [request, setRequest] = useState<ActionRequest | null>(null);
  const [deploy, setDeploy] = useState<DeployRequest | null>(null);
  const entry = services.data?.nodes.find((item) => item.id === node.id);
  const trusted = (entry?.trust?.access.length ?? 0) > 0;
  const reported =
    entry !== undefined &&
    (entry.services.length > 0 || entry.stacks.length > 0);
  const refreshing =
    entry !== undefined && refreshPending(entry, services.dataUpdatedAt);
  const checks = (overview.data?.checks ?? []).filter(
    (check) => check.node_id === node.id,
  );
  const items = attention.data?.items ?? [];
  const { cards, other } = entry
    ? whatRuns(entry, checks, overview.data?.incidents ?? [], items)
    : { cards: [], other: checks };
  const list = services.data
    ? serverLists(services.data, [node], {
        showSystem: true,
        query: "",
        notRunning: false,
      })[0]
    : undefined;
  const problems = services.data
    ? servicesAttention(services.data, [node], items, view.now)
    : [];
  const locked =
    serverOperation(node, services.data?.actions ?? [], view.now)?.kind ===
    "restarting"
      ? `Waiting for ${node.name} to come back`
      : undefined;
  return (
    <div className="space-y-6">
      <section aria-labelledby="what-runs">
        <div className="mb-2 flex min-h-8 items-center gap-2">
          <h2 id="what-runs" className={SECTION_TITLE}>
            What Runs on {node.name}
          </h2>
          {services.data && !trusted && <TrustLink />}
          <Button
            variant="ghost"
            size="sm"
            className="ml-auto h-8"
            disabled={refresh.isPending || refreshing}
            onClick={() => refresh.mutate([node.id])}
          >
            <RefreshCw aria-hidden="true" />
            {refreshing ? <Busy>Refreshing</Busy> : "Refresh"}
          </Button>
        </div>
        {!reported || !list ? (
          <p className="rounded-lg border border-dashed p-4 text-sm text-muted-foreground">
            {services.data ? (
              "Nothing reported yet. Stacks, containers and systemd units appear within five minutes of enrolling."
            ) : (
              <Busy>Loading</Busy>
            )}
          </p>
        ) : (
          <div className="space-y-2">
            {cards.map((card) => (
              <Card
                key={`${card.kind}|${card.name}`}
                card={card}
                list={list}
                problem={problems.find(
                  (each) =>
                    each.kind === card.kind && each.target.name === card.name,
                )}
                stopped={
                  card.kind === "stack"
                    ? stopped.find((each) => each.project === card.name)
                    : undefined
                }
                node={node}
                view={view}
                seen={seen}
                locked={locked}
                onRequest={setRequest}
                onDeploy={setDeploy}
              />
            ))}
          </div>
        )}
      </section>
      {other.length > 0 && (
        <section aria-labelledby="other-checks">
          <h2
            id="other-checks"
            className={cn(SECTION_TITLE, "mb-2 flex min-h-8 items-center")}
          >
            Other Checks
          </h2>
          <ul className="divide-y rounded-lg border bg-card">
            {other.map((check) => (
              <CheckRow key={check.id} check={check} view={view} />
            ))}
          </ul>
        </section>
      )}
      {checks.length === 0 && (
        <p className="rounded-lg border border-dashed p-4 text-sm text-muted-foreground">
          No checks on this server. Use Actions to add one.
        </p>
      )}
      <ActionDialog request={request} onClose={() => setRequest(null)} />
      <DeployDialog
        request={deploy}
        seen={seen}
        onClose={() => setDeploy(null)}
      />
    </div>
  );
}
