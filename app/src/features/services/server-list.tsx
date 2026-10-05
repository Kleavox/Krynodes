import { ArrowUpRight, ChevronRight } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router";

import { DockerMark } from "@/components/docker-mark";
import { OperationText } from "@/components/node-status";
import { SecurityMark } from "@/components/security-mark";
import { StatusDot } from "@/components/status";
import type { DeployRequest } from "@/features/deploy/deploy-dialog";
import { StackRow } from "@/features/deploy/stack-list";
import { NodeActions } from "@/features/nodes/node-actions";
import { nodeState } from "@/lib/format";
import { serverOperation } from "@/lib/operations";
import type { ServerList } from "@/lib/stacks";
import { cn } from "@/lib/utils";
import type { ActionRecord } from "@/types";

import type { ActionRequest } from "./action-dialog";
import { ServiceRows, TrustLink } from "./service-list";

const plural = (count: number, word: string) =>
  `${count} ${word}${count === 1 ? "" : "s"}`;

export const countText = (list: ServerList) =>
  [
    list.stacks.length > 0 ? plural(list.stacks.length, "stack") : null,
    list.members.length > 0 || list.stacks.length === 0
      ? plural(list.members.length, "service")
      : null,
  ]
    .filter(Boolean)
    .join(" · ");

export function ServerServiceList({
  groups,
  actions,
  seen,
  filtering,
  onRequest,
  onDeploy,
}: {
  groups: ServerList[];
  actions: ActionRecord[];
  seen: number;
  filtering: boolean;
  onRequest: (request: ActionRequest) => void;
  onDeploy: (request: DeployRequest) => void;
}) {
  const [flipped, setFlipped] = useState<ReadonlySet<string>>(() => new Set());
  const openByDefault = filtering || groups.length === 1;
  const toggle = (id: string) =>
    setFlipped((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  return (
    <div className="space-y-3">
      {groups.map((group) => {
        const id = group.node.id;
        const open = openByDefault !== flipped.has(id);
        const down =
          group.members.filter((member) => member.entry.state !== "running")
            .length +
          group.stacks.filter(
            (item) => item.member.stack.running < item.member.stack.total,
          ).length;
        const operation = serverOperation(group.node, actions, Date.now());
        const away = !operation && nodeState(group.node, seen) === "offline";
        const locked =
          operation?.kind === "restarting"
            ? `Waiting for ${group.node.name} to come back`
            : undefined;
        return (
          <section
            key={id}
            aria-labelledby={`server-${id}`}
            className="rounded-lg border bg-card"
          >
            <div
              className={cn(
                "flex min-h-11 items-center gap-2 px-3",
                open && "border-b",
              )}
            >
              <h2 id={`server-${id}`} className="min-w-0 flex-1">
                <button
                  type="button"
                  aria-expanded={open}
                  aria-controls={`services-${id}`}
                  onClick={() => toggle(id)}
                  className="flex w-full min-w-0 flex-wrap items-center gap-x-2 gap-y-0.5 rounded-sm py-2 text-left outline-none focus-visible:ring-2 focus-visible:ring-ring"
                >
                  <ChevronRight
                    aria-hidden="true"
                    className={cn(
                      "size-4 shrink-0 text-muted-foreground transition-transform",
                      open && "rotate-90",
                    )}
                  />
                  <StatusDot
                    tone={operation ? "warn" : away ? "idle" : "ok"}
                    pulse={operation !== null}
                  />
                  <span className="min-w-0 truncate font-medium">
                    {group.node.name}
                  </span>
                  <DockerMark nodeId={group.node.id} />
                  <SecurityMark nodeId={group.node.id} />
                  <span className="font-mono text-xs font-normal text-muted-foreground">
                    {countText(group)}
                    {down > 0 && ` · ${down} not running`}
                    {away && " · offline"}
                  </span>
                  {operation && (
                    <span className="font-mono text-xs font-normal text-warning">
                      <OperationText operation={operation} />
                    </span>
                  )}
                </button>
              </h2>
              {!group.trusted && <TrustLink />}
              <NodeActions node={group.node} compact />
              <Link
                to={`/nodes/${id}`}
                aria-label={`Open ${group.node.name}`}
                className="grid size-8 shrink-0 place-items-center rounded-md text-muted-foreground hover:bg-accent hover:text-foreground"
              >
                <ArrowUpRight aria-hidden="true" className="size-4" />
              </Link>
            </div>
            {open && (
              <ServiceRows
                id={`services-${id}`}
                members={group.members}
                seen={seen}
                trusted={group.trusted}
                branch
                locked={locked}
                onRequest={onRequest}
              >
                {group.stacks.map((item) => (
                  <StackRow
                    key={item.member.stack.project}
                    item={item}
                    seen={seen}
                    branch
                    locked={locked}
                    onRequest={onRequest}
                    onDeploy={onDeploy}
                  />
                ))}
              </ServiceRows>
            )}
          </section>
        );
      })}
    </div>
  );
}
