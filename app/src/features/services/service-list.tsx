import { useState, type ReactNode } from "react";
import { Link } from "react-router";

import { Elapsed } from "@/components/node-status";
import { RowMenu } from "@/components/row-menu";
import { StatusDot } from "@/components/status";
import { Button } from "@/components/ui/button";
import { useSignedAction } from "@/features/deploy/use-signed-action";
import { useCancelActions } from "@/lib/api";
import { capitalize, clockTime, nodeState, parseTimestamp } from "@/lib/format";
import { historyText } from "@/lib/history";
import { handleOf } from "@/lib/operations";
import {
  actionText,
  canReadLogs,
  displayName,
  durationText,
  isPending,
  primaryAction,
  toTarget,
  verb,
  type ServiceMember,
} from "@/lib/services";
import { cn } from "@/lib/utils";
import { stacksReady } from "@/lib/devices";
import type { ActionRecord, ServiceAction, ServiceState } from "@/types";

import type { ActionRequest } from "./action-dialog";
import { LogsDialog } from "./logs-dialog";

const TONE: Record<ServiceState, "ok" | "bad" | "warn" | "idle"> = {
  running: "ok",
  starting: "warn",
  stopped: "idle",
  failed: "bad",
};

const ROW =
  "grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 px-3 py-2 md:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)_minmax(0,1.2fr)_7.5rem]";

const BRANCH =
  "relative pl-10 before:absolute before:top-0 before:bottom-0 before:left-5 before:w-px before:bg-border-strong last:before:bottom-1/2 after:absolute after:top-1/2 after:left-5 after:h-px after:w-3 after:bg-border-strong";

const offline = (member: ServiceMember, seen: number) =>
  nodeState(member.node, seen) === "offline";

function stateLabel(member: ServiceMember): string {
  return `${capitalize(member.entry.kind)} · ${member.entry.state}`;
}

export function ActionOutcome({
  action,
  nodeName,
}: {
  action: ActionRecord;
  nodeName: string;
}) {
  const text = `${actionText(action, nodeName)} · ${handleOf(action.requestedBy)}`;
  if (
    !action.output ||
    (action.status !== "failed" && action.status !== "expired")
  ) {
    return (
      <span className="truncate motion-safe:animate-in motion-safe:fade-in">
        {text}
      </span>
    );
  }
  return (
    <details className="min-w-0">
      <summary className="cursor-pointer truncate text-destructive">
        {text}
      </summary>
      <pre className="mt-1 max-h-40 overflow-auto rounded border bg-background p-2 text-[11px] whitespace-pre-wrap">
        {action.output}
      </pre>
    </details>
  );
}

export function ActionRow({
  action,
  nodeName,
  deviceName,
  where = false,
}: {
  action: ActionRecord;
  nodeName: string;
  deviceName?: string;
  where?: boolean;
}) {
  const duration = durationText(action);
  const extra = [where ? `on ${nodeName}` : null, deviceName ?? null]
    .filter(Boolean)
    .join(" · ");
  return (
    <li className="grid grid-cols-[auto_minmax(0,1fr)] items-start gap-x-3 gap-y-1 px-3 py-2.5 text-sm sm:grid-cols-[auto_minmax(0,1fr)_minmax(0,1fr)]">
      <span className="font-mono text-xs leading-5 text-muted-foreground">
        {clockTime(action.requestedAt)}
      </span>
      <span className="min-w-0 break-words">
        {historyText(action)}
        {extra && <span className="text-muted-foreground"> {extra}</span>}
      </span>
      <span className="col-start-2 flex min-w-0 flex-wrap items-baseline gap-x-1 font-mono text-xs text-muted-foreground sm:col-start-auto sm:justify-end">
        {isPending(action) ? (
          <PendingText action={action} nodeName={nodeName} />
        ) : (
          <ActionOutcome action={action} nodeName={nodeName} />
        )}
        {duration && <span>· {duration}</span>}
      </span>
    </li>
  );
}

export function PendingText({
  action,
  nodeName,
}: {
  action: ActionRecord;
  nodeName: string;
}) {
  return (
    <span className="font-mono text-xs text-warning">
      {actionText(action, nodeName)} · {handleOf(action.requestedBy)}
      {action.status === "sent" && (
        <>
          {" · "}
          <Elapsed
            since={parseTimestamp(action.sentAt ?? action.requestedAt)}
          />
        </>
      )}
    </span>
  );
}

function MemberControls({
  member,
  onRequest,
}: {
  member: ServiceMember;
  onRequest: (request: ActionRequest) => void;
}) {
  const [reading, setReading] = useState(false);
  const run = useSignedAction();
  const cancel = useCancelActions();
  const target = toTarget(member);
  const name = displayName(member.entry.kind, member.entry.name);
  const action = member.action;
  const primary = primaryAction(member.entry.state);
  const direct = (chosen: ServiceAction) =>
    run.mutate({ action: chosen, targets: [target] });
  if (action && isPending(action)) {
    return action.status === "queued" ? (
      <Button
        variant="ghost"
        size="sm"
        className="h-8"
        onClick={() => cancel.mutate(action.batchId)}
      >
        Cancel
      </Button>
    ) : null;
  }
  return (
    <div className="flex items-center justify-end gap-1">
      <Button
        variant="outline"
        size="sm"
        className="h-8"
        disabled={run.isPending}
        aria-label={`${verb(primary)} ${name} on ${member.node.name}`}
        onClick={() => direct(primary)}
      >
        {verb(primary)}
      </Button>
      <RowMenu
        label={`${name} on ${member.node.name} actions`}
        items={[
          ...(member.entry.state === "running"
            ? []
            : [{ label: "Start", onSelect: () => direct("start") }]),
          { label: "Restart", onSelect: () => direct("restart") },
          ...(canReadLogs(member.node)
            ? [{ label: "Logs", onSelect: () => setReading(true) }]
            : []),
          {
            label: "Stop",
            destructive: true,
            onSelect: () => onRequest({ action: "stop", target }),
          },
          ...(member.entry.kind === "docker" && stacksReady(member.node)
            ? [
                {
                  label: "Remove",
                  destructive: true,
                  onSelect: () => onRequest({ action: "remove", target }),
                },
              ]
            : []),
        ]}
      />
      <LogsDialog target={target} open={reading} onOpenChange={setReading} />
    </div>
  );
}

export function ServiceRows({
  id,
  members,
  seen,
  trusted,
  branch = false,
  locked,
  onRequest,
  children,
}: {
  id?: string;
  members: ServiceMember[];
  seen: number;
  trusted: boolean;
  branch?: boolean;
  locked?: string;
  onRequest: (request: ActionRequest) => void;
  children?: ReactNode;
}) {
  return (
    <ul id={id} className={branch ? "py-1" : "divide-y"}>
      {children}
      {members.map((member) => {
        const label = stateLabel(member);
        const pending = isPending(member.action);
        return (
          <li
            key={`${member.entry.kind}:${member.entry.name}`}
            className={cn(
              ROW,
              branch && BRANCH,
              offline(member, seen) && "opacity-60",
            )}
          >
            <span className="flex min-h-8 min-w-0 items-center gap-2">
              <StatusDot
                tone={locked ? "idle" : TONE[member.entry.state]}
                pulse={pending}
              />
              <span className="truncate font-medium" title={member.entry.name}>
                {displayName(member.entry.kind, member.entry.name)}
              </span>
            </span>
            <span
              className="col-span-2 truncate font-mono text-xs text-muted-foreground md:col-span-1"
              title={label}
            >
              {label}
            </span>
            <span
              className="col-span-2 min-w-0 truncate font-mono text-xs text-muted-foreground empty:hidden md:col-span-1 md:empty:block"
              aria-live="polite"
            >
              {locked && !pending ? (
                <span className="text-warning">{locked}</span>
              ) : (
                member.action &&
                (isPending(member.action) ? (
                  <PendingText
                    action={member.action}
                    nodeName={member.node.name}
                  />
                ) : (
                  <ActionOutcome
                    action={member.action}
                    nodeName={member.node.name}
                  />
                ))
              )}
            </span>
            <div className="col-start-2 row-start-1 md:col-start-auto md:row-start-auto">
              {trusted && !locked && (
                <MemberControls member={member} onRequest={onRequest} />
              )}
            </div>
          </li>
        );
      })}
    </ul>
  );
}

export function TrustLink() {
  return (
    <Link
      to="/devices"
      className="font-mono text-xs text-warning underline-offset-4 hover:underline"
    >
      Not trusted yet
    </Link>
  );
}
