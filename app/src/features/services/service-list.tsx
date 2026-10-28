import { useState, type ReactNode } from "react";
import { Link } from "react-router";

import { Busy } from "@/components/busy";
import { Elapsed } from "@/components/node-status";
import { RowMenu } from "@/components/row-menu";
import { SmallLabel, StatusDot } from "@/components/status";
import { Button } from "@/components/ui/button";
import { useSignedAction } from "@/features/deploy/use-signed-action";
import { useCancelActions, useDevices } from "@/lib/api";
import { nodeState, parseTimestamp } from "@/lib/format";
import { actorOf } from "@/lib/operations";
import {
  actionText,
  displayName,
  isPending,
  STATE_LABEL,
  toTarget,
  type ServiceMember,
} from "@/lib/services";
import { cn } from "@/lib/utils";
import { agentCurrent } from "@/lib/devices";
import type {
  ActionRecord,
  ServiceAction,
  ServiceKind,
  ServiceState,
} from "@/types";

import type { ActionRequest } from "./action-dialog";
import { LogsDialog } from "./logs-dialog";

const TONE: Record<ServiceState, "ok" | "bad" | "warn" | "idle"> = {
  running: "ok",
  starting: "warn",
  stopped: "idle",
  failed: "bad",
  boot: "idle",
  unneeded: "idle",
};

const KIND: Record<"stack" | ServiceKind, string> = {
  stack: "Stack",
  docker: "Container",
  systemd: "Systemd",
};

export const rowGrid =
  "grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 px-3 py-2 md:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)_minmax(0,1.2fr)_7.5rem]";

const BRANCH =
  "relative pl-10 before:absolute before:top-0 before:bottom-0 before:left-5 before:w-px before:bg-border-strong last:before:bottom-1/2 after:absolute after:top-1/2 after:left-5 after:h-px after:w-3 after:bg-border-strong";

const offline = (member: ServiceMember, seen: number) =>
  nodeState(member.node, seen) === "offline";

export function KindLabel({ kind }: { kind: "stack" | ServiceKind }) {
  return <SmallLabel>{KIND[kind]}</SmallLabel>;
}

export function StateCell({ label }: { label: string }) {
  return (
    <span
      className="col-span-2 truncate font-mono text-xs text-muted-foreground md:col-span-1"
      title={label}
    >
      {label}
    </span>
  );
}

export function ActionOutcome({
  action,
  nodeName,
}: {
  action: ActionRecord;
  nodeName: string;
}) {
  const devices = useDevices().data?.devices;
  const text = `${actionText(action, nodeName)} · ${actorOf(action, devices)}`;
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

export function PendingText({
  action,
  nodeName,
}: {
  action: ActionRecord;
  nodeName: string;
}) {
  const devices = useDevices().data?.devices;
  return (
    <span className="font-mono text-xs text-warning">
      <Busy>{actionText(action, nodeName)}</Busy> · {actorOf(action, devices)}
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
      <RowMenu
        label={`${name} on ${member.node.name} actions`}
        items={[
          ...(member.entry.state === "running"
            ? []
            : [{ label: "Start", onSelect: () => direct("start") }]),
          { label: "Restart", onSelect: () => direct("restart") },
          ...(agentCurrent(member.node)
            ? [{ label: "Logs", onSelect: () => setReading(true) }]
            : []),
          {
            label: "Stop",
            destructive: true,
            onSelect: () => onRequest({ action: "stop", target }),
          },
          ...(member.entry.kind === "docker" && agentCurrent(member.node)
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
        const pending = isPending(member.action);
        return (
          <li
            key={`${member.node.id}:${member.entry.kind}:${member.entry.name}`}
            className={cn(
              rowGrid,
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
              {!branch && <KindLabel kind={member.entry.kind} />}
            </span>
            <StateCell label={STATE_LABEL[member.entry.state]} />
            <span
              className="col-span-2 min-w-0 truncate font-mono text-xs text-muted-foreground empty:hidden md:col-span-1 md:empty:block"
              aria-live="polite"
            >
              {locked && !pending ? (
                <span className="text-warning">{locked}</span>
              ) : (
                member.action &&
                pending && (
                  <PendingText
                    action={member.action}
                    nodeName={member.node.name}
                  />
                )
              )}
            </span>
            <div className="col-start-2 row-start-1 md:col-start-auto md:row-start-auto">
              {trusted && !locked ? (
                <MemberControls member={member} onRequest={onRequest} />
              ) : (
                !trusted &&
                !branch && (
                  <p className="text-right">
                    <TrustLink />
                  </p>
                )
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
      Not Trusted Yet
    </Link>
  );
}
