import { ChevronRight } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router";

import { RowMenu } from "@/components/row-menu";
import { StatusDot } from "@/components/status";
import { Button } from "@/components/ui/button";
import type { ActionRequest } from "@/features/services/action-dialog";
import {
  KindLabel,
  PendingText,
  rowGrid,
  ServiceRows,
  StateCell,
} from "@/features/services/service-list";
import { useCancelActions, useServices } from "@/lib/api";
import { agentCurrent } from "@/lib/devices";
import { nodeState } from "@/lib/format";
import { LogsDialog } from "@/features/services/logs-dialog";
import { isPending } from "@/lib/services";
import {
  deployBlocker,
  ownFolder,
  reachReady,
  stackCommands,
  stackState,
  type ServerStack,
  type StackMember,
} from "@/lib/stacks";
import { cn } from "@/lib/utils";
import type { WebAddress } from "@/types";

import { ComposeDialog, type StackTarget } from "./compose-dialog";
import { AdoptDialog, MoveDialog } from "./move-dialog";
import { CloseAddressDialog, WebAddressDialog } from "./web-address-dialog";

import type { DeployRequest } from "./deploy-dialog";
import {
  StackActionDialog,
  type StackActionRequest,
} from "./stack-action-dialog";
import { useSignedAction } from "./use-signed-action";

const BRANCH =
  "relative before:absolute before:top-0 before:bottom-0 before:left-5 before:w-px before:bg-border-strong last:before:bottom-auto last:before:h-6 after:absolute after:top-6 after:left-5 after:h-px after:w-3 after:bg-border-strong";

const offline = (member: StackMember, seen: number) =>
  nodeState(member.node, seen) === "offline";

const tone = (member: StackMember) =>
  member.stack.running === member.stack.total
    ? "ok"
    : member.stack.running === 0
      ? "bad"
      : "warn";

function Addresses({ addresses }: { addresses: WebAddress[] }) {
  return (
    <span className="flex min-w-0 flex-wrap gap-x-3">
      {addresses.map((address) => (
        <a
          key={address.hostname}
          href={`https://${address.hostname}${address.mode === "path" ? (address.path ?? "") : ""}`}
          target="_blank"
          rel="noreferrer"
          className="truncate text-primary underline-offset-4 hover:underline"
        >
          {address.hostname}
          {address.mode === "everyone" ? "" : " · Login"}
        </a>
      ))}
    </span>
  );
}

type Panel =
  "compose" | "address" | "close" | "move" | "adopt" | "remove" | "purge";

function StackControls({
  project,
  member,
  peers,
  onRequest,
}: {
  project: string;
  member: StackMember;
  peers: StackMember[];
  onRequest: (request: DeployRequest) => void;
}) {
  const [reading, setReading] = useState(false);
  const [confirming, setConfirming] = useState<StackActionRequest | null>(null);
  const run = useSignedAction();
  const cancel = useCancelActions();
  const blocker = deployBlocker(member);
  const commands = stackCommands(member);
  const direct = (action: "start" | "restart") =>
    run.mutate({
      action,
      targets: [{ nodeId: member.node.id, kind: "compose", name: project }],
    });
  const services = useServices();
  const [panel, setPanel] = useState<Panel | null>(null);
  const addresses = member.addresses ?? [];
  const target: StackTarget = {
    nodeId: member.node.id,
    nodeName: member.node.name,
    project,
    sealKey:
      services.data?.nodes.find((entry) => entry.id === member.node.id)
        ?.sealKey ?? null,
    reach: reachReady(member.node),
  };
  const modern =
    agentCurrent(member.node) && member.trusted && member.stack.compose;
  const own = ownFolder(member.stack.directory);
  const confirm = (action: StackActionRequest["action"]) =>
    action !== "stop" && addresses.length > 0
      ? setPanel(action)
      : setConfirming({
          action,
          project,
          node: member.node,
          directory: member.stack.directory,
        });
  const openPanel = (next: Panel) => () => setPanel(next);
  const panelProps = (name: Panel) => ({
    open: panel === name,
    onOpenChange: (open: boolean) => setPanel(open ? name : null),
  });
  const action = member.action;
  if (action && isPending(action)) {
    return action.status === "queued" ? (
      <div className="flex justify-end">
        <Button
          variant="ghost"
          size="sm"
          className="h-9 md:h-8"
          onClick={() => cancel.mutate(action.batchId)}
        >
          Cancel
        </Button>
      </div>
    ) : null;
  }
  if (blocker) {
    return (
      <p className="text-right text-xs text-muted-foreground">
        {blocker === "Not Trusted Yet" ? (
          <Link
            to="/devices"
            className="underline underline-offset-4 hover:text-foreground"
          >
            {blocker}
          </Link>
        ) : (
          blocker
        )}
      </p>
    );
  }
  const deploy = () =>
    onRequest({ action: "deploy", project, members: [member] });
  const rollback = () =>
    onRequest({ action: "rollback", project, members: [member] });
  const everywhere = peers.filter((peer) => deployBlocker(peer) === null);
  return (
    <div className="flex items-center justify-end gap-1">
      <RowMenu
        label={`${project} on ${member.node.name} actions`}
        items={[
          { label: "Deploy", onSelect: deploy },
          ...(member.stack.rollback
            ? [{ label: "Roll Back", onSelect: rollback }]
            : []),
          ...(commands.includes("start")
            ? [{ label: "Start", onSelect: () => direct("start") }]
            : []),
          ...(commands.includes("restart")
            ? [{ label: "Restart", onSelect: () => direct("restart") }]
            : []),
          ...(everywhere.length > 1
            ? [
                {
                  label: `Deploy on all ${everywhere.length} servers`,
                  onSelect: () =>
                    onRequest({ action: "deploy", project, members: peers }),
                },
              ]
            : []),
          ...(agentCurrent(member.node)
            ? [{ label: "Logs", onSelect: () => setReading(true) }]
            : []),
          ...(modern
            ? [
                {
                  label: own ? "Edit Compose" : "View Compose",
                  onSelect: openPanel("compose"),
                },
                { label: "Web Address…", onSelect: openPanel("address") },
                ...(addresses.length > 0
                  ? [
                      {
                        label: "Close Web Address…",
                        onSelect: openPanel("close"),
                      },
                    ]
                  : []),
                { label: "Move to Server…", onSelect: openPanel("move") },
                ...(own
                  ? []
                  : [
                      {
                        label: "Move into Krynodes",
                        onSelect: openPanel("adopt"),
                      },
                    ]),
              ]
            : []),
          ...(commands.includes("stop")
            ? [
                {
                  label: "Stop",
                  destructive: true,
                  onSelect: () => confirm("stop"),
                },
              ]
            : []),
          ...(commands.includes("remove")
            ? [
                {
                  label: "Remove",
                  destructive: true,
                  onSelect: () => confirm("remove"),
                },
                {
                  label: "Delete Permanently",
                  destructive: true,
                  onSelect: () => confirm("purge"),
                },
              ]
            : []),
        ]}
      />
      <StackActionDialog
        request={confirming}
        onClose={() => setConfirming(null)}
      />
      {modern && (
        <>
          <ComposeDialog
            target={target}
            editable={own}
            {...panelProps("compose")}
          />
          <WebAddressDialog
            target={target}
            addresses={addresses}
            {...panelProps("address")}
          />
          <CloseAddressDialog
            target={target}
            addresses={addresses}
            {...panelProps("close")}
          />
          <CloseAddressDialog
            target={target}
            addresses={addresses}
            disposal="remove"
            {...panelProps("remove")}
          />
          <CloseAddressDialog
            target={target}
            addresses={addresses}
            disposal="purge"
            {...panelProps("purge")}
          />
          <MoveDialog
            target={target}
            addresses={addresses}
            {...panelProps("move")}
          />
          <AdoptDialog
            target={target}
            directory={member.stack.directory}
            {...panelProps("adopt")}
          />
        </>
      )}
      <LogsDialog
        target={{
          nodeId: member.node.id,
          nodeName: member.node.name,
          kind: "compose",
          name: project,
        }}
        open={reading}
        onOpenChange={setReading}
      />
    </div>
  );
}

export function StackRow({
  item,
  seen,
  branch = false,
  locked,
  onRequest,
  onDeploy,
}: {
  item: ServerStack;
  seen: number;
  branch?: boolean;
  locked?: string;
  onRequest: (request: ActionRequest) => void;
  onDeploy: (request: DeployRequest) => void;
}) {
  const [open, setOpen] = useState(false);
  const { member, containers } = item;
  const project = member.stack.project;
  const listId = `containers-${member.node.id}-${project}`;
  const addresses = member.addresses ?? [];
  const action = member.action;
  return (
    <li className={cn(branch && BRANCH)}>
      <div
        className={cn(
          rowGrid,
          branch && "pl-10",
          offline(member, seen) && "opacity-60",
        )}
      >
        <span className="flex min-h-8 min-w-0 items-center gap-1.5">
          <Button
            variant="ghost"
            size="icon"
            className="-ml-1.5 size-7 shrink-0"
            aria-expanded={open}
            aria-controls={listId}
            aria-label={`${open ? "Hide" : "Show"} containers of ${project}`}
            onClick={() => setOpen(!open)}
          >
            <ChevronRight
              aria-hidden="true"
              className={cn("transition-transform", open && "rotate-90")}
            />
          </Button>
          <StatusDot
            tone={locked ? "idle" : tone(member)}
            pulse={isPending(member.action)}
          />
          <span className="truncate font-medium" title={member.stack.directory}>
            {project}
          </span>
          <KindLabel kind="stack" />
        </span>
        <StateCell label={stackState(member.stack)} />
        <span
          className="col-span-2 min-w-0 truncate font-mono text-xs text-muted-foreground empty:hidden md:col-span-1 md:empty:block"
          aria-live="polite"
        >
          {action && isPending(action) ? (
            <PendingText action={action} nodeName={member.node.name} />
          ) : locked ? (
            <span className="text-warning">{locked}</span>
          ) : (
            addresses.length > 0 && <Addresses addresses={addresses} />
          )}
        </span>
        <div className="col-start-2 row-start-1 md:col-start-auto md:row-start-auto">
          {!locked && (
            <StackControls
              project={project}
              member={member}
              peers={item.peers}
              onRequest={onDeploy}
            />
          )}
        </div>
      </div>
      {open && (
        <div id={listId} className={branch ? "pl-6" : "pl-1"}>
          {containers.length === 0 ? (
            <p className="px-3 pb-2 pl-10 font-mono text-xs text-muted-foreground">
              No containers named after this stack.
            </p>
          ) : (
            <ServiceRows
              members={containers}
              seen={seen}
              trusted={member.trusted}
              branch
              locked={locked}
              onRequest={onRequest}
            />
          )}
        </div>
      )}
    </li>
  );
}
