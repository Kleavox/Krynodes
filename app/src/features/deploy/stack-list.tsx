import { ChevronRight } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router";

import { RowMenu } from "@/components/row-menu";
import { StatusDot } from "@/components/status";
import { Button } from "@/components/ui/button";
import type { ActionRequest } from "@/features/services/action-dialog";
import {
  ActionOutcome,
  PendingText,
  ServiceRows,
} from "@/features/services/service-list";
import { useCancelActions, useServices } from "@/lib/api";
import { agentCurrent } from "@/lib/devices";
import { nodeState } from "@/lib/format";
import { LogsDialog } from "@/features/services/logs-dialog";
import { isPending } from "@/lib/services";
import {
  deployBlocker,
  ownFolder,
  stackCommands,
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

const ROW =
  "grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 px-3 py-2 md:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)_minmax(0,1.2fr)_7.5rem]";

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

function stackLabel(member: StackMember) {
  const access =
    member.stack.access === "contained"
      ? " · Contained"
      : member.stack.access === "full"
        ? " · Full access"
        : "";
  return `Compose · ${member.stack.running}/${member.stack.total} running${access}`;
}

function LastDeploy({ member }: { member: StackMember }) {
  const action = member.action;
  if (!action) return <span>No deploy yet</span>;
  return isPending(action) ? (
    <PendingText action={action} nodeName={member.node.name} />
  ) : (
    <ActionOutcome action={action} nodeName={member.node.name} />
  );
}

function Addresses({ addresses }: { addresses: WebAddress[] }) {
  if (addresses.length === 0) return null;
  return (
    <span className="col-span-2 flex min-w-0 flex-wrap gap-x-3 font-mono text-xs md:col-span-4">
      {addresses.map((address) => (
        <a
          key={address.hostname}
          href={`https://${address.hostname}${address.mode === "path" ? (address.path ?? "") : ""}`}
          target="_blank"
          rel="noreferrer"
          className="truncate text-primary underline-offset-4 hover:underline"
        >
          {address.hostname}
          {address.mode === "everyone" ? "" : " · login"}
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
        {blocker === "Not trusted yet" ? (
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
  const failed =
    action?.action === "deploy" &&
    action.status === "failed" &&
    member.stack.rollback;
  const down = member.stack.running === 0;
  const everywhere = peers.filter((peer) => deployBlocker(peer) === null);
  return (
    <div className="flex items-center justify-end gap-1">
      <Button
        variant={failed || down ? "default" : "outline"}
        size="sm"
        className="h-9 md:h-8"
        aria-label={`${failed ? "Roll back" : "Deploy"} ${project} on ${member.node.name}`}
        onClick={failed ? rollback : deploy}
      >
        {failed ? "Roll back" : "Deploy"}
      </Button>
      <RowMenu
        label={`${project} on ${member.node.name} actions`}
        items={[
          ...(failed
            ? [{ label: "Deploy", onSelect: deploy }]
            : member.stack.rollback
              ? [{ label: "Roll back", onSelect: rollback }]
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
                  label: own ? "Edit compose" : "View compose",
                  onSelect: openPanel("compose"),
                },
                { label: "Web address…", onSelect: openPanel("address") },
                ...(addresses.length > 0
                  ? [
                      {
                        label: "Close web address…",
                        onSelect: openPanel("close"),
                      },
                    ]
                  : []),
                { label: "Move to server…", onSelect: openPanel("move") },
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
                  label: "Delete permanently",
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
          <WebAddressDialog target={target} {...panelProps("address")} />
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
  branch,
  locked,
  onRequest,
  onDeploy,
}: {
  item: ServerStack;
  seen: number;
  branch: boolean;
  locked?: string;
  onRequest: (request: ActionRequest) => void;
  onDeploy: (request: DeployRequest) => void;
}) {
  const [open, setOpen] = useState(false);
  const { member, containers } = item;
  const project = member.stack.project;
  const listId = `containers-${member.node.id}-${project}`;
  const addresses = member.addresses ?? [];
  return (
    <li className={cn(branch && BRANCH)}>
      <div
        className={cn(
          ROW,
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
        </span>
        <span className="col-span-2 truncate font-mono text-xs text-muted-foreground md:col-span-1">
          {stackLabel(member)}
        </span>
        <span
          className="col-span-2 min-w-0 truncate font-mono text-xs text-muted-foreground md:col-span-1"
          aria-live="polite"
        >
          {locked && !isPending(member.action) ? (
            <span className="text-warning">{locked}</span>
          ) : (
            <LastDeploy member={member} />
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
      {addresses.length > 0 && (
        <div className={cn("px-3 pb-2", branch ? "pl-16" : "pl-10")}>
          <Addresses addresses={addresses} />
        </div>
      )}
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
