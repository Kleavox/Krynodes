import type { ContainerEntry, StackEntry, UnitEntry } from "@krynodes/protocol";
import { useState } from "react";

import { RowMenu } from "@/components/row-menu";
import { ActionDialog, type Ask } from "@/features/actions/action-dialog";
import { AddCheckDialog } from "@/features/checks/check-dialog";
import { useRefreshStacks } from "@/lib/api";
import type { Access } from "@/lib/stacks";
import type { FleetNode, StackNode } from "@/types";

import { LogsDialog } from "./logs-dialog";
import { AccessChoice, NewStackDialog } from "./new-stack-dialog";

type Opens = "edit" | "logs" | "check" | "adopt";

export interface MenuItem {
  label: string;
  destructive?: boolean;
  ask?: Ask;
  opens?: Opens;
}

const offline = (server: string): MenuItem[] => [
  { label: `${server} is offline.` },
];

const verb = (
  kind: Ask["kind"],
  name: string,
  action: string,
  label: string,
  body: string,
  destructive = false,
): MenuItem => ({
  label,
  destructive,
  ask: {
    kind,
    action,
    name,
    title: `${label} ${name}`,
    heading: destructive ? `${label} ${name}?` : `${label} ${name}`,
    body,
    confirm: label,
    destructive,
  },
});

export function stackItems(entry: StackNode, stack: StackEntry): MenuItem[] {
  if (!entry.online) return offline(entry.name);
  const name = stack.project;
  const run = (
    action: string,
    label: string,
    body: string,
    destructive = false,
  ) => verb("stack", name, action, label, body, destructive);
  if (!stack.own) {
    return [
      { label: "Adopt", opens: "adopt" },
      { label: "Add Check", opens: "check" },
    ];
  }
  return [
    run(
      "deploy",
      "Deploy",
      `${entry.name} pulls the newest images for ${name} and starts them. If they fail their health check, the previous images come back.`,
    ),
    { label: "Edit Compose", opens: "edit" },
    ...(stack.rollback
      ? [
          run(
            "rollback",
            "Rollback",
            `${name} goes back to the images it ran before the last deploy.`,
            true,
          ),
        ]
      : []),
    run("start", "Start", `${entry.name} starts ${name}.`),
    run(
      "stop",
      "Stop",
      `${name} stops until you start it again. Its checks read Paused.`,
      true,
    ),
    run(
      "restart",
      "Restart",
      `${name} restarts. What it serves is away for a moment.`,
    ),
    { label: "Logs", opens: "logs" },
    { label: "Add Check", opens: "check" },
    run(
      "remove",
      "Remove",
      `${name} stops and waits in Removed for 7 days. Restore brings it back; Delete Permanently deletes it, its folder, its volumes and its checks.`,
      true,
    ),
  ];
}

export function removedItems(entry: StackNode, project: string): MenuItem[] {
  if (!entry.online) return offline(entry.name);
  return [
    verb(
      "stack",
      project,
      "restore",
      "Restore",
      `${project} comes back from Removed on ${entry.name}.`,
    ),
    verb(
      "stack",
      project,
      "purge",
      "Delete Permanently",
      `${project}, its folder, its volumes and its checks are deleted from ${entry.name}. This cannot be undone.`,
      true,
    ),
  ];
}

export function serviceItems(
  entry: StackNode,
  target:
    | { kind: "container"; item: ContainerEntry }
    | { kind: "unit"; item: UnitEntry },
): MenuItem[] {
  if (!entry.online) return offline(entry.name);
  const { kind, item } = target;
  if (kind === "unit" && item.protected) {
    return [{ label: `${item.name} is protected.` }];
  }
  const run = (
    action: string,
    label: string,
    body: string,
    destructive = false,
  ) => verb(kind, item.name, action, label, body, destructive);
  return [
    run("start", "Start", `${entry.name} starts ${item.name}.`),
    run("stop", "Stop", `${item.name} stops until you start it again.`, true),
    run("restart", "Restart", `${item.name} restarts.`),
    ...(kind === "container"
      ? [{ label: "Logs", opens: "logs" as const }]
      : []),
  ];
}

export const installDocker = (entry: StackNode): MenuItem => {
  const item = verb(
    "docker",
    "docker",
    "install",
    "Install Docker",
    `${entry.name} installs Docker and Docker Compose from Docker's own packages.`,
  );
  return {
    ...item,
    ask: { ...item.ask!, title: "Install Docker", heading: "Install Docker" },
  };
};

export function VerbMenu({
  label,
  items,
  node,
  onOpen,
}: {
  label: string;
  items: MenuItem[];
  node: FleetNode | undefined;
  onOpen?: (opens: Opens) => void;
}) {
  const [asked, setAsked] = useState<Ask | null>(null);
  const refresh = useRefreshStacks();
  return (
    <>
      <RowMenu
        label={label}
        items={items.map((item) => ({
          label: item.label,
          destructive: item.destructive,
          onSelect:
            node && item.ask
              ? () => setAsked(item.ask!)
              : node && item.opens
                ? () => onOpen?.(item.opens!)
                : undefined,
        }))}
      />
      {asked && node && (
        <ActionDialog
          node={node}
          ask={asked}
          onClose={() => setAsked(null)}
          onDone={refresh}
        />
      )}
    </>
  );
}

function AdoptDialog({
  node,
  project,
  onClose,
}: {
  node: FleetNode;
  project: string;
  onClose: () => void;
}) {
  const refresh = useRefreshStacks();
  const [access, setAccess] = useState<Access>("contained");
  return (
    <ActionDialog
      node={node}
      onClose={onClose}
      onDone={refresh}
      ask={{
        kind: "stack",
        action: "adopt",
        name: project,
        title: `Adopt ${project}`,
        args: { access },
        heading: `Adopt ${project}`,
        body: `Krynodes takes over ${project} on ${node.name}, so you can deploy, edit and roll it back here.`,
        confirm: "Adopt",
      }}
    >
      <AccessChoice value={access} onChange={setAccess} />
    </ActionDialog>
  );
}

export function StackMenu({
  entry,
  stack,
  node,
  servers,
}: {
  entry: StackNode;
  stack: StackEntry;
  node: FleetNode | undefined;
  servers: StackNode[];
}) {
  const [open, setOpen] = useState<Opens | null>(null);
  const close = () => setOpen(null);
  const containers = [
    ...new Set([
      ...stack.services.map((one) => one.container),
      ...entry.containers
        .filter((one) => one.project === stack.project)
        .map((one) => one.name),
    ]),
  ];
  return (
    <>
      <VerbMenu
        label={`Actions for ${stack.project}`}
        items={stackItems(entry, stack)}
        node={node}
        onOpen={setOpen}
      />
      {open === "edit" && (
        <NewStackDialog
          servers={servers}
          editing={{ entry, project: stack.project }}
          onClose={close}
        />
      )}
      {open === "logs" && node && (
        <LogsDialog
          node={node}
          kind="stack"
          name={stack.project}
          services={stack.services.map((one) => one.service)}
          onClose={close}
        />
      )}
      {open === "check" && (
        <AddCheckDialog
          nodeId={entry.nodeId}
          server={entry.name}
          containers={containers}
          onClose={close}
        />
      )}
      {open === "adopt" && node && (
        <AdoptDialog node={node} project={stack.project} onClose={close} />
      )}
    </>
  );
}
