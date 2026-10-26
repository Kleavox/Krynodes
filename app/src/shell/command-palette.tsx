import { useState } from "react";
import { useNavigate } from "react-router";

import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command";
import {
  displayName,
  groupByServer,
  primaryAction,
  toTarget,
  verb,
  type ActionTarget,
} from "@/lib/services";
import { usePackageNames } from "@/lib/api";
import { canRestartServer } from "@/lib/devices";
import { packageCommands } from "@/lib/packages";
import { deployBlocker, groupStacks } from "@/lib/stacks";
import type { NodeRecord, ServiceAction, ServicesResponse } from "@/types";

import { PAGES } from "./nav";

export function CommandPalette({
  open,
  onOpenChange,
  nodes,
  services,
  onRun,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  nodes: NodeRecord[];
  services: ServicesResponse | undefined;
  onRun: (target: ActionTarget, action: ServiceAction) => void;
}) {
  const navigate = useNavigate();
  const [search, setSearch] = useState("");
  const names = usePackageNames(open);
  const close = (next: boolean) => {
    if (!next) setSearch("");
    onOpenChange(next);
  };
  const go = (to: string) => {
    close(false);
    void navigate(to);
  };
  const packages = packageCommands(nodes, names.data?.servers ?? [], search);
  const groups = services
    ? groupByServer(services, nodes, {
        showSystem: false,
        query: "",
        notRunning: false,
      }).filter((group) => group.trusted)
    : [];
  const stacks = services ? groupStacks(services, nodes, "") : [];
  const trustById = new Map(
    (services?.nodes ?? []).map((entry) => [entry.id, entry.trust]),
  );
  const restartable = nodes.filter((node) =>
    canRestartServer(node, trustById.get(node.id) ?? null),
  );

  return (
    <CommandDialog
      open={open}
      onOpenChange={close}
      title="Search and Commands"
      description="Jump to a page or a server, or run an action."
    >
      <CommandInput
        placeholder="Search pages, nodes, packages and actions"
        value={search}
        onValueChange={setSearch}
      />
      <CommandList>
        <CommandEmpty>No results.</CommandEmpty>
        <CommandGroup heading="Actions">
          <CommandItem onSelect={() => go("/?enroll=1")}>
            Enroll Server
          </CommandItem>
          <CommandItem onSelect={() => go("/devices")}>
            Trusted Devices
          </CommandItem>
          <CommandItem onSelect={() => go("/checks?add=1")}>
            Add Check
          </CommandItem>
        </CommandGroup>
        <CommandGroup heading="Pages">
          {PAGES.map((section) => (
            <CommandItem key={section.to} onSelect={() => go(section.to)}>
              <section.icon aria-hidden="true" />
              {section.label}
            </CommandItem>
          ))}
        </CommandGroup>
        {restartable.length > 0 && (
          <CommandGroup heading="Servers">
            {restartable.map((node) => (
              <CommandItem
                key={`restart|${node.id}`}
                value={`restart server reboot ${node.name}`}
                onSelect={() => go(`/nodes/${node.id}?restart=1`)}
              >
                Restart server · {node.name}
              </CommandItem>
            ))}
          </CommandGroup>
        )}
        {nodes.length > 0 && (
          <CommandGroup heading="Servers">
            {nodes.map((node) => (
              <CommandItem
                key={node.id}
                value={`node ${node.name} ${node.hostname ?? ""} ${node.id}`}
                onSelect={() => go(`/nodes/${node.id}`)}
              >
                <span className="truncate">{node.name}</span>
                {node.hostname && (
                  <span className="ml-auto font-mono text-xs text-muted-foreground">
                    {node.hostname}
                  </span>
                )}
              </CommandItem>
            ))}
          </CommandGroup>
        )}
        {packages.length > 0 && (
          <CommandGroup heading="Packages">
            {packages.map((entry) => (
              <CommandItem
                key={entry.key}
                value={entry.value}
                onSelect={() => go(entry.to)}
              >
                {entry.label}
              </CommandItem>
            ))}
          </CommandGroup>
        )}
        {groups.length > 0 && (
          <CommandGroup heading="Services">
            {groups.flatMap((group) =>
              group.members.map((member) => {
                const action = primaryAction(member.entry.state);
                const name = displayName(member.entry.kind, member.entry.name);
                return (
                  <CommandItem
                    key={`${member.node.id}|${member.entry.kind}:${member.entry.name}`}
                    value={`service ${verb(action)} ${name} ${member.node.name}`}
                    onSelect={() => {
                      onOpenChange(false);
                      onRun(toTarget(member), action);
                    }}
                  >
                    {verb(action)} {name} · {member.node.name}
                  </CommandItem>
                );
              }),
            )}
          </CommandGroup>
        )}
        {stacks.length > 0 && (
          <CommandGroup heading="Stacks">
            {stacks.flatMap((group) =>
              group.members
                .filter((member) => deployBlocker(member) === null)
                .map((member) => (
                  <CommandItem
                    key={`${group.project}|${member.node.id}`}
                    value={`stack deploy ${group.project} ${member.node.name}`}
                    onSelect={() =>
                      go(
                        `/services?deploy=${encodeURIComponent(group.project)}&node=${member.node.id}`,
                      )
                    }
                  >
                    Deploy {group.project} · {member.node.name}
                  </CommandItem>
                )),
            )}
          </CommandGroup>
        )}
      </CommandList>
    </CommandDialog>
  );
}
