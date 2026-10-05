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
import { canRestartServer } from "@/lib/devices";
import { deployBlocker, groupStacks } from "@/lib/stacks";
import type { NodeRecord, ServiceAction, ServicesResponse } from "@/types";

import { SECTIONS } from "./nav";

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
  const go = (to: string) => {
    onOpenChange(false);
    void navigate(to);
  };
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
      onOpenChange={onOpenChange}
      title="Search and commands"
      description="Jump to a page or a node, or run an action."
    >
      <CommandInput placeholder="Search pages, nodes and actions" />
      <CommandList>
        <CommandEmpty>No results.</CommandEmpty>
        <CommandGroup heading="Actions">
          <CommandItem onSelect={() => go("/?enroll=1")}>
            Enroll node
          </CommandItem>
          <CommandItem onSelect={() => go("/devices")}>
            Trusted devices
          </CommandItem>
          <CommandItem onSelect={() => go("/checks?add=1")}>
            Add check
          </CommandItem>
        </CommandGroup>
        <CommandGroup heading="Pages">
          {SECTIONS.map((section) => (
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
          <CommandGroup heading="Nodes">
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
