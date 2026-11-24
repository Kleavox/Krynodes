import { RowMenu } from "@/components/row-menu";
import { Badge } from "@/components/ui/badge";
import { canExit, memberRow } from "@/lib/network";
import type { FleetNode, NetworkView } from "@/types";

type Member = NetworkView["members"][number];

export type MemberAsk = "exit" | "test" | "keys" | "remove";

export function memberActions(
  member: Member,
  exit: string | null | undefined,
): {
  label: string;
  ask: MemberAsk;
  destructive?: boolean;
  disabled?: boolean;
}[] {
  const server = member.kind !== "laptop";
  const waiting = exit === undefined;
  return [
    ...(exit === member.node || canExit(member)
      ? [
          {
            label: "Exit Node for Laptops",
            ask: "exit" as const,
            disabled: waiting,
          },
        ]
      : []),
    ...(server
      ? [
          { label: "Test Link", ask: "test" as const },
          { label: "New Keys", ask: "keys" as const, disabled: waiting },
        ]
      : []),
    { label: "Remove from Network", ask: "remove", destructive: true },
  ];
}

export function MemberList({
  view,
  nodes,
  exit,
  onAsk,
}: {
  view: NetworkView;
  nodes: FleetNode[];
  exit: string | null | undefined;
  onAsk: (member: Member, ask: MemberAsk) => void;
}) {
  return (
    <section className="space-y-2">
      <h2 className="font-medium">Members</h2>
      {view.members.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          No machine is in the private network.
        </p>
      ) : (
        <ul className="divide-y rounded-lg border bg-card">
          {view.members.map((member) => {
            const row = memberRow(
              view,
              nodes.find((node) => node.id === member.node) ?? {
                id: member.node,
                via: null,
                ms: null,
              },
            )!;
            return (
              <li
                key={member.node}
                className="flex items-center gap-3 px-4 py-3"
              >
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                    <span className="truncate font-medium">{member.name}</span>
                    <Badge variant="outline">
                      {member.kind === "laptop" ? "Laptop" : "Server"}
                    </Badge>
                    {exit === member.node && (
                      <Badge variant="secondary">Exit Node</Badge>
                    )}
                    {member.state === "leaving" && (
                      <Badge variant="secondary">Leaving</Badge>
                    )}
                  </div>
                  <p className="mt-1 flex flex-wrap gap-x-3 text-xs text-muted-foreground">
                    <span className="font-mono">{row.address}</span>
                    <span>{row.path}</span>
                    <span>{row.ms}</span>
                    <span
                      className={
                        member.failure ? "text-destructive" : undefined
                      }
                    >
                      {row.state}
                    </span>
                  </p>
                </div>
                <RowMenu
                  label={`Actions for ${member.name}`}
                  items={memberActions(member, exit).map((item) => ({
                    label: item.label,
                    destructive: item.destructive,
                    onSelect: item.disabled
                      ? undefined
                      : () => onAsk(member, item.ask),
                  }))}
                />
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
