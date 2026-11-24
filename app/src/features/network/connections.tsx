import type { NetworkDocument, NetworkRule } from "@krynodes/protocol";

import { RowMenu } from "@/components/row-menu";
import { Button } from "@/components/ui/button";
import {
  describeRule,
  namesOf,
  OPEN_CONNECTIONS_LINE,
  reachOf,
  serversOf,
} from "@/lib/rules";

export function Connections({
  document,
  onAdd,
  onEdit,
  onDelete,
}: {
  document: NetworkDocument;
  onAdd: () => void;
  onEdit: (index: number, rule: NetworkRule) => void;
  onDelete: (index: number, rule: NetworkRule) => void;
}) {
  const names = namesOf(document);
  return (
    <section className="space-y-3">
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="font-medium">Connections</h2>
        <Button className="ml-auto" size="sm" variant="outline" onClick={onAdd}>
          Add Rule
        </Button>
      </div>
      {document.allow.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          There are no rules yet. No machine can connect to a server.
        </p>
      ) : (
        <ul className="divide-y rounded-lg border bg-card">
          {document.allow.map((rule, index) => (
            <li key={index} className="flex items-center gap-3 px-4 py-3">
              <p className="min-w-0 flex-1 text-sm">
                {describeRule(rule, names)}
              </p>
              <RowMenu
                label={`Actions for rule ${index + 1}`}
                items={[
                  { label: "Edit", onSelect: () => onEdit(index, rule) },
                  {
                    label: "Delete",
                    destructive: true,
                    onSelect: () => onDelete(index, rule),
                  },
                ]}
              />
            </li>
          ))}
        </ul>
      )}
      <p className="text-sm text-muted-foreground">{OPEN_CONNECTIONS_LINE}</p>
      <div className="grid gap-3 sm:grid-cols-2">
        {serversOf(document).map((server) => {
          const reach = reachOf(server.node, document);
          return (
            <div
              key={server.node}
              className="space-y-2 rounded-lg border bg-card p-4"
            >
              <h3 className="text-sm font-medium">{`Who can reach ${server.name}`}</h3>
              {reach.length === 0 ? (
                <p className="text-sm text-muted-foreground">No rules</p>
              ) : (
                <ul className="space-y-1 text-sm">
                  {reach.map((one) => (
                    <li
                      key={one.from}
                      className="flex flex-wrap justify-between gap-x-3"
                    >
                      <span>{one.from}</span>
                      <span className="font-mono text-xs text-muted-foreground">
                        {one.ports}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          );
        })}
      </div>
    </section>
  );
}
