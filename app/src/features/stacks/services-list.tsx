import type { ContainerEntry, UnitEntry } from "@krynodes/protocol";
import { useState } from "react";

import type { FleetNode, StackNode } from "@/types";

import { LogsDialog } from "./logs-dialog";
import { serviceItems, VerbMenu } from "./stack-menu";

const STATE: Record<string, string> = {
  running: "Running",
  stopped: "Stopped",
  restarting: "Restarting",
  paused: "Paused",
  failed: "Failed",
};

function ContainerRow({
  entry,
  node,
  container,
}: {
  entry: StackNode;
  node: FleetNode | undefined;
  container: ContainerEntry;
}) {
  const [logs, setLogs] = useState(false);
  return (
    <li className="flex items-center gap-3 px-4 py-2">
      <div className="min-w-0 flex-1">
        <p className="truncate font-mono text-sm">{container.name}</p>
        <p className="text-xs text-muted-foreground">
          Container · {entry.online ? STATE[container.state] : "--"} ·{" "}
          {container.image || "--"}
        </p>
      </div>
      <VerbMenu
        label={`Actions for ${container.name}`}
        items={serviceItems(entry, { kind: "container", item: container })}
        node={node}
        onOpen={() => setLogs(true)}
      />
      {logs && node && (
        <LogsDialog
          node={node}
          kind="container"
          name={container.name}
          onClose={() => setLogs(false)}
        />
      )}
    </li>
  );
}

function UnitRow({
  entry,
  node,
  unit,
}: {
  entry: StackNode;
  node: FleetNode | undefined;
  unit: UnitEntry;
}) {
  return (
    <li className="flex items-center gap-3 px-4 py-2">
      <div className="min-w-0 flex-1">
        <p className="truncate font-mono text-sm">{unit.name}</p>
        <p className="text-xs text-muted-foreground">
          Unit · {entry.online ? STATE[unit.state] : "--"}
        </p>
      </div>
      <VerbMenu
        label={`Actions for ${unit.name}`}
        items={serviceItems(entry, { kind: "unit", item: unit })}
        node={node}
      />
    </li>
  );
}

export function ServicesList({
  entry,
  node,
}: {
  entry: StackNode;
  node: FleetNode | undefined;
}) {
  const loose = entry.containers.filter((one) => one.project === null);
  if (loose.length === 0 && entry.units.length === 0) return null;
  return (
    <div className="space-y-1">
      <h3 className="text-sm font-medium">Services</h3>
      <ul className="divide-y rounded-lg border bg-card">
        {loose.map((container) => (
          <ContainerRow
            key={container.name}
            entry={entry}
            node={node}
            container={container}
          />
        ))}
        {entry.units.map((unit) => (
          <UnitRow key={unit.name} entry={entry} node={node} unit={unit} />
        ))}
      </ul>
    </div>
  );
}
