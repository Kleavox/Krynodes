import { useState, type ReactNode } from "react";
import { Link } from "react-router";

import { SmallLabel, StatusDot } from "@/components/status";
import { Button } from "@/components/ui/button";
import { LogsDialog, type LogsTarget } from "@/features/services/logs-dialog";
import { failuresText, incidentLine } from "@/lib/checks";
import { publicLabel } from "@/lib/format";
import type { CheckRecord, Incident, NodeRecord } from "@/types";

import { CheckMenu } from "./check-menu";

export interface DownItem {
  check: CheckRecord;
  node: NodeRecord;
  figure: string;
  incident: Incident | undefined;
  updates: number;
  autoLine: string | null;
  strip: ReactNode;
  restart: (() => void) | undefined;
  logs: LogsTarget | null;
}

export function CheckTags({ check }: { check: CheckRecord }) {
  const shared = publicLabel(check);
  return (
    <>
      {check.auto_restart === 1 && (
        <SmallLabel title="Restarts automatically when this check turns red">
          AUTO
        </SmallLabel>
      )}
      {shared && <SmallLabel>{shared}</SmallLabel>}
    </>
  );
}

function DownRow({ item, nodes }: { item: DownItem; nodes: NodeRecord[] }) {
  const [reading, setReading] = useState(false);
  const { check, node, incident, logs } = item;
  const failures = failuresText(check.consecutive_failures);
  const picked = check.kind === "CONTAINER" || check.kind === "SERVICE";
  return (
    <li className="grid gap-x-3 gap-y-2 px-3 py-2.5 md:grid-cols-[minmax(0,1fr)_minmax(140px,0.7fr)_auto] md:items-center">
      <div className="min-w-0 space-y-0.5">
        <p className="flex flex-wrap items-center gap-x-1.5 gap-y-0.5 text-sm">
          <span className="font-medium">{check.name}</span>
          <SmallLabel>{check.kind}</SmallLabel>
          <span className="font-mono text-xs text-muted-foreground">
            on {node.name}
          </span>
          <CheckTags check={check} />
        </p>
        <p className="font-mono text-xs break-words">
          <span className="text-destructive">
            {check.last_message ?? "Down"}
          </span>
          <span className="text-muted-foreground">
            {" "}
            · {item.figure}
            {failures && ` · ${failures}`}
          </span>
        </p>
        {incident && (
          <Link
            to={`/incidents/${incident.id}`}
            className="block font-mono text-xs text-primary underline-offset-4 hover:underline"
          >
            {incidentLine(item.updates)}
          </Link>
        )}
        {item.autoLine && (
          <p className="font-mono text-xs break-words text-warning">
            {item.autoLine}
          </p>
        )}
      </div>
      {item.strip}
      <div className="flex items-center justify-end gap-1">
        {picked ? (
          <>
            {logs && (
              <Button
                variant="outline"
                size="sm"
                className="h-9 md:h-8"
                aria-label={`Logs of ${check.name}`}
                onClick={() => setReading(true)}
              >
                Logs
              </Button>
            )}
            {item.restart && (
              <Button
                size="sm"
                className="h-9 md:h-8"
                aria-label={`Restart ${check.name}`}
                onClick={item.restart}
              >
                Restart
              </Button>
            )}
          </>
        ) : (
          incident && (
            <Button asChild variant="outline" size="sm" className="h-9 md:h-8">
              <Link to={`/incidents/${incident.id}`}>Open incident</Link>
            </Button>
          )
        )}
        <CheckMenu
          check={check}
          nodes={nodes}
          restart={check.kind === "SERVICE" ? item.restart : undefined}
        />
      </div>
      {logs && (
        <LogsDialog target={logs} open={reading} onOpenChange={setReading} />
      )}
    </li>
  );
}

export function DownBox({
  items,
  nodes,
}: {
  items: DownItem[];
  nodes: NodeRecord[];
}) {
  if (items.length === 0) {
    return (
      <p className="flex items-center gap-2 rounded-lg border bg-card px-3 py-2.5 text-sm text-muted-foreground">
        <StatusDot tone="ok" />
        Nothing is down.
      </p>
    );
  }
  return (
    <section
      aria-labelledby="checks-down"
      className="rounded-lg border border-destructive/40 bg-card"
    >
      <h2
        id="checks-down"
        className="flex items-center gap-2 px-3 py-2.5 text-sm font-medium"
      >
        <StatusDot tone="bad" />
        Down
        <span className="font-mono text-xs font-normal text-muted-foreground">
          {items.length}
        </span>
      </h2>
      <ul className="divide-y border-t">
        {items.map((item) => (
          <DownRow key={item.check.id} item={item} nodes={nodes} />
        ))}
      </ul>
    </section>
  );
}
