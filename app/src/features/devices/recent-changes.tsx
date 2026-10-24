import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useChangeHistory, useServices } from "@/lib/api";
import { appliedOn } from "@/lib/devices";
import { cn } from "@/lib/utils";
import type { ChangeEntry } from "@/types";

import { plural, when } from "./parts";
import type { Fleet } from "./use-fleet";

const DAY_MS = 24 * 3_600_000;

const STATUS: Record<ChangeEntry["status"], string> = {
  applied: "Applied",
  expired: "Expired",
  cancelled: "Cancelled",
  superseded: "Replaced",
};

function ChangeRow({ fleet, entry }: { fleet: Fleet; entry: ChangeEntry }) {
  const services = useServices();
  const applied = entry.status === "applied";
  const { done, total } = appliedOn(fleet.view, entry);
  const recent = Date.now() - Date.parse(entry.closedAt) < DAY_MS;
  const refused = recent
    ? (services.data?.actions ?? []).filter(
        (action) =>
          action.kind === "trust" &&
          action.status === "failed" &&
          entry.targets.includes(action.nodeId) &&
          action.requestedAt >= entry.closedAt,
      )
    : [];
  const people = [
    `Opened by ${entry.openedBy}`,
    entry.approvedBy.length > 0
      ? `approved by ${entry.approvedBy.join(", ")}`
      : null,
    when(entry.closedAt),
  ].filter(Boolean);
  return (
    <li className="grid grid-cols-[minmax(0,1fr)_auto] items-start gap-x-3 gap-y-1 px-4 py-3 text-sm">
      <p className="min-w-0 break-words">{entry.title || "Refresh Servers"}</p>
      <Badge
        variant="outline"
        className={cn(
          "font-normal",
          applied ? "text-success" : "text-muted-foreground",
        )}
      >
        {STATUS[entry.status]}
      </Badge>
      <p className="col-span-2 font-mono text-xs break-words text-muted-foreground">
        {people.join(" · ")}
      </p>
      {applied && done < total && (
        <p className="col-span-2 font-mono text-xs text-warning">
          Applied on {done} of {plural(total, "server")}
        </p>
      )}
      {refused.map((action) => (
        <p key={action.id} className="col-span-2 text-xs text-destructive">
          Refused on{" "}
          {fleet.servers.find((server) => server.node.id === action.nodeId)
            ?.node.name ?? "a server"}
          : {action.output ?? "no reason given"}
        </p>
      ))}
    </li>
  );
}

export function RecentChanges({ fleet }: { fleet: Fleet }) {
  const history = useChangeHistory();
  const changes = history.data?.pages.flatMap((page) => page.changes) ?? [];
  return (
    <section
      aria-labelledby="changes-heading"
      className="mt-5 rounded-lg border bg-card"
    >
      <div className="flex min-h-12 items-center border-b px-4">
        <h2 id="changes-heading" className="text-sm font-medium">
          Recent Changes
        </h2>
      </div>
      {changes.length === 0 ? (
        <p className="px-4 py-3 text-sm text-muted-foreground">
          {history.isPending ? "Loading changes…" : "No changes yet."}
        </p>
      ) : (
        <ul className="divide-y">
          {changes.map((entry) => (
            <ChangeRow key={entry.id} fleet={fleet} entry={entry} />
          ))}
        </ul>
      )}
      <div className="flex min-h-12 flex-wrap items-center gap-3 border-t px-4 py-2 text-xs text-muted-foreground">
        <span>Changes are kept for a year.</span>
        {history.hasNextPage && (
          <Button
            variant="outline"
            size="sm"
            className="ml-auto h-9 md:h-8"
            disabled={history.isFetchingNextPage}
            onClick={() => void history.fetchNextPage()}
          >
            {history.isFetchingNextPage ? "Loading…" : "Show Older"}
          </Button>
        )}
      </div>
    </section>
  );
}
