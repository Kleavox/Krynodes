import { useEffect, useState } from "react";
import { useSearchParams } from "react-router";

import { Busy } from "@/components/busy";
import { FilterChips } from "@/components/filter-chips";
import { PageHeader } from "@/components/page-header";
import { StatusDot } from "@/components/status";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  DeployDialog,
  type DeployRequest,
} from "@/features/deploy/deploy-dialog";
import { FailedCard } from "@/features/history/failed-card";
import { HistoryFeed } from "@/features/history/history-feed";
import {
  ActionDialog,
  type ActionRequest,
} from "@/features/services/action-dialog";
import { useHistory, useHistoryAttention, useOverview } from "@/lib/api";
import { dayGroups, readShow } from "@/lib/history";
import type { HistoryShow } from "@/types";

const ALL = "all";

const SHOW_TITLE: Record<HistoryShow, string> = {
  everything: "Everything",
  actions: "Actions",
  incidents: "Incidents",
  failed: "Failed",
};

const EMPTY: Record<HistoryShow, string> = {
  everything: "Nothing Happened",
  actions: "No Actions",
  incidents: "No Incidents",
  failed: "No Failed Actions",
};

export function HistoryPage() {
  const overview = useOverview();
  const attention = useHistoryAttention();
  const [params] = useSearchParams();
  const [node, setNode] = useState(() => params.get("server") ?? ALL);
  const [show, setShow] = useState<HistoryShow>(() =>
    readShow(params.get("show")),
  );
  const [typed, setTyped] = useState("");
  const [q, setQ] = useState("");
  const [request, setRequest] = useState<ActionRequest | null>(null);
  const [deploy, setDeploy] = useState<DeployRequest | null>(null);
  useEffect(() => {
    const timer = setTimeout(() => setQ(typed), 300);
    return () => clearTimeout(timer);
  }, [typed]);
  const history = useHistory({
    node: node === ALL ? undefined : node,
    show,
    q,
  });
  const nodes = (overview.data?.nodes ?? []).filter(
    (entry) => entry.enrolled_at !== null,
  );
  const names = new Map(nodes.map((entry) => [entry.id, entry.name]));
  const items = (attention.data?.items ?? []).filter(
    (item) =>
      names.has(item.action.nodeId) &&
      (node === ALL || item.action.nodeId === node),
  );
  const entries = (history.data?.pages ?? [])
    .flatMap((page) => page.entries)
    .filter(
      (entry) =>
        entry.type === "network" ||
        names.has(
          entry.type === "action" ? entry.action.nodeId : entry.incident.nodeId,
        ),
    );
  const groups = dayGroups(entries, Date.now());
  const where = node === ALL ? "" : ` on ${names.get(node) ?? "this server"}`;

  return (
    <>
      <PageHeader
        title="History"
        meta={
          <span className="font-mono text-xs text-muted-foreground">
            Kept for 90 days
          </span>
        }
      />
      <div className="space-y-5">
        {items.length > 0 ? (
          <section aria-labelledby="not-fixed" className="space-y-2">
            <h2
              id="not-fixed"
              className="text-xs font-medium text-muted-foreground"
            >
              Failed, not fixed · {items.length}
            </h2>
            {items.map((item) => (
              <FailedCard
                key={item.action.id}
                item={item}
                nodes={nodes}
                onRequest={setRequest}
                onDeploy={setDeploy}
              />
            ))}
          </section>
        ) : (
          attention.data && (
            <p className="flex items-center gap-2 rounded-lg border bg-card px-3 py-2.5 text-sm text-muted-foreground">
              <StatusDot tone="ok" />
              Every failed action is fixed or hidden.
            </p>
          )
        )}
        <section aria-labelledby="everything" className="space-y-2">
          <h2
            id="everything"
            className="text-xs font-medium text-muted-foreground"
          >
            {SHOW_TITLE[show]}
          </h2>
          <div className="flex flex-wrap items-center gap-2">
            <Input
              type="search"
              value={typed}
              onChange={(event) => setTyped(event.target.value)}
              placeholder="Search names, servers or ports"
              aria-label="Search history"
              className="h-9 w-full sm:w-64 md:h-8"
            />
            <Select value={node} onValueChange={setNode}>
              <SelectTrigger
                aria-label="Server"
                className="h-9 w-full sm:w-44 md:h-8"
              >
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={ALL}>All Servers</SelectItem>
                {nodes.map((entry) => (
                  <SelectItem key={entry.id} value={entry.id}>
                    {entry.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <FilterChips
              label="Show"
              value={show}
              onChange={(value) => setShow(value)}
              options={[
                { value: "everything", label: "Everything" },
                { value: "actions", label: "Actions" },
                { value: "incidents", label: "Incidents" },
                {
                  value: "failed",
                  label: items.length > 0 ? `Failed ${items.length}` : "Failed",
                },
              ]}
            />
          </div>
          {groups.length === 0 ? (
            <p className="rounded-lg border border-dashed p-4 text-sm text-muted-foreground">
              {history.isPending ? (
                <Busy>Loading History</Busy>
              ) : q ? (
                `Nothing${where} matches ${q}. Search another word.`
              ) : (
                `${EMPTY[show]}${where} in the last 90 days.`
              )}
            </p>
          ) : (
            <HistoryFeed
              groups={groups}
              names={names}
              showServer={node === ALL}
            />
          )}
          {history.hasNextPage && (
            <div className="flex justify-center">
              <Button
                variant="outline"
                size="sm"
                className="h-9 md:h-8"
                disabled={history.isFetchingNextPage}
                onClick={() => void history.fetchNextPage()}
              >
                {history.isFetchingNextPage ? (
                  <Busy>Loading</Busy>
                ) : (
                  "Load Older"
                )}
              </Button>
            </div>
          )}
        </section>
      </div>
      <DeployDialog
        request={deploy}
        seen={overview.dataUpdatedAt}
        onClose={() => setDeploy(null)}
      />
      <ActionDialog request={request} onClose={() => setRequest(null)} />
    </>
  );
}
