import { Plus, RefreshCw } from "lucide-react";
import { useState } from "react";
import { Link, useSearchParams } from "react-router";

import { EmptyState } from "@/components/empty-state";
import { FilterChips } from "@/components/filter-chips";
import { PageHeader } from "@/components/page-header";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import {
  DeployDialog,
  type DeployRequest,
} from "@/features/deploy/deploy-dialog";
import { NewStackDialog } from "@/features/deploy/new-stack-dialog";
import { RemovedList } from "@/features/deploy/removed-list";
import { StackList } from "@/features/deploy/stack-list";
import {
  ActionDialog,
  type ActionRequest,
} from "@/features/services/action-dialog";
import { ServerServiceList } from "@/features/services/service-list";
import { useOverview, useRefreshServices, useServices } from "@/lib/api";
import { groupByServer, refreshPending } from "@/lib/services";
import { groupStacks, removedStacks } from "@/lib/stacks";

export function ServicesPage() {
  const overview = useOverview();
  const services = useServices();
  const refresh = useRefreshServices();
  const [params, setParams] = useSearchParams();
  const [query, setQuery] = useState("");
  const [request, setRequest] = useState<ActionRequest | null>(null);
  const [deploy, setDeploy] = useState<DeployRequest | null>(null);
  const [creating, setCreating] = useState(false);
  const stacksView = params.get("view") === "stacks";
  const notRunning = params.get("state") === "down";
  const showSystem = params.get("system") === "1";

  const setParam = (key: string, value: string | null) =>
    setParams(
      (current) => {
        const next = new URLSearchParams(current);
        if (value === null) next.delete(key);
        else next.set(key, value);
        return next;
      },
      { replace: true },
    );

  if (!overview.data || !services.data) {
    return (
      <>
        <PageHeader title="Services" />
        <Skeleton className="h-64" />
      </>
    );
  }

  const nodes = overview.data.nodes.filter((node) => node.enrolled_at !== null);
  const seen = overview.dataUpdatedAt;
  const groups = groupByServer(services.data, nodes, {
    showSystem,
    query,
    notRunning,
  });
  const refreshing = services.data.nodes.some((node) =>
    refreshPending(node, services.dataUpdatedAt),
  );
  const stackGroups = groupStacks(services.data, nodes, query);
  const removed = removedStacks(services.data, nodes, query);
  const linked = params.get("deploy") ?? params.get("rollback");
  const linkedGroup = linked
    ? groupStacks(services.data, nodes, "").find(
        (group) => group.project === linked,
      )
    : undefined;
  const linkedNode = params.get("node");
  const deployRequest: DeployRequest | null =
    deploy ??
    (linkedGroup
      ? {
          action: params.get("rollback") ? "rollback" : "deploy",
          project: linkedGroup.project,
          members: linkedGroup.members.filter(
            (member) => !linkedNode || member.node.id === linkedNode,
          ),
        }
      : null);
  const servicesByNode = new Map(
    services.data.nodes.map((node) => [node.id, node.services]),
  );

  return (
    <>
      <PageHeader
        title="Services"
        actions={
          nodes.length > 0 && (
            <>
              <FilterChips
                label="View"
                value={stacksView ? "stacks" : "services"}
                onChange={(value) =>
                  setParam("view", value === "stacks" ? "stacks" : null)
                }
                options={[
                  { value: "services", label: "Services" },
                  { value: "stacks", label: "Stacks" },
                ]}
              />
              <Input
                type="search"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder={
                  stacksView
                    ? "Search stacks or servers"
                    : "Search services or servers"
                }
                aria-label={
                  stacksView
                    ? "Search stacks or servers"
                    : "Search services or servers"
                }
                className="h-9 w-full md:h-8 md:w-56"
              />
              {!stacksView && (
                <>
                  <FilterChips
                    label="Filter services"
                    value={notRunning ? "down" : "all"}
                    onChange={(value) =>
                      setParam("state", value === "all" ? null : value)
                    }
                    options={[
                      { value: "all", label: "All" },
                      { value: "down", label: "Not running" },
                    ]}
                  />
                  <div className="flex items-center gap-2">
                    <Switch
                      id="system-services"
                      checked={showSystem}
                      onCheckedChange={(checked) =>
                        setParam("system", checked ? "1" : null)
                      }
                    />
                    <Label
                      htmlFor="system-services"
                      className="text-xs text-muted-foreground"
                    >
                      System services
                    </Label>
                  </div>
                </>
              )}
              {stacksView && (
                <Button onClick={() => setCreating(true)}>
                  <Plus aria-hidden="true" />
                  New stack
                </Button>
              )}
              <Button
                variant="outline"
                disabled={refresh.isPending || refreshing}
                onClick={() => refresh.mutate(undefined)}
              >
                <RefreshCw aria-hidden="true" />
                {refreshing ? "Refreshing…" : "Refresh all"}
              </Button>
            </>
          )
        }
      />

      {nodes.length === 0 ? (
        <EmptyState
          title="No servers yet"
          body="Enroll a server from Fleet. Its services appear here within five minutes."
          action={
            <Button asChild>
              <Link to="/">Open Fleet</Link>
            </Button>
          }
        />
      ) : stacksView ? (
        stackGroups.length === 0 && removed.length === 0 ? (
          <EmptyState
            title={query ? "No stacks match" : "No Compose stacks yet"}
            body={
              query
                ? "Change the search to see the rest."
                : "Servers list Docker Compose stacks here once their agent reports them, or start one with New stack."
            }
            action={
              query ? undefined : (
                <Button onClick={() => setCreating(true)}>
                  <Plus aria-hidden="true" />
                  New stack
                </Button>
              )
            }
          />
        ) : (
          <div className="space-y-6">
            {stackGroups.length > 0 && (
              <StackList
                groups={stackGroups}
                seen={seen}
                showServer
                services={servicesByNode}
                onRequest={setDeploy}
              />
            )}
            <RemovedList items={removed} seen={seen} showServer />
          </div>
        )
      ) : groups.length === 0 ? (
        <EmptyState
          title={
            query || notRunning
              ? "No services match"
              : "No services reported yet"
          }
          body={
            query || notRunning
              ? "Change the search or the filter to see the rest."
              : "Agents report their services within five minutes of enrolling. Refresh asks them now."
          }
        />
      ) : (
        <ServerServiceList
          groups={groups}
          actions={services.data.actions}
          seen={seen}
          filtering={query.trim() !== "" || notRunning}
          onRequest={setRequest}
        />
      )}

      <DeployDialog
        request={deployRequest}
        seen={seen}
        onClose={() => {
          setDeploy(null);
          if (linked) {
            setParams(
              (current) => {
                const next = new URLSearchParams(current);
                for (const key of ["deploy", "rollback", "node"])
                  next.delete(key);
                return next;
              },
              { replace: true },
            );
          }
        }}
      />
      <ActionDialog request={request} onClose={() => setRequest(null)} />
      <NewStackDialog
        open={creating}
        onOpenChange={setCreating}
        nodes={nodes}
      />
    </>
  );
}
