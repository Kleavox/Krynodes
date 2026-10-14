import { useState, type ReactNode } from "react";
import { useSearchParams } from "react-router";

import { FilterChips } from "@/components/filter-chips";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import type { DeployRequest } from "@/features/deploy/deploy-dialog";
import { RemovedList } from "@/features/deploy/removed-list";
import { StackRow } from "@/features/deploy/stack-list";
import { useServices } from "@/lib/api";
import { serverOperation } from "@/lib/operations";
import { removedStacks, serviceBoard } from "@/lib/stacks";
import { cn } from "@/lib/utils";
import type { NodeRecord } from "@/types";

import type { ActionRequest } from "./action-dialog";
import { ServiceRows } from "./service-list";

type Tab = "stacks" | "containers" | "systemd" | "removed";

const TABS: { value: Tab; label: string }[] = [
  { value: "stacks", label: "Stacks" },
  { value: "containers", label: "Containers" },
  { value: "systemd", label: "Systemd" },
  { value: "removed", label: "Removed" },
];

const EMPTY: Record<Tab, string> = {
  stacks: "No Compose stacks here. New stack starts one.",
  containers: "No Docker containers outside a stack.",
  systemd: "No systemd services reported.",
  removed: "Nothing waits in Removed.",
};

const ALL = "all";

export function ServicesBoard({
  nodes,
  single = false,
  seen,
  onRequest,
  onDeploy,
}: {
  nodes: NodeRecord[];
  single?: boolean;
  seen: number;
  onRequest: (request: ActionRequest) => void;
  onDeploy: (request: DeployRequest) => void;
}) {
  const services = useServices();
  const [params, setParams] = useSearchParams();
  const [query, setQuery] = useState("");
  if (!services.data) return null;
  const data = services.data;
  const notRunning = params.get("state") === "down";
  const showSystem = params.get("system") === "1";
  const serverId = single ? null : params.get("server");
  const shown = serverId ? nodes.filter((node) => node.id === serverId) : nodes;
  const options = { showSystem, query, notRunning: false };
  const all = serviceBoard(data, shown, options);
  const down = serviceBoard(data, shown, { ...options, notRunning: true });
  const board = notRunning ? down : all;
  const removed = removedStacks(data, shown, query);
  const total: Record<Tab, number> = {
    stacks: all.stacks.length,
    containers: all.containers.length,
    systemd: all.units.length,
    removed: removed.length,
  };
  const hurt: Record<Tab, boolean> = {
    stacks: down.stacks.length > 0,
    containers: down.containers.length > 0,
    systemd: down.units.length > 0,
    removed: false,
  };
  const asked = TABS.find((item) => item.value === params.get("tab"))?.value;
  const tab: Tab =
    asked ??
    (["stacks", "containers", "systemd"] as const).find(
      (value) => total[value] > 0,
    ) ??
    "stacks";
  const tabs = TABS.filter(
    (item) =>
      item.value !== "removed" || removed.length > 0 || tab === "removed",
  );
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
  const trusted = (member: { node: { id: string } }) =>
    board.trusted.has(member.node.id);
  const now = Date.now();
  const locked = (member: { node: NodeRecord }) =>
    serverOperation(member.node, data.actions, now)?.kind === "restarting"
      ? `Waiting for ${member.node.name} to come back`
      : undefined;

  let list: ReactNode;
  if (tab === "removed") {
    list = <RemovedList items={removed} seen={seen} showServer={!single} />;
  } else if (tab === "stacks" && board.stacks.length > 0) {
    list = (
      <ul className="divide-y rounded-lg border bg-card">
        {board.stacks.map((item) => (
          <StackRow
            key={`${item.member.node.id}|${item.member.stack.project}`}
            item={item}
            seen={seen}
            showServer={!single}
            locked={locked(item.member)}
            onRequest={onRequest}
            onDeploy={onDeploy}
          />
        ))}
      </ul>
    );
  } else if (tab !== "stacks") {
    const members = tab === "containers" ? board.containers : board.units;
    list =
      members.length > 0 ? (
        <div className="rounded-lg border bg-card">
          <ServiceRows
            members={members}
            seen={seen}
            trusted={trusted}
            showServer={!single}
            locked={locked}
            onRequest={onRequest}
          />
        </div>
      ) : null;
  }

  return (
    <div className="space-y-3">
      <div
        role="tablist"
        aria-label="Kind of service"
        className="flex gap-1 overflow-x-auto border-b max-sm:gap-0"
      >
        {tabs.map((item) => (
          <button
            key={item.value}
            type="button"
            role="tab"
            aria-selected={tab === item.value}
            onClick={() => setParam("tab", item.value)}
            className={cn(
              "-mb-px flex h-9 shrink-0 items-center gap-1.5 border-b-2 border-transparent px-2.5 text-sm max-sm:px-1.5 text-muted-foreground hover:text-foreground",
              tab === item.value && "border-primary text-foreground",
            )}
          >
            {item.label}
            <span className="font-mono text-xs text-muted-foreground">
              {total[item.value]}
            </span>
            {hurt[item.value] && (
              <>
                <span
                  aria-hidden="true"
                  className="size-1.5 rounded-full bg-destructive"
                />
                <span className="sr-only">, something is not running</span>
              </>
            )}
          </button>
        ))}
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <Input
          type="search"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder={single ? "Search" : "Search names or servers"}
          aria-label="Search services"
          className="h-9 w-full sm:w-56 md:h-8"
        />
        {!single && nodes.length > 1 && (
          <Select
            value={serverId ?? ALL}
            onValueChange={(value) =>
              setParam("server", value === ALL ? null : value)
            }
          >
            <SelectTrigger
              aria-label="Server"
              className="h-9 w-full sm:w-44 md:h-8"
            >
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={ALL}>All servers</SelectItem>
              {nodes.map((node) => (
                <SelectItem key={node.id} value={node.id}>
                  {node.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
        {tab !== "removed" && (
          <FilterChips
            label="Filter by state"
            value={notRunning ? "down" : "all"}
            onChange={(value) =>
              setParam("state", value === "all" ? null : value)
            }
            options={[
              { value: "all", label: "All" },
              { value: "down", label: "Not running" },
            ]}
          />
        )}
        {tab === "systemd" && (
          <div className="flex items-center gap-2">
            <Switch
              id={single ? "node-system-services" : "system-services"}
              checked={showSystem}
              onCheckedChange={(checked) =>
                setParam("system", checked ? "1" : null)
              }
            />
            <Label
              htmlFor={single ? "node-system-services" : "system-services"}
              className="text-xs text-muted-foreground"
            >
              System services
            </Label>
          </div>
        )}
      </div>
      <div
        role="tabpanel"
        aria-label={TABS.find((item) => item.value === tab)?.label}
      >
        {list ?? (
          <p className="rounded-lg border border-dashed p-4 text-sm text-muted-foreground">
            {query || notRunning
              ? "Nothing matches. Change the search or the filter to see the rest."
              : EMPTY[tab]}
          </p>
        )}
      </div>
    </div>
  );
}
