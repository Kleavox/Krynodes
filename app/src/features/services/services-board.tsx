import { useState } from "react";
import { Link, useSearchParams } from "react-router";

import { Button } from "@/components/ui/button";
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
import {
  foldedText,
  removedStacks,
  serverBoxes,
  type KindFilter,
} from "@/lib/stacks";
import type { NodeRecord } from "@/types";

import type { ActionRequest } from "./action-dialog";
import { ServiceRows } from "./service-list";

const KINDS: { value: KindFilter; label: string }[] = [
  { value: "all", label: "All Kinds" },
  { value: "stack", label: "Stacks" },
  { value: "docker", label: "Containers" },
  { value: "systemd", label: "Systemd" },
];

export function ServicesBoard({
  nodes,
  seen,
  onRequest,
  onDeploy,
}: {
  nodes: NodeRecord[];
  seen: number;
  onRequest: (request: ActionRequest) => void;
  onDeploy: (request: DeployRequest) => void;
}) {
  const services = useServices();
  const [params, setParams] = useSearchParams();
  const [query, setQuery] = useState(() => params.get("q") ?? "");
  const [showRemoved, setShowRemoved] = useState(false);
  if (!services.data) return null;
  const data = services.data;
  const showSystem = params.get("system") === "1";
  const kind =
    KINDS.find((item) => item.value === params.get("kind"))?.value ?? "all";
  const boxes = serverBoxes(data, nodes, { query, kind, showSystem });
  const removed = removedStacks(data, nodes, query);
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
  const now = Date.now();
  const lockOf = (node: NodeRecord) =>
    serverOperation(node, data.actions, now)?.kind === "restarting"
      ? `Waiting for ${node.name} to come back`
      : undefined;

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <Input
          type="search"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Search names or servers"
          aria-label="Search services"
          className="h-9 w-full sm:w-56 md:h-8"
        />
        <Select
          value={kind}
          onValueChange={(value) =>
            setParam("kind", value === "all" ? null : value)
          }
        >
          <SelectTrigger
            aria-label="Kind"
            className="h-9 w-full sm:w-36 md:h-8"
          >
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {KINDS.map((item) => (
              <SelectItem key={item.value} value={item.value}>
                {item.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
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
            System Services
          </Label>
        </div>
      </div>
      {boxes.length === 0 ? (
        <p className="rounded-lg border border-dashed p-4 text-sm text-muted-foreground">
          {query || kind !== "all"
            ? "Nothing matches. Change the search or the kind to see the rest."
            : "Nothing reported yet. New stack starts one."}
        </p>
      ) : (
        boxes.map((box) => {
          const locked = lockOf(box.node);
          return (
            <section
              key={box.node.id}
              aria-label={box.node.name}
              className="divide-y rounded-lg border bg-card"
            >
              <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1 px-3 py-2">
                <h2 className="text-sm font-medium">{box.node.name}</h2>
                <span className="font-mono text-xs text-muted-foreground">
                  {box.count}
                </span>
                <Link
                  to={`/nodes/${box.node.id}`}
                  className="ml-auto font-mono text-xs text-primary underline-offset-4 hover:underline"
                >
                  Open Server →
                </Link>
              </div>
              {box.stacks.length > 0 && (
                <ul className="divide-y">
                  {box.stacks.map((item) => (
                    <StackRow
                      key={item.member.stack.project}
                      item={item}
                      seen={seen}
                      locked={locked}
                      onRequest={onRequest}
                      onDeploy={onDeploy}
                    />
                  ))}
                </ul>
              )}
              {box.members.length > 0 && (
                <ServiceRows
                  members={box.members}
                  seen={seen}
                  trusted={box.trusted}
                  locked={locked}
                  onRequest={onRequest}
                />
              )}
              {box.folded > 0 && (
                <button
                  type="button"
                  className="block w-full px-3 py-2 text-left font-mono text-xs text-muted-foreground hover:text-foreground"
                  onClick={() => setParam("system", "1")}
                >
                  {foldedText(box.folded)}
                </button>
              )}
            </section>
          );
        })
      )}
      {removed.length > 0 && (
        <div className="space-y-2">
          <Button
            variant="link"
            size="sm"
            className="h-auto px-0 font-mono text-xs text-muted-foreground"
            aria-expanded={showRemoved}
            onClick={() => setShowRemoved(!showRemoved)}
          >
            Removed {removed.length}
          </Button>
          {showRemoved && <RemovedList items={removed} seen={seen} />}
        </div>
      )}
    </div>
  );
}
