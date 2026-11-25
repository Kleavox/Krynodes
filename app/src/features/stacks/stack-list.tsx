import { useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ActionDialog } from "@/features/actions/action-dialog";
import { useRefreshStacks } from "@/lib/api";
import { stackLine } from "@/lib/stacks";
import { cn } from "@/lib/utils";
import type { FleetNode, StackNode } from "@/types";

import { RemovedList } from "./removed-list";
import { ServicesList } from "./services-list";
import { installDocker, StackMenu } from "./stack-menu";

function DockerLine({
  entry,
  node,
}: {
  entry: StackNode;
  node: FleetNode | undefined;
}) {
  const [installing, setInstalling] = useState(false);
  const refresh = useRefreshStacks();
  if (entry.docker === null) {
    return (
      <p className="text-sm text-muted-foreground">
        {entry.name} has not reported Docker yet.
      </p>
    );
  }
  if (entry.docker === "stopped") {
    return (
      <p className="text-sm text-muted-foreground">
        Docker is installed on {entry.name} but not running.
      </p>
    );
  }
  if (entry.docker === "ready") return null;
  const install = installDocker(entry);
  return (
    <div className="flex flex-wrap items-center gap-3">
      <p className="text-sm text-muted-foreground">Docker is not installed.</p>
      <Button
        size="sm"
        variant="outline"
        disabled={!entry.online || !node}
        onClick={() => setInstalling(true)}
      >
        Install Docker
      </Button>
      {installing && node && install.ask && (
        <ActionDialog
          node={node}
          ask={install.ask}
          onClose={() => setInstalling(false)}
          onDone={refresh}
        />
      )}
    </div>
  );
}

export function StackSection({
  entry,
  node,
  servers,
}: {
  entry: StackNode;
  node: FleetNode | undefined;
  servers: StackNode[];
}) {
  return (
    <section
      aria-label={entry.name}
      className={cn("space-y-2", !entry.online && "opacity-60")}
    >
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="font-medium">{entry.name}</h2>
        {!entry.online && <Badge variant="secondary">Offline</Badge>}
        {entry.compose && (
          <span className="font-mono text-xs text-muted-foreground">
            Compose {entry.compose}
          </span>
        )}
      </div>
      <DockerLine entry={entry} node={node} />
      {entry.stacks.length > 0 && (
        <ul className="divide-y rounded-lg border bg-card">
          {entry.stacks.map((stack) => (
            <li
              key={stack.project}
              className="flex items-center gap-3 px-4 py-3"
            >
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                  <span className="truncate font-medium">
                    {stack.title ?? stack.project}
                  </span>
                  {stack.title && (
                    <span className="font-mono text-xs text-muted-foreground">
                      {stack.project}
                    </span>
                  )}
                  {!stack.own ? (
                    <Badge variant="outline">Not Managed</Badge>
                  ) : (
                    stack.access === "full" && (
                      <Badge variant="outline">Full Access</Badge>
                    )
                  )}
                </div>
                <p className="mt-1 flex flex-wrap gap-x-3 text-xs text-muted-foreground">
                  <span>{entry.online ? stackLine(stack) : "--"}</span>
                  {stack.network.length > 0 && (
                    <span>Private Network {stack.network.join(", ")}</span>
                  )}
                </p>
              </div>
              <StackMenu
                entry={entry}
                stack={stack}
                node={node}
                servers={servers}
              />
            </li>
          ))}
        </ul>
      )}
      {entry.docker === "ready" && entry.stacks.length === 0 && (
        <p className="text-sm text-muted-foreground">No stacks yet.</p>
      )}
      <RemovedList entry={entry} node={node} />
      <ServicesList entry={entry} node={node} />
    </section>
  );
}
