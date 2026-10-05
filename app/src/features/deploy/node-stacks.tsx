import { useState } from "react";

import { useServices } from "@/lib/api";
import { groupStacks, removedStacks } from "@/lib/stacks";
import type { NodeRecord } from "@/types";

import { DeployDialog, type DeployRequest } from "./deploy-dialog";
import { RemovedList } from "./removed-list";
import { StackList } from "./stack-list";

export function NodeStacks({ node, seen }: { node: NodeRecord; seen: number }) {
  const services = useServices();
  const [request, setRequest] = useState<DeployRequest | null>(null);
  if (!services.data) return null;
  const groups = groupStacks(services.data, [node], "");
  const removed = removedStacks(services.data, [node], "");
  if (groups.length === 0 && removed.length === 0) return null;
  const entry = services.data.nodes.find((item) => item.id === node.id);
  return (
    <div className="space-y-6">
      {groups.length > 0 && (
        <section aria-labelledby="node-stacks">
          <div className="mb-2 flex min-h-8 items-center gap-2">
            <h2
              id="node-stacks"
              className="text-[11px] tracking-wider text-muted-foreground uppercase"
            >
              Stacks · {groups.length}
            </h2>
          </div>
          <StackList
            groups={groups}
            seen={seen}
            showServer={false}
            services={new Map([[node.id, entry?.services ?? []]])}
            onRequest={setRequest}
          />
        </section>
      )}
      <RemovedList items={removed} seen={seen} showServer={false} />
      <DeployDialog
        request={request}
        seen={seen}
        onClose={() => setRequest(null)}
      />
    </div>
  );
}
