import { Link } from "react-router";

import { Busy } from "@/components/busy";
import { useNodeActions } from "@/lib/api";
import type { NodeRecord } from "@/types";

import { ActionLine } from "./action-line";

const RECENT = 6;

export function RecentActions({ node }: { node: NodeRecord }) {
  const actions = useNodeActions(node.id);
  const list = (actions.data?.actions ?? []).slice(0, RECENT);
  const now = Date.now();
  return (
    <section aria-labelledby="node-recent-actions">
      <div className="mb-2 flex min-h-8 items-center gap-2">
        <h2
          id="node-recent-actions"
          className="text-xs font-medium text-muted-foreground"
        >
          Recent Actions
        </h2>
        <Link
          to={`/history?server=${encodeURIComponent(node.id)}`}
          className="ml-auto font-mono text-xs text-primary underline-offset-4 hover:underline"
        >
          All in History →
        </Link>
      </div>
      {list.length === 0 ? (
        <p className="rounded-lg border border-dashed p-4 text-sm text-muted-foreground">
          {actions.data ? "No actions yet." : <Busy>Loading actions</Busy>}
        </p>
      ) : (
        <ul className="divide-y rounded-lg border bg-card">
          {list.map((action) => (
            <ActionLine
              key={action.id}
              action={action}
              nodeName={node.name}
              now={now}
            />
          ))}
        </ul>
      )}
    </section>
  );
}
