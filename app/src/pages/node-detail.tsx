import { Link, useNavigate, useParams, useSearchParams } from "react-router";

import { DockerMark } from "@/components/docker-mark";
import { EmptyState } from "@/components/empty-state";
import { NodeStatus } from "@/components/node-status";
import { PageHeader } from "@/components/page-header";
import { SecurityMark } from "@/components/security-mark";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { MachineTiles, readRange } from "@/features/nodes/machine-tiles";
import { NodeActions } from "@/features/nodes/node-actions";
import { SecurityPanel } from "@/features/nodes/security-panel";
import { ThisServer } from "@/features/nodes/this-server";
import { WhatRuns } from "@/features/nodes/what-runs";
import { RecentActions } from "@/features/services/node-sections";
import { useDevices, useOverview, useServices } from "@/lib/api";
import { nodeState, timeAgo } from "@/lib/format";
import { systemFacts } from "@/lib/node-facts";
import { serverOperation } from "@/lib/operations";
import { useNow } from "@/lib/use-now";

export function NodeDetailPage() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const range = readRange(params.get("range"));
  const overview = useOverview();
  const services = useServices();
  const devices = useDevices();
  const now = useNow(5_000);

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

  if (!overview.data) {
    return (
      <>
        <PageHeader title="Server" />
        <Skeleton className="h-96" />
      </>
    );
  }

  const node = overview.data.nodes.find((item) => item.id === id);
  if (!node) {
    return (
      <EmptyState
        title="Server Not Found"
        body="It may have been deleted."
        action={
          <Button asChild variant="outline">
            <Link to="/">Back to Fleet</Link>
          </Button>
        }
      />
    );
  }

  const seen = overview.dataUpdatedAt;

  return (
    <>
      <PageHeader
        crumb={
          <>
            <Link to="/" className="hover:underline">
              Fleet
            </Link>{" "}
            / {node.name}
          </>
        }
        title={node.name}
        meta={
          <span className="flex items-center gap-2">
            <NodeStatus
              state={nodeState(node, seen)}
              operation={serverOperation(
                node,
                services.data?.actions ?? [],
                now,
                devices.data?.devices,
              )}
              offlineDetail={`Reported ${timeAgo(node.last_seen_at, now)}`}
            />
            <DockerMark nodeId={node.id} />
            <SecurityMark nodeId={node.id} />
          </span>
        }
        actions={
          <NodeActions
            node={node}
            onDeleted={() => void navigate("/", { replace: true })}
            restart={params.get("restart") === "1"}
            onRestartClosed={() => setParam("restart", null)}
          />
        }
      />

      <p className="-mt-3 mb-5 font-mono text-[11px] text-muted-foreground">
        {systemFacts(node)}
      </p>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-[minmax(0,1fr)_340px] lg:items-start">
        <div className="min-w-0 lg:col-start-1 lg:row-start-1">
          <WhatRuns node={node} seen={seen} />
        </div>
        <aside className="min-w-0 space-y-6 lg:col-start-2 lg:row-span-2 lg:row-start-1">
          <MachineTiles
            node={node}
            range={range}
            onRange={(value) => setParam("range", value)}
          />
          <SecurityPanel node={node} seen={seen} />
          <ThisServer
            node={node}
            release={overview.data.agentRelease}
            now={now}
          />
        </aside>
        <div className="min-w-0 lg:col-start-1 lg:row-start-2">
          <RecentActions node={node} />
        </div>
      </div>
    </>
  );
}
