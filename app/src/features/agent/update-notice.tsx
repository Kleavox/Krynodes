import { CircleArrowUp } from "lucide-react";

import { Button } from "@/components/ui/button";
import { useCheckAgentRelease, useRequestAgentUpdate } from "@/lib/api";
import { agentState } from "@/lib/agent";
import { timeAgo } from "@/lib/format";
import type { AgentRelease, NodeRecord } from "@/types";

export function UpdateNotice({
  nodes,
  release,
  now,
  onShow,
}: {
  nodes: NodeRecord[];
  release: AgentRelease;
  now: number;
  onShow: () => void;
}) {
  const request = useRequestAgentUpdate();
  const states = nodes.map((node) => ({
    node,
    state: agentState(node, release.version, now),
  }));
  const remote = states.filter((item) => item.state === "available");
  const behind = states.filter((item) =>
    ["available", "failed", "unsupported"].includes(item.state),
  );
  const updating = states.filter((item) => item.state === "updating").length;

  if (behind.length === 0) return null;

  return (
    <div
      role="status"
      className="mb-4 flex flex-wrap items-center gap-3 rounded-lg border border-primary/30 bg-primary/5 px-3 py-2.5"
    >
      <CircleArrowUp
        aria-hidden="true"
        className="size-4 shrink-0 text-primary"
      />
      <p className="min-w-0 flex-1 text-sm">
        Agent <span className="font-mono">{release.version}</span> is available
        <span className="text-muted-foreground">
          {" "}
          · {behind.length} {behind.length === 1 ? "server" : "servers"} behind
          {updating > 0 && ` · ${updating} updating`}
        </span>
      </p>
      <div className="flex gap-2">
        <Button variant="ghost" size="sm" onClick={onShow}>
          Show
        </Button>
        {remote.length > 0 && (
          <Button
            size="sm"
            disabled={request.isPending}
            onClick={() => {
              void Promise.allSettled(
                remote.map((item) => request.mutateAsync(item.node.id)),
              );
            }}
          >
            {remote.length === 1 ? "Update" : `Update ${remote.length}`}
          </Button>
        )}
      </div>
    </div>
  );
}

export function LatestAgent({
  release,
  now,
}: {
  release: AgentRelease;
  now: number;
}) {
  const check = useCheckAgentRelease();
  return (
    <span
      className="flex items-center gap-2 font-mono text-[11px] whitespace-nowrap text-muted-foreground"
      title={
        release.checkedAt
          ? `Checked ${timeAgo(release.checkedAt, now)}`
          : undefined
      }
    >
      {release.version ? `Latest ${release.version}` : "No Release Checked"}
      <button
        type="button"
        onClick={() => check.mutate()}
        disabled={check.isPending}
        className="rounded-sm text-primary underline-offset-4 hover:underline disabled:opacity-50"
      >
        {check.isPending ? "Checking…" : "Check"}
      </button>
    </span>
  );
}
