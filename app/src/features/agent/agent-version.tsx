import { CircleArrowUp } from "lucide-react";

import { agentState } from "@/lib/agent";
import { cn } from "@/lib/utils";
import type { AgentRelease, NodeRecord } from "@/types";

export function AgentVersion({
  node,
  release,
  now,
  className,
}: {
  node: NodeRecord;
  release: AgentRelease;
  now: number;
  className?: string;
}) {
  const state = agentState(node, release.version, now);
  const version = node.agent_version ?? "--";
  const target = node.update_requested_version ?? release.version;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 font-mono text-[11px] whitespace-nowrap text-muted-foreground",
        className,
      )}
    >
      <span className="sr-only">Agent </span>
      {version}
      {state === "available" && (
        <span
          className="inline-flex items-center gap-0.5 text-primary"
          title={`Agent ${target} is available`}
        >
          <CircleArrowUp aria-hidden="true" className="size-3" />
          <span className="sr-only">update available:</span>
          {target}
        </span>
      )}
      {state === "updating" && (
        <span className="text-primary motion-safe:animate-pulse">
          → {target}
        </span>
      )}
      {state === "failed" && (
        <span className="text-destructive">Update Failed</span>
      )}
      {state === "unsupported" && (
        <span className="text-destructive">Update by Hand</span>
      )}
    </span>
  );
}
