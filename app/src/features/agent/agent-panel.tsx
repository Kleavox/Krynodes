import {
  CircleArrowUp,
  CircleCheck,
  CircleX,
  LoaderCircle,
} from "lucide-react";

import { Busy } from "@/components/busy";
import { CopyCommand } from "@/components/copy-command";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Switch } from "@/components/ui/switch";
import {
  useCheckAgentRelease,
  useRequestAgentUpdate,
  useUpdateNode,
} from "@/lib/api";
import { UPDATE_ATTEMPTS, agentState } from "@/lib/agent";
import { timeAgo } from "@/lib/format";
import type { AgentRelease, NodeRecord } from "@/types";

export function AgentDialog({
  node,
  release,
  now,
  open,
  onOpenChange,
}: {
  node: NodeRecord;
  release: AgentRelease;
  now: number;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const state = agentState(node, release.version, now);
  const request = useRequestAgentUpdate();
  const check = useCheckAgentRelease();
  const settings = useUpdateNode();
  const target = node.update_requested_version ?? release.version;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Agent on {node.name}</DialogTitle>
          <DialogDescription className="sr-only">
            The agent's version, its updates and how to update it by hand.
          </DialogDescription>
        </DialogHeader>
        <div>
          <p className="font-mono text-xl">{node.agent_version ?? "--"}</p>
          <p className="flex flex-wrap items-center gap-x-2 font-mono text-[11px] text-muted-foreground">
            <span
              title={
                release.checkedAt
                  ? `Checked ${timeAgo(release.checkedAt, now)}`
                  : undefined
              }
            >
              {release.version ? `Latest ${release.version}` : "Latest Unknown"}
            </span>
            <Button
              variant="link"
              size="sm"
              className="h-auto px-0 font-mono text-[11px]"
              onClick={() => check.mutate()}
              disabled={check.isPending}
            >
              {check.isPending ? <Busy>Checking</Busy> : "Check for Releases"}
            </Button>
          </p>
        </div>

        <div className="space-y-3 text-sm">
          {state === "current" && (
            <p className="flex items-center gap-2 text-success">
              <CircleCheck aria-hidden="true" className="size-4 shrink-0" />
              Up to date.
            </p>
          )}
          {state === "available" && (
            <div className="flex flex-wrap items-center gap-3">
              <p className="flex items-center gap-2">
                <CircleArrowUp
                  aria-hidden="true"
                  className="size-4 shrink-0 text-primary"
                />
                <span>
                  Version <span className="font-mono">{target}</span> is
                  available.
                </span>
              </p>
              <Button
                size="sm"
                onClick={() => request.mutate(node.id)}
                disabled={request.isPending}
              >
                {request.isPending ? <Busy>Requesting</Busy> : "Update Agent"}
              </Button>
            </div>
          )}
          {state === "updating" && (
            <p role="status" className="flex items-start gap-2 text-primary">
              <LoaderCircle
                aria-hidden="true"
                className="mt-0.5 size-4 shrink-0 motion-safe:animate-spin"
              />
              <span>
                Updating to <span className="font-mono">{target}</span>. The
                agent restarts on its own after its next report.
                {(node.update_attempts ?? 1) > 1 &&
                  ` Attempt ${node.update_attempts} of ${UPDATE_ATTEMPTS}.`}
              </span>
            </p>
          )}
          {state === "updating" && node.update_error && (
            <p className="text-xs text-muted-foreground">
              Last attempt: {node.update_error}
            </p>
          )}
          {state === "failed" && (
            <div className="flex flex-wrap items-center gap-3">
              <p className="flex items-start gap-2 text-destructive">
                <CircleX
                  aria-hidden="true"
                  className="mt-0.5 size-4 shrink-0"
                />
                <span>
                  The update to <span className="font-mono">{target}</span> did
                  not finish
                  {node.update_error ? `: ${node.update_error}` : "."}
                </span>
              </p>
              <Button
                size="sm"
                variant="outline"
                onClick={() => request.mutate(node.id)}
                disabled={request.isPending}
              >
                Retry
              </Button>
            </div>
          )}
          {state === "unsupported" && (
            <div className="space-y-2">
              <p className="flex items-start gap-2 text-destructive">
                <CircleX
                  aria-hidden="true"
                  className="mt-0.5 size-4 shrink-0"
                />
                <span>
                  Agent <span className="font-mono">{node.agent_version}</span>{" "}
                  can no longer connect. Run this on the server to update it:
                </span>
              </p>
              <CopyCommand command={release.updateCommand} />
            </div>
          )}
          {state === "unknown" && (
            <p className="text-muted-foreground">
              Krynodes has not checked for agent releases yet.
            </p>
          )}
        </div>

        <label className="flex min-h-9 cursor-pointer items-center justify-between gap-4 border-t pt-3 md:min-h-0">
          <span>
            <span className="block text-sm">Update Automatically</span>
            <span className="block text-xs text-muted-foreground">
              Installs each new release as soon as Krynodes sees it.
            </span>
          </span>
          <Switch
            checked={Boolean(node.auto_update)}
            disabled={settings.isPending}
            onCheckedChange={(checked) =>
              settings.mutate({ id: node.id, autoUpdate: checked })
            }
          />
        </label>

        <details className="text-sm">
          <summary className="cursor-pointer text-muted-foreground hover:text-foreground">
            Update by Hand
          </summary>
          <div className="mt-2">
            <CopyCommand command={release.updateCommand} />
          </div>
        </details>
      </DialogContent>
    </Dialog>
  );
}
