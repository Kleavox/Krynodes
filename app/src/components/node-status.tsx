import { StatusChip, nodeTone } from "@/components/status";
import type { NodeState } from "@/lib/format";
import { elapsedText, type ServerOperation } from "@/lib/operations";
import { useNow } from "@/lib/use-now";

export function Elapsed({ since }: { since: number }) {
  const now = useNow(1_000);
  return <>{elapsedText(now - since)}</>;
}

export function OperationText({ operation }: { operation: ServerOperation }) {
  if (operation.kind === "restarting") {
    return (
      <>
        Restarting · {operation.by} · <Elapsed since={operation.since} />
      </>
    );
  }
  return (
    <>
      Updating agent to {operation.version}
      {operation.attempt > 1 && ` · try ${operation.attempt} of 3`}
    </>
  );
}

export function NodeStatus({
  state,
  operation,
  offlineDetail,
}: {
  state: NodeState;
  operation: ServerOperation | null;
  offlineDetail?: string;
}) {
  if (operation?.kind === "restarting") {
    return (
      <StatusChip
        tone="warn"
        pulse
        label="restarting"
        detail={
          <>
            {operation.by} · <Elapsed since={operation.since} />
          </>
        }
      />
    );
  }
  if (operation?.kind === "updating") {
    return (
      <StatusChip
        tone="warn"
        pulse
        label="updating"
        detail={`agent ${operation.version}`}
      />
    );
  }
  return (
    <StatusChip
      tone={nodeTone(state)}
      label={state === "disabled" ? "removed" : state}
      detail={state === "offline" ? offlineDetail : undefined}
    />
  );
}
