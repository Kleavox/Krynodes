import { StatusChip, nodeTone } from "@/components/status";
import { capitalize, type NodeState } from "@/lib/format";
import { elapsedText, type ServerOperation } from "@/lib/operations";
import { useNow } from "@/lib/use-now";

export function Elapsed({ since }: { since: number }) {
  const now = useNow(1_000);
  return <>{elapsedText(now - since)}</>;
}

export function OperationText({ operation }: { operation: ServerOperation }) {
  if (operation.kind === "deleting") {
    return (
      <>
        {operation.stopped
          ? "Delete Stopped · Open Delete Node to try again"
          : "Deleting · It disappears once Krynodes finishes"}
      </>
    );
  }
  if (operation.kind === "restarting") {
    return (
      <>
        Restarting · {operation.by} · <Elapsed since={operation.since} />
      </>
    );
  }
  return (
    <>
      Updating Agent to {operation.version}
      {operation.attempt > 1 && ` · Try ${operation.attempt} of 3`}
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
  if (operation?.kind === "deleting") {
    return operation.stopped ? (
      <StatusChip tone="bad" label="delete stopped" />
    ) : (
      <StatusChip tone="warn" pulse label="deleting" />
    );
  }
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
        detail={`Agent ${operation.version}`}
      />
    );
  }
  return (
    <StatusChip
      tone={nodeTone(state)}
      label={state === "disabled" ? "removed" : state}
      detail={
        state === "offline" && offlineDetail
          ? capitalize(offlineDetail)
          : undefined
      }
    />
  );
}
