import { useState } from "react";

import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { useFleet } from "@/features/fleet/use-fleet";
import { NewStackDialog } from "@/features/stacks/new-stack-dialog";
import { StackSection } from "@/features/stacks/stack-list";
import { useStacks } from "@/lib/api";
import { errorMessage } from "@/lib/http";

export function StacksPage() {
  const stacks = useStacks();
  const fleet = useFleet();
  const [creating, setCreating] = useState(false);
  const servers = stacks.data ?? [];
  return (
    <>
      <PageHeader
        title="Stacks"
        actions={
          <Button
            disabled={
              !servers.some((one) => one.online && one.docker === "ready")
            }
            onClick={() => setCreating(true)}
          >
            New Stack
          </Button>
        }
      />
      {stacks.data ? (
        servers.length === 0 ? (
          <EmptyState
            title="No servers yet"
            body="Enroll a server in Fleet and its Docker stacks appear here."
          />
        ) : (
          <div className="space-y-6">
            {servers.map((entry) => (
              <StackSection
                key={entry.nodeId}
                entry={entry}
                node={fleet.data?.find((one) => one.id === entry.nodeId)}
                servers={servers}
              />
            ))}
          </div>
        )
      ) : stacks.isError ? (
        <EmptyState
          title="The stacks can't load"
          body={errorMessage(stacks.error)}
          action={<Button onClick={() => void stacks.refetch()}>Retry</Button>}
        />
      ) : (
        <div role="status" aria-label="Loading stacks" className="space-y-2">
          <Skeleton className="h-14" />
          <Skeleton className="h-14" />
        </div>
      )}
      {creating && (
        <NewStackDialog servers={servers} onClose={() => setCreating(false)} />
      )}
    </>
  );
}
