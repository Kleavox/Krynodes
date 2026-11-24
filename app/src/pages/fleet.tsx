import { useState } from "react";

import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { EnrollDialog } from "@/features/fleet/enroll-dialog";
import { ServerRow } from "@/features/fleet/server-row";
import { useFleet } from "@/features/fleet/use-fleet";
import { errorMessage } from "@/lib/http";

export function FleetPage() {
  const fleet = useFleet();
  const [enrolling, setEnrolling] = useState(false);
  const names = new Map(fleet.data?.map((node) => [node.id, node.name]));
  return (
    <>
      <PageHeader
        title="Fleet"
        actions={
          <Button onClick={() => setEnrolling(true)}>Enroll Server</Button>
        }
      />
      {fleet.data ? (
        fleet.data.length === 0 ? (
          <EmptyState
            title="No servers yet"
            body="Servers you enroll will appear here."
          />
        ) : (
          <ul className="divide-y rounded-lg border bg-card">
            {fleet.data.map((node) => (
              <ServerRow key={node.id} node={node} names={names} />
            ))}
          </ul>
        )
      ) : fleet.isError ? (
        <EmptyState
          title="The fleet can't load"
          body={errorMessage(fleet.error)}
          action={<Button onClick={() => void fleet.refetch()}>Retry</Button>}
        />
      ) : (
        <div role="status" aria-label="Loading servers" className="space-y-2">
          <Skeleton className="h-14" />
          <Skeleton className="h-14" />
        </div>
      )}
      <EnrollDialog open={enrolling} onOpenChange={setEnrolling} />
    </>
  );
}
