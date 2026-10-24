import { Plus, RefreshCw } from "lucide-react";
import { useState } from "react";
import { Link, useSearchParams } from "react-router";

import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  DeployDialog,
  type DeployRequest,
} from "@/features/deploy/deploy-dialog";
import { NewStackDialog } from "@/features/deploy/new-stack-dialog";
import {
  ActionDialog,
  type ActionRequest,
} from "@/features/services/action-dialog";
import { NeedsAttention } from "@/features/services/needs-attention";
import { ServicesBoard } from "@/features/services/services-board";
import {
  useHistoryAttention,
  useOverview,
  useRefreshServices,
  useServices,
} from "@/lib/api";
import { refreshPending } from "@/lib/services";
import { groupStacks, servicesAttention } from "@/lib/stacks";

export function ServicesPage() {
  const overview = useOverview();
  const services = useServices();
  const attention = useHistoryAttention();
  const refresh = useRefreshServices();
  const [params, setParams] = useSearchParams();
  const [request, setRequest] = useState<ActionRequest | null>(null);
  const [deploy, setDeploy] = useState<DeployRequest | null>(null);
  const [creating, setCreating] = useState(false);

  if (!overview.data || !services.data) {
    return (
      <>
        <PageHeader title="Services" />
        <Skeleton className="h-64" />
      </>
    );
  }

  const nodes = overview.data.nodes.filter(
    (node) => node.enrolled_at !== null && node.disabled_at === null,
  );
  const seen = overview.dataUpdatedAt;
  const refreshing = services.data.nodes.some((node) =>
    refreshPending(node, services.dataUpdatedAt),
  );
  const linked = params.get("deploy") ?? params.get("rollback");
  const linkedGroup = linked
    ? groupStacks(services.data, nodes, "").find(
        (group) => group.project === linked,
      )
    : undefined;
  const linkedNode = params.get("node");
  const deployRequest: DeployRequest | null =
    deploy ??
    (linkedGroup
      ? {
          action: params.get("rollback") ? "rollback" : "deploy",
          project: linkedGroup.project,
          members: linkedGroup.members.filter(
            (member) => !linkedNode || member.node.id === linkedNode,
          ),
        }
      : null);

  return (
    <>
      <PageHeader
        title="Services"
        actions={
          nodes.length > 0 && (
            <>
              <Button onClick={() => setCreating(true)}>
                <Plus aria-hidden="true" />
                New stack
              </Button>
              <Button
                variant="outline"
                disabled={refresh.isPending || refreshing}
                onClick={() => refresh.mutate(undefined)}
              >
                <RefreshCw aria-hidden="true" />
                {refreshing ? "Refreshing…" : "Refresh all"}
              </Button>
            </>
          )
        }
      />

      {nodes.length === 0 ? (
        <EmptyState
          title="No servers yet"
          body="Enroll a server from Fleet. Its services appear here within five minutes."
          action={
            <Button asChild>
              <Link to="/">Open Fleet</Link>
            </Button>
          }
        />
      ) : (
        <div className="space-y-4">
          <NeedsAttention
            problems={servicesAttention(
              services.data,
              nodes,
              attention.data?.items ?? [],
              Date.now(),
            )}
            onDeploy={setDeploy}
          />
          <ServicesBoard
            nodes={nodes}
            seen={seen}
            onRequest={setRequest}
            onDeploy={setDeploy}
          />
        </div>
      )}

      <DeployDialog
        request={deployRequest}
        seen={seen}
        onClose={() => {
          setDeploy(null);
          if (linked) {
            setParams(
              (current) => {
                const next = new URLSearchParams(current);
                for (const key of ["deploy", "rollback", "node"])
                  next.delete(key);
                return next;
              },
              { replace: true },
            );
          }
        }}
      />
      <ActionDialog request={request} onClose={() => setRequest(null)} />
      <NewStackDialog
        open={creating}
        onOpenChange={setCreating}
        nodes={nodes}
      />
    </>
  );
}
