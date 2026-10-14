import { RefreshCw } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import {
  DeployDialog,
  type DeployRequest,
} from "@/features/deploy/deploy-dialog";
import { useNodeActions, useRefreshServices, useServices } from "@/lib/api";
import { refreshPending } from "@/lib/services";
import type { NodeRecord } from "@/types";

import { ActionDialog, type ActionRequest } from "./action-dialog";
import { ActionRow, TrustLink } from "./service-list";
import { ServicesBoard } from "./services-board";

const SECTION_TITLE =
  "text-[11px] tracking-wider text-muted-foreground uppercase";

export function NodeServices({
  node,
  seen,
}: {
  node: NodeRecord;
  seen: number;
}) {
  const services = useServices();
  const refresh = useRefreshServices();
  const [request, setRequest] = useState<ActionRequest | null>(null);
  const [deploy, setDeploy] = useState<DeployRequest | null>(null);
  const entry = services.data?.nodes.find((item) => item.id === node.id);
  const trusted = (entry?.trust?.access.length ?? 0) > 0;
  const reported =
    entry !== undefined &&
    (entry.services.length > 0 ||
      entry.stacks.length > 0 ||
      (entry.removed?.length ?? 0) > 0);
  const refreshing =
    entry !== undefined && refreshPending(entry, services.dataUpdatedAt);
  return (
    <section aria-labelledby="node-services">
      <div className="mb-2 flex min-h-8 items-center gap-2">
        <h2 id="node-services" className={SECTION_TITLE}>
          Services
        </h2>
        {services.data && !trusted && <TrustLink />}
        <Button
          variant="ghost"
          size="sm"
          className="ml-auto h-8"
          disabled={refresh.isPending || refreshing}
          onClick={() => refresh.mutate([node.id])}
        >
          <RefreshCw aria-hidden="true" />
          {refreshing ? "Refreshing…" : "Refresh"}
        </Button>
      </div>
      {!reported ? (
        <p className="rounded-lg border border-dashed p-4 text-sm text-muted-foreground">
          {services.data
            ? "No services reported yet. They appear within five minutes of enrolling."
            : "Loading services…"}
        </p>
      ) : (
        <ServicesBoard
          nodes={[node]}
          single
          seen={seen}
          onRequest={setRequest}
          onDeploy={setDeploy}
        />
      )}
      <ActionDialog request={request} onClose={() => setRequest(null)} />
      <DeployDialog
        request={deploy}
        seen={seen}
        onClose={() => setDeploy(null)}
      />
    </section>
  );
}

export function RecentActions({ node }: { node: NodeRecord }) {
  const actions = useNodeActions(node.id);
  const list = actions.data?.actions ?? [];
  return (
    <section
      aria-labelledby="node-recent-actions"
      className="flex max-h-[28rem] flex-col lg:absolute lg:inset-0 lg:max-h-none"
    >
      <h2
        id="node-recent-actions"
        className={`mb-2 flex min-h-8 items-center ${SECTION_TITLE}`}
      >
        Recent actions
      </h2>
      {list.length === 0 ? (
        <p className="rounded-lg border border-dashed p-4 text-sm text-muted-foreground">
          {actions.data ? "No actions yet." : "Loading actions…"}
        </p>
      ) : (
        <ul className="min-h-0 divide-y overflow-y-auto rounded-lg border bg-card">
          {list.map((action) => (
            <ActionRow key={action.id} action={action} nodeName={node.name} />
          ))}
        </ul>
      )}
    </section>
  );
}
