import { RefreshCw } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import {
  DeployDialog,
  type DeployRequest,
} from "@/features/deploy/deploy-dialog";
import { RemovedList } from "@/features/deploy/removed-list";
import { StackRow } from "@/features/deploy/stack-list";
import {
  useDevices,
  useNodeActions,
  useRefreshServices,
  useServices,
} from "@/lib/api";
import { refreshPending } from "@/lib/services";
import { removedStacks, serverLists } from "@/lib/stacks";
import type { NodeRecord } from "@/types";

import { ActionDialog, type ActionRequest } from "./action-dialog";
import { countText } from "./server-list";
import { ActionRow, ServiceRows, TrustLink } from "./service-list";

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
  const [group] = services.data
    ? serverLists(services.data, [node], {
        showSystem: false,
        query: "",
        notRunning: false,
      })
    : [];
  const removed = services.data ? removedStacks(services.data, [node], "") : [];
  const trusted =
    (services.data?.nodes.find((entry) => entry.id === node.id)?.trust?.access
      .length ?? 0) > 0;
  const refreshing =
    services.data?.nodes.some(
      (entry) =>
        entry.id === node.id && refreshPending(entry, services.dataUpdatedAt),
    ) ?? false;
  return (
    <section aria-labelledby="node-services">
      <div className="mb-2 flex min-h-8 items-center gap-2">
        <h2 id="node-services" className={SECTION_TITLE}>
          {group ? countText(group) : "Services"}
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
      {!group ? (
        <p className="rounded-lg border border-dashed p-4 text-sm text-muted-foreground">
          {services.data
            ? "No services reported yet. They appear within five minutes of enrolling."
            : "Loading services…"}
        </p>
      ) : (
        <div className="rounded-lg border bg-card">
          <ServiceRows
            members={group.members}
            seen={seen}
            trusted={trusted}
            onRequest={setRequest}
          >
            {group.stacks.map((item) => (
              <StackRow
                key={item.member.stack.project}
                item={item}
                seen={seen}
                branch={false}
                onRequest={setRequest}
                onDeploy={setDeploy}
              />
            ))}
          </ServiceRows>
        </div>
      )}
      {removed.length > 0 && (
        <div className="mt-6">
          <RemovedList items={removed} seen={seen} showServer={false} />
        </div>
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
  const devices = useDevices();
  const list = actions.data?.actions ?? [];
  const deviceName = (id: string | null) =>
    devices.data?.devices.find((device) => device.id === id)?.name;
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
            <ActionRow
              key={action.id}
              action={action}
              nodeName={node.name}
              deviceName={deviceName(action.deviceId)}
            />
          ))}
        </ul>
      )}
    </section>
  );
}
