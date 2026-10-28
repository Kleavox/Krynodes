import type { BridgesReport } from "@krynodes/protocol";
import { agentHasFeatures, FEATURE_AGENT } from "@krynodes/protocol/versions";
import { Plus } from "lucide-react";
import { useState } from "react";

import { RowMenu } from "@/components/row-menu";
import { SmallLabel } from "@/components/status";
import { Button } from "@/components/ui/button";
import { agentState } from "@/lib/agent";
import { useOverview, useRequestAgentUpdate } from "@/lib/api";
import {
  KIND_TAG,
  networkUsers,
  notReported,
  type BridgeNetwork,
} from "@/lib/bridges";
import { FIRST_REPORT } from "@/lib/devices";
import { useNow } from "@/lib/use-now";
import type { NodeRecord } from "@/types";

import { ComposeLinesDialog } from "./compose-lines-dialog";
import { CreateNetworkDialog } from "./create-network-dialog";
import { DeleteNetworkDialog } from "./delete-network-dialog";
import { useBridges } from "./use-bridges";

function Users({ network }: { network: BridgeNetwork }) {
  const users = networkUsers(network);
  if (users.length === 0) {
    return <span className="text-muted-foreground">Not used</span>;
  }
  return users.map((user, index) => (
    <span key={user.name}>
      {index > 0 && ", "}
      {user.name}
      {user.guest && <span className="text-muted-foreground"> guest</span>}
    </span>
  ));
}

export function NetworkRows({
  server,
  onCopy,
  onDelete,
}: {
  server: { name: string; bridges: BridgesReport | null };
  onCopy: (network: BridgeNetwork) => void;
  onDelete: (network: BridgeNetwork) => void;
}) {
  if (!server.bridges) {
    return (
      <p className="rounded-lg border border-dashed p-4 text-sm text-muted-foreground">
        {notReported(server.name)}
      </p>
    );
  }
  if (server.bridges.networks.length === 0) {
    return (
      <p className="rounded-lg border border-dashed p-4 text-sm text-muted-foreground">
        No shared networks on {server.name} yet.
      </p>
    );
  }
  return (
    <ul className="divide-y rounded-lg border bg-card">
      {server.bridges.networks.map((network) => (
        <li
          key={network.name}
          className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 px-3.5 py-2 text-sm md:grid-cols-[minmax(0,1fr)_128px_minmax(0,190px)_auto]"
        >
          <span className="flex min-w-0 items-center gap-2">
            <span className="truncate font-medium">{network.name}</span>
            <SmallLabel>{KIND_TAG[network.kind]}</SmallLabel>
          </span>
          <span className="hidden font-mono text-xs text-muted-foreground md:block">
            {network.subnet ?? "--"}
          </span>
          <span className="hidden truncate font-mono text-xs md:block">
            <Users network={network} />
          </span>
          <span className="row-span-2 md:row-span-1">
            <RowMenu
              label={`${network.name} actions`}
              items={[
                {
                  label: "Copy Compose Lines",
                  onSelect: () => onCopy(network),
                },
                ...(network.kind === "outside"
                  ? []
                  : [
                      {
                        label: "Delete Network",
                        destructive: true,
                        onSelect: () => onDelete(network),
                      },
                    ]),
              ]}
            />
          </span>
          <span className="col-start-1 truncate font-mono text-xs text-muted-foreground md:hidden">
            {network.subnet ?? "--"} · <Users network={network} />
          </span>
        </li>
      ))}
    </ul>
  );
}

export function DockerNetworks({ node }: { node: NodeRecord }) {
  const { server, privateRange } = useBridges(node);
  const release = useOverview().data?.agentRelease.version ?? null;
  const update = useRequestAgentUpdate();
  const now = useNow(30_000);
  const [creating, setCreating] = useState(false);
  const [copying, setCopying] = useState<BridgeNetwork | null>(null);
  const [deleting, setDeleting] = useState<BridgeNetwork | null>(null);
  const current = agentHasFeatures(node.agent_version);
  const updatable =
    release !== null &&
    ["available", "failed"].includes(agentState(node, release, now));
  return (
    <section aria-labelledby="docker-networks">
      <div className="mb-2 flex min-h-8 flex-wrap items-center gap-2">
        <h2
          id="docker-networks"
          className="text-xs font-medium text-muted-foreground"
        >
          Docker Networks
        </h2>
        {current ? (
          <Button
            variant="ghost"
            size="sm"
            className="ml-auto h-8"
            disabled={!server.bridges}
            onClick={() => setCreating(true)}
          >
            <Plus aria-hidden="true" />
            Create Network
          </Button>
        ) : (
          <span className="ml-auto flex items-center gap-2">
            <span className="font-mono text-xs text-muted-foreground">
              {node.agent_version
                ? `Needs agent ${FEATURE_AGENT} · ${node.name} runs ${node.agent_version}`
                : FIRST_REPORT}
            </span>
            {updatable && (
              <Button
                variant="outline"
                size="sm"
                className="h-9 md:h-8"
                disabled={update.isPending}
                onClick={() => update.mutate(node.id)}
              >
                Update Agent
              </Button>
            )}
          </span>
        )}
      </div>
      <NetworkRows server={server} onCopy={setCopying} onDelete={setDeleting} />
      <CreateNetworkDialog
        nodeId={node.id}
        server={server}
        privateRange={privateRange}
        open={creating}
        onOpenChange={setCreating}
      />
      <ComposeLinesDialog
        serverName={node.name}
        network={copying}
        onClose={() => setCopying(null)}
      />
      <DeleteNetworkDialog
        nodeId={node.id}
        serverName={node.name}
        network={deleting}
        onClose={() => setDeleting(null)}
      />
    </section>
  );
}
