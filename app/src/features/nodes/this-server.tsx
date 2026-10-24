import { Ellipsis } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router";

import { AddressRows } from "@/components/server-addresses";
import { Button } from "@/components/ui/button";
import { AgentDialog } from "@/features/agent/agent-panel";
import { useDevices, useServices } from "@/lib/api";
import { agentLine } from "@/lib/agent";
import { parseTimestamp, shortDate } from "@/lib/format";
import type { AgentRelease, NodeRecord } from "@/types";

function reachedBy(
  trust: { core: string[]; access: string[] } | null,
  devices: { name: string; fingerprint: string }[],
): string {
  if ((trust?.core.length ?? 0) === 0) return "Not trusted yet";
  const names = devices
    .filter((device) => trust?.access.includes(device.fingerprint))
    .map((device) => device.name);
  return names.length > 0 ? names.join(", ") : "No access";
}

export function ThisServer({
  node,
  release,
  now,
}: {
  node: NodeRecord;
  release: AgentRelease;
  now: number;
}) {
  const [agent, setAgent] = useState(false);
  const services = useServices();
  const devices = useDevices();
  const trust =
    services.data?.nodes.find((entry) => entry.id === node.id)?.trust ?? null;
  return (
    <section aria-labelledby="this-server">
      <h2
        id="this-server"
        className="mb-2 flex min-h-8 items-center text-[11px] tracking-wider text-muted-foreground uppercase"
      >
        This server
      </h2>
      <div className="space-y-3 rounded-lg border bg-card p-3">
        <AddressRows node={node} correct />
        <dl className="grid grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-x-3 gap-y-1.5 border-t pt-3 font-mono text-xs">
          <dt className="leading-8 text-muted-foreground">Reached by</dt>
          <dd className="min-w-0 truncate">
            {services.data && devices.data ? (
              <Link
                to="/devices"
                className="underline-offset-4 hover:underline"
                title="Change access in Trusted devices"
              >
                {reachedBy(trust, devices.data.devices)}
              </Link>
            ) : (
              "--"
            )}
          </dd>
          <dd />
          <dt className="leading-8 text-muted-foreground">Enrolled</dt>
          <dd className="min-w-0 truncate">
            {node.enrolled_at
              ? shortDate(parseTimestamp(node.enrolled_at))
              : "--"}
          </dd>
          <dd />
          <dt className="leading-8 text-muted-foreground">Agent</dt>
          <dd className="min-w-0 break-words">
            {agentLine(node, release.version, now)}
          </dd>
          <dd>
            <Button
              variant="ghost"
              size="icon"
              aria-label={`Agent on ${node.name}`}
              className="size-9 md:size-8"
              onClick={() => setAgent(true)}
            >
              <Ellipsis aria-hidden="true" />
            </Button>
          </dd>
        </dl>
      </div>
      <AgentDialog
        node={node}
        release={release}
        now={now}
        open={agent}
        onOpenChange={setAgent}
      />
    </section>
  );
}
