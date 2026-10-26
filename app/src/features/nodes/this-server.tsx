import { Ellipsis } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router";
import { dnsName } from "@krynodes/protocol";

import { AddressRows } from "@/components/server-addresses";
import { Button } from "@/components/ui/button";
import { AgentDialog } from "@/features/agent/agent-panel";
import { SignInDialog } from "@/features/packages/sign-in-dialog";
import { useDevices, useNetwork, useOverview, useServices } from "@/lib/api";
import { agentLine } from "@/lib/agent";
import { parseTimestamp, shortDate } from "@/lib/format";
import { presenceOf, serverRow } from "@/lib/network";
import { packagesBlocker, tailscaleLine, updatesLine } from "@/lib/packages";
import { cn } from "@/lib/utils";
import type { AgentRelease, NodeRecord } from "@/types";

function reachedBy(
  trust: { core: string[]; access: string[] } | null,
  devices: { name: string; fingerprint: string }[],
): string {
  if ((trust?.core.length ?? 0) === 0) return "Not Trusted Yet";
  const names = devices
    .filter((device) => trust?.access.includes(device.fingerprint))
    .map((device) => device.name);
  return names.length > 0 ? names.join(", ") : "No Access";
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
  const network = useNetwork();
  const overview = useOverview();
  const [signIn, setSignIn] = useState<{ again: boolean } | null>(null);
  const trust =
    services.data?.nodes.find((entry) => entry.id === node.id)?.trust ?? null;
  const updates = updatesLine(node.updates, now);
  const tailnet = node.tailscale
    ? tailscaleLine(node.tailscale, node.name, now)
    : null;
  const blocker = packagesBlocker(node, (trust?.core.length ?? 0) > 0, now);
  const member = network.data?.members.find(
    (entry) => entry.nodeId === node.id,
  );
  const links =
    member && network.data && overview.data
      ? serverRow(
          member,
          network.data,
          presenceOf(overview.data.nodes, now),
          now,
        )
      : null;
  return (
    <section aria-labelledby="this-server">
      <h2
        id="this-server"
        className="mb-2 flex min-h-8 items-center text-[11px] text-muted-foreground"
      >
        This Server
      </h2>
      <div className="space-y-3 rounded-lg border bg-card p-3">
        <AddressRows node={node} correct />
        <dl className="grid grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-x-3 gap-y-1.5 border-t pt-3 font-mono text-xs">
          {node.network?.state === "in" && (
            <>
              <dt className="self-start leading-8 text-muted-foreground">
                Private
              </dt>
              <dd className="min-w-0 py-2 leading-4">
                <span className="block truncate">
                  {node.network.address ?? "--"} · {dnsName(node.name)}.kry
                </span>
                <Link
                  to="/network"
                  className="underline-offset-4 hover:underline"
                >
                  <span className={cn(links?.short && "text-warning")}>
                    {links?.links ?? "--"}
                  </span>{" "}
                  <span className="font-sans text-muted-foreground">
                    · Network ›
                  </span>
                </Link>
              </dd>
              <dd />
            </>
          )}
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
          {updates && (
            <>
              <dt className="leading-8 text-muted-foreground">Updates</dt>
              <dd className="min-w-0 py-1.5 break-words">
                {updates.text}
                {updates.restart && (
                  <span className="block text-warning">{updates.restart}</span>
                )}
              </dd>
              <dd>
                <Link
                  to={`/nodes/${node.id}/packages`}
                  className="inline-flex min-h-9 items-center px-1 whitespace-nowrap text-primary underline-offset-4 hover:underline md:min-h-8"
                >
                  Packages ›
                </Link>
              </dd>
            </>
          )}
          {tailnet && (
            <>
              <dt className="leading-8 text-muted-foreground">Tailscale</dt>
              <dd
                className={cn(
                  "min-w-0 py-1.5 break-words",
                  tailnet.warn && "text-warning",
                )}
              >
                {tailnet.lines.map((line) => (
                  <span key={line} className="block">
                    {line}
                  </span>
                ))}
                {tailnet.action && (
                  <span className="block">
                    <button
                      type="button"
                      disabled={blocker !== null}
                      title={blocker ?? undefined}
                      onClick={() =>
                        setSignIn({
                          again: tailnet.action === "Sign In Again",
                        })
                      }
                      className="text-primary underline-offset-4 hover:underline disabled:text-muted-foreground disabled:no-underline"
                    >
                      {tailnet.action} ›
                    </button>
                    {tailnet.after}
                  </span>
                )}
              </dd>
              <dd />
            </>
          )}
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
      {signIn !== null && (
        <SignInDialog
          node={node}
          again={signIn.again}
          open
          onOpenChange={(open) => !open && setSignIn(null)}
        />
      )}
    </section>
  );
}
