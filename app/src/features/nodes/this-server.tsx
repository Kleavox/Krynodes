import { Ellipsis } from "lucide-react";
import { Fragment, useState } from "react";
import { Link } from "react-router";
import { dnsName, TAILSCALE } from "@krynodes/protocol";

import { AddressRows } from "@/components/server-addresses";
import { Button } from "@/components/ui/button";
import { AgentDialog } from "@/features/agent/agent-panel";
import { useTailnet } from "@/features/network/use-tailscale";
import { SignInDialog } from "@/features/packages/sign-in-dialog";
import {
  useDevices,
  useNetwork,
  useOverview,
  useQuarantine,
  useServices,
} from "@/lib/api";
import { agentLine } from "@/lib/agent";
import { parseTimestamp, shortDate } from "@/lib/format";
import { presenceOf, serverRow } from "@/lib/network";
import { packagesBlocker, tailscaleLine, updatesLine } from "@/lib/packages";
import { tailnetRemoved } from "@/lib/quarantine";
import {
  dnsLine,
  exitNodeLine,
  notApplied,
  serverLines,
} from "@/lib/tailscale";
import { cn } from "@/lib/utils";
import type { AgentRelease, NodeRecord } from "@/types";

import { TailscaleSettingDialog } from "./tailscale-setting-dialog";

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
  const [changing, setChanging] = useState<"exitnode" | "dns" | null>(null);
  const trust =
    services.data?.nodes.find((entry) => entry.id === node.id)?.trust ?? null;
  const updates = updatesLine(node.updates, now);
  const record = useQuarantine(node.id, !!node.quarantine).data?.quarantine;
  const blocked = record?.tailnet ?? [];
  const removed =
    node.quarantine && record ? tailnetRemoved(record, now) : null;
  const tailnet: ReturnType<typeof tailscaleLine> | null = removed
    ? {
        lines: [removed.title, removed.detail],
        warn: true,
        action: null,
        after: null,
      }
    : node.quarantine && blocked.length > 0
      ? {
          lines: [`${blocked[0]} · Blocked by your servers`],
          warn: true,
          action: null,
          after: null,
        }
      : node.tailscale
        ? tailscaleLine(node.tailscale, node.name, now)
        : null;
  const tail = useTailnet().data;
  const onTailnet = tail?.servers.find((entry) => entry.nodeId === node.id);
  const rules =
    tail?.connected && onTailnet?.report && !node.quarantine
      ? {
          sources: serverLines(onTailnet, tail.connected, tail.servers).sources,
          late: notApplied(tail.connected, tail.servers, now).find(
            (item) => item.nodeId === node.id,
          ),
        }
      : null;
  const blocker = packagesBlocker(node, (trust?.core.length ?? 0) > 0, now);
  const settings =
    node.tailscale?.state === "running" && !node.quarantine
      ? [
          {
            setting: "exitnode" as const,
            title: "Exit Node",
            line: exitNodeLine(node.tailscale, node.agent_version),
          },
          {
            setting: "dns" as const,
            title: "Tailscale DNS",
            line: dnsLine(node.tailscale, node.agent_version),
          },
        ]
      : [];
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
              <dd className="col-span-2 min-w-0 py-2 leading-4">
                <span className="block truncate">
                  {node.network.address ?? "--"} ·{" "}
                  {node.quarantine ? "cut off" : `${dnsName(node.name)}.kry`}
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
            </>
          )}
          <dt className="leading-8 text-muted-foreground">Reached by</dt>
          <dd className="col-span-2 min-w-0 truncate">
            {services.data && devices.data ? (
              <Link
                to="/devices"
                className="underline-offset-4 hover:underline"
                title="Change access in Passkeys"
              >
                {reachedBy(trust, devices.data.devices)}
              </Link>
            ) : (
              "--"
            )}
          </dd>
          <dt className="leading-8 text-muted-foreground">Enrolled</dt>
          <dd className="col-span-2 min-w-0 truncate">
            {node.enrolled_at
              ? shortDate(parseTimestamp(node.enrolled_at))
              : "--"}
          </dd>
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
                  "col-span-2 min-w-0 py-1.5 break-words",
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
                {rules?.sources.map((source, index) => (
                  <span
                    key={`${index}:${source.source}`}
                    className="block text-foreground"
                  >
                    {source.source}
                    {source.outside && (
                      <span className="text-muted-foreground">
                        {" "}
                        · Admin Console
                      </span>
                    )}
                    <span className="text-muted-foreground">
                      {" "}
                      · {source.ports}
                    </span>
                  </span>
                ))}
                {rules?.late && (
                  <span className="block text-warning">
                    {rules.late.title}
                    <span className="block font-sans">{rules.late.text}</span>
                  </span>
                )}
                {rules && (
                  <Link
                    to="/network"
                    className="block text-primary underline-offset-4 hover:underline"
                  >
                    Rules ›
                  </Link>
                )}
              </dd>
            </>
          )}
          {settings.map((row) => (
            <Fragment key={row.setting}>
              <dt className="leading-8 text-muted-foreground">{row.title}</dt>
              <dd
                className={cn(
                  "min-w-0 py-1.5 break-words",
                  row.line.warn && "text-warning",
                )}
              >
                {row.line.text}
              </dd>
              <dd>
                {row.line.changes && (
                  <Button
                    variant="ghost"
                    size="icon"
                    aria-label={`${row.title} on ${node.name}`}
                    disabled={blocker !== null}
                    title={blocker ?? undefined}
                    className="size-9 md:size-8"
                    onClick={() => setChanging(row.setting)}
                  >
                    <Ellipsis aria-hidden="true" />
                  </Button>
                )}
              </dd>
            </Fragment>
          ))}
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
      {changing !== null && node.tailscale && (
        <TailscaleSettingDialog
          node={node}
          setting={changing}
          on={
            changing === "dns"
              ? node.tailscale.acceptDNS === true
              : node.tailscale.exitNode?.advertised === true
          }
          approves={
            !!tail?.connected &&
            (node.tailscale.tags?.includes(TAILSCALE.tag) ?? false)
          }
          onClose={() => setChanging(null)}
        />
      )}
    </section>
  );
}
