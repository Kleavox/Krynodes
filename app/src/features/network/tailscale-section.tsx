import { TAILSCALE } from "@krynodes/protocol";

import { RowMenu } from "@/components/row-menu";
import { StatusDot } from "@/components/status";
import { Button } from "@/components/ui/button";
import { useDevices } from "@/lib/api";
import { clockTime } from "@/lib/format";
import {
  alarmRows,
  applied,
  beforeConnect,
  notApplied,
  outsideRows,
  ruleRows,
  serverLines,
} from "@/lib/tailscale";
import { cn } from "@/lib/utils";
import type { TailscaleResponse } from "@/types";

import { ChangedRuleDialog, type Changed } from "./changed-rule-dialog";
import { ConnectTailscaleSheet } from "./connect-tailscale-sheet";
import { DisconnectDialog } from "./disconnect-dialog";
import { RemoveRuleDialog } from "./remove-rule-dialog";
import { RuleDialog } from "./rule-dialog";
import { StartRulesSheet } from "./start-rules-sheet";
import { CONSOLE, useTailnet, type Started } from "./use-tailscale";

const sectionTitle = "text-xs font-medium text-muted-foreground";
const card = "divide-y rounded-lg border bg-card";

export type TailnetOpen =
  | { kind: "connect" }
  | { kind: "change" }
  | { kind: "start"; started: Started }
  | { kind: "rule"; index: number | null }
  | { kind: "remove"; index: number }
  | { kind: "changed"; changed: Changed }
  | { kind: "disconnect" };

export function TailnetDialogs({
  open,
  onOpen,
}: {
  open: TailnetOpen | null;
  onOpen: (open: TailnetOpen | null) => void;
}) {
  const close = () => onOpen(null);
  const onChanged = (changed: Changed) => onOpen({ kind: "changed", changed });
  switch (open?.kind) {
    case "connect":
    case "change":
      return (
        <ConnectTailscaleSheet
          change={open.kind === "change"}
          onStarted={(started) => onOpen({ kind: "start", started })}
          onClose={close}
        />
      );
    case "start":
      return (
        <StartRulesSheet
          started={open.started}
          onChanged={onChanged}
          onClose={close}
        />
      );
    case "rule":
      return (
        <RuleDialog index={open.index} onChanged={onChanged} onClose={close} />
      );
    case "remove":
      return (
        <RemoveRuleDialog
          index={open.index}
          onChanged={onChanged}
          onClose={close}
        />
      );
    case "changed":
      return (
        <ChangedRuleDialog
          key={open.changed.block}
          changed={open.changed}
          onChanged={onChanged}
          onClose={close}
        />
      );
    case "disconnect":
      return <DisconnectDialog onClose={close} />;
    default:
      return null;
  }
}

const tailnetOf = (data: TailscaleResponse) =>
  data.connected?.tailnet ??
  data.servers.find((server) => server.report?.tailnet)?.report?.tailnet ??
  null;

function Alarms({ data }: { data: TailscaleResponse }) {
  const rows = alarmRows(data.alarms, data.servers);
  if (rows.length === 0) return null;
  return (
    <ul className={cn(card, "border-destructive/40")}>
      {rows.map((row) => (
        <li key={row.id} className="flex items-start gap-3 px-3.5 py-3 text-sm">
          <span
            aria-hidden="true"
            className="mt-0.5 font-bold text-destructive"
          >
            !
          </span>
          <span className="min-w-0 flex-1 space-y-1">
            <span className="block font-medium break-words text-destructive">
              {row.title}{" "}
              {row.detail && (
                <span className="font-mono text-xs font-normal text-muted-foreground">
                  {row.detail}
                </span>
              )}
            </span>
            {row.tag && (
              <span className="block font-mono text-xs">{row.tag}</span>
            )}
            <span className="block text-xs text-muted-foreground">
              {row.text}
            </span>
            {row.lines.map((line) => (
              <span key={line} className="block font-mono text-xs break-words">
                {line}
              </span>
            ))}
          </span>
          <Button asChild variant="outline" size="sm" className="h-9 md:h-8">
            <a href={row.link} target="_blank" rel="noreferrer">
              Admin Console ↗
            </a>
          </Button>
        </li>
      ))}
    </ul>
  );
}

function Before({
  data,
  onConnect,
}: {
  data: TailscaleResponse;
  onConnect: () => void;
}) {
  const open = beforeConnect(data.servers);
  const tailnet = tailnetOf(data);
  if (!open && !tailnet) return null;
  return (
    <section className="space-y-2">
      <h2 className={sectionTitle}>
        {open?.heading ?? `Tailscale ${tailnet}`}
      </h2>
      <div
        className={cn("rounded-lg border bg-card", open && "border-warning/40")}
      >
        {open && (
          <div className="space-y-2 border-b px-3.5 py-3 text-sm">
            <p className="flex items-start gap-2 font-medium text-warning">
              <span aria-hidden="true">!</span>
              {open.title}
            </p>
            <p className="text-xs text-muted-foreground">{open.note}</p>
            <ul className="divide-y rounded-md border">
              {open.rows.map((row) => (
                <li
                  key={row.nodeId}
                  className="grid grid-cols-[minmax(0,1fr)_auto] gap-x-3 px-3 py-2 font-mono text-xs sm:grid-cols-[minmax(0,1fr)_120px_100px_80px]"
                >
                  <span className="font-sans font-medium">{row.name}</span>
                  <span className="text-muted-foreground max-sm:hidden">
                    {row.address}
                  </span>
                  <span className="text-muted-foreground max-sm:hidden">
                    {row.devices}
                  </span>
                  <span className="text-warning">{row.ports}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
        <div className="flex flex-wrap items-center gap-3 px-3.5 py-3 text-sm">
          <span className="min-w-0 flex-1">
            <span className="block font-medium">
              Krynodes can keep these rules for your servers
            </span>
            <span className="block text-xs text-muted-foreground">
              Rules for your laptop, phone and other people stay yours, in
              Tailscale's admin console.
            </span>
          </span>
          <Button size="sm" className="h-9 md:h-8" onClick={onConnect}>
            Connect Tailscale
          </Button>
        </div>
      </div>
    </section>
  );
}

export function TailscaleSection({
  now,
  onOpen,
}: {
  now: number;
  onOpen: (open: TailnetOpen) => void;
}) {
  const { data } = useTailnet();
  if (!data) return null;
  const connected = data.connected;
  if (!connected) {
    return (
      <div className="space-y-2">
        <Alarms data={data} />
        <Before data={data} onConnect={() => onOpen({ kind: "connect" })} />
      </div>
    );
  }
  const rules = ruleRows(connected, data.servers);
  const outside = outsideRows(connected, data.servers);
  const late = notApplied(connected, data.servers, now);
  const on = data.servers.filter(
    (server) => server.report?.state === "running",
  );
  return (
    <div className="space-y-6">
      <Alarms data={data} />
      {late.length > 0 && (
        <ul className={cn(card, "border-warning/40")}>
          {late.map((item) => (
            <li
              key={item.nodeId}
              className="flex items-start gap-3 px-3.5 py-3 text-sm"
            >
              <StatusDot tone="warn" className="mt-1.5" />
              <span className="min-w-0 flex-1">
                <span className="block font-medium">{item.title}</span>
                <span className="block text-xs text-muted-foreground">
                  {item.text}
                </span>
              </span>
            </li>
          ))}
        </ul>
      )}
      <section>
        <div className="mb-2 flex items-center justify-between">
          <h2 className={sectionTitle}>Tailscale Rules</h2>
          <Button
            variant="outline"
            size="sm"
            className="h-9 md:h-8"
            onClick={() => onOpen({ kind: "rule", index: null })}
          >
            Add Rule
          </Button>
        </div>
        <ul className={card}>
          {rules.map((row) => (
            <li
              key={row.index ?? "back"}
              className={cn(
                "flex items-center gap-3 py-1 pr-2 pl-3.5 text-sm",
                row.locked && "text-muted-foreground",
              )}
            >
              {row.locked && (
                <span aria-hidden="true" className="text-destructive">
                  ✕
                </span>
              )}
              <span className="flex min-h-9 min-w-0 flex-1 flex-col justify-center gap-0.5 py-1.5 sm:flex-row sm:items-center sm:gap-3">
                <span className="min-w-0 break-words sm:flex-1">
                  {row.route}
                </span>
                <span className="font-mono text-xs">{row.ports}</span>
              </span>
              {row.index !== null ? (
                <RowMenu
                  label={`More for ${row.route}`}
                  items={[
                    {
                      label: "Edit Rule",
                      onSelect: () =>
                        onOpen({ kind: "rule", index: row.index }),
                    },
                    {
                      label: "Remove",
                      destructive: true,
                      onSelect: () =>
                        onOpen({ kind: "remove", index: row.index! }),
                    },
                  ]}
                />
              ) : (
                <span className="size-9 md:size-8" />
              )}
            </li>
          ))}
          {outside.map((row) => (
            <li
              key={row.id}
              className="flex items-center gap-3 py-1 pr-2 pl-3.5 text-sm"
            >
              <span className="flex min-w-0 flex-1 flex-col gap-0.5 py-1.5 sm:flex-row sm:items-center sm:gap-3">
                <span className="min-w-0 break-words sm:flex-1">
                  {row.route}
                  <span className="block text-xs text-muted-foreground">
                    Set outside Krynodes. Change it in Tailscale's admin
                    console.
                  </span>
                </span>
                <span className="font-mono text-xs">{row.ports}</span>
              </span>
              <Button asChild variant="ghost" size="sm" className="h-9 md:h-8">
                <a
                  href={CONSOLE.policy}
                  target="_blank"
                  rel="noreferrer"
                  aria-label={`Change ${row.route} in Tailscale's admin console`}
                >
                  ↗
                </a>
              </Button>
            </li>
          ))}
        </ul>
      </section>
      {on.length > 0 && (
        <section>
          <h2 className={cn(sectionTitle, "mb-2")}>On Tailscale</h2>
          <ul className={card}>
            {on.map((server) => {
              const lines = serverLines(server, connected, data.servers);
              const taken = applied(server, connected, data.servers);
              return (
                <li
                  key={server.nodeId}
                  className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 gap-y-0.5 px-3.5 py-2.5 text-sm sm:grid-cols-[minmax(0,1fr)_220px_96px]"
                >
                  <span className="min-w-0">
                    <span className="font-medium">{server.name}</span>{" "}
                    <span className="font-mono text-xs text-muted-foreground">
                      {server.report?.addresses[0] ?? "--"}
                    </span>
                  </span>
                  <span className="font-mono text-xs text-muted-foreground max-sm:col-start-1 max-sm:row-start-2">
                    {lines.tag ?? "Not tagged kry"}
                  </span>
                  <span
                    className={cn(
                      "text-right font-mono text-xs max-sm:row-span-2 max-sm:row-start-1 max-sm:col-start-2",
                      taken === true && "text-success",
                      taken === false && "text-warning",
                      taken === null && "text-muted-foreground",
                    )}
                  >
                    {taken === true
                      ? "✓ Applied"
                      : taken === false
                        ? "Not Applied"
                        : "--"}
                  </span>
                </li>
              );
            })}
          </ul>
        </section>
      )}
    </div>
  );
}

export function ThisTailnet({
  onOpen,
}: {
  onOpen: (open: TailnetOpen) => void;
}) {
  const { data } = useTailnet();
  const devices = useDevices().data?.devices ?? [];
  const connected = data?.connected;
  if (!data || !connected) return null;
  const pieces = data.servers.filter(
    (server) => server.vault?.set === connected.setId,
  ).length;
  const tagged = data.servers.filter((server) =>
    server.report?.tags?.includes(TAILSCALE.tag),
  ).length;
  const by = devices.find((device) => device.id === connected.savedBy)?.name;
  const facts: [string, string, string | null][] = [
    ["Tailnet", connected.tailnet, null],
    [
      "Credential",
      connected.clientId,
      pieces > 0 ? `${pieces} pieces · any 2 rebuild it` : "--",
    ],
    ["Tag", `${TAILSCALE.tag} · ${tagged} servers`, null],
    [
      "Saved",
      connected.savedAt
        ? `${clockTime(connected.savedAt)} · ${by ?? "--"}`
        : "--",
      connected.savedAt ? "Tailscale checked it first" : null,
    ],
  ];
  return (
    <section className="mt-6">
      <div className="mb-1 flex items-center justify-between">
        <h2 className={sectionTitle}>This Tailnet</h2>
        <RowMenu
          label="More for this tailnet"
          items={[
            {
              label: "Change Credential",
              onSelect: () => onOpen({ kind: "change" }),
            },
            {
              label: "Disconnect",
              destructive: true,
              onSelect: () => onOpen({ kind: "disconnect" }),
            },
          ]}
        />
      </div>
      <dl className="grid grid-cols-[96px_minmax(0,1fr)] gap-x-3 gap-y-3.5 rounded-lg border bg-card p-3.5 text-sm">
        {facts.map(([label, value, detail]) => (
          <div key={label} className="contents">
            <dt className="font-mono text-xs text-muted-foreground">{label}</dt>
            <dd className="min-w-0 font-mono text-xs break-words">
              {value}
              {detail && (
                <span className="block font-sans text-muted-foreground">
                  {detail}
                </span>
              )}
            </dd>
          </div>
        ))}
      </dl>
      <p className="mt-2 text-xs text-muted-foreground">
        Disconnect keeps your rules in your policy file.
      </p>
    </section>
  );
}
