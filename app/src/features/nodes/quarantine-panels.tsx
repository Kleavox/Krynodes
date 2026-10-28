import { KeyRound } from "lucide-react";
import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";

import { Busy, Waiting } from "@/components/busy";
import { Button } from "@/components/ui/button";
import { useSignedAction } from "@/features/deploy/use-signed-action";
import { useRemoveFromTailnet } from "@/features/network/use-tailscale";
import { LogsDialog } from "@/features/services/logs-dialog";
import {
  useCutOff,
  useDevices,
  useNetwork,
  useServices,
  useTailscale,
} from "@/lib/api";
import { errorMessage } from "@/lib/http";
import {
  changeThese,
  quarantineCard,
  resharing,
  stoppedRow,
  TAILSCALE_CONSOLE,
  warningStrip,
  whatHappened,
  type ChangeRow,
} from "@/lib/quarantine";
import { queryKeys } from "@/lib/query-client";
import type {
  NodeRecord,
  NodeWarning,
  QuarantineView,
  StoppedStack,
} from "@/types";

import { useItWasMe, useReshareWithout } from "./use-quarantine";

const SECTION_TITLE =
  "mb-2 flex min-h-8 items-center text-xs font-medium text-muted-foreground";

export function WarningStrip({
  strip,
  cutting,
  confirming,
  error,
  onCut,
  onMine,
}: {
  strip: ReturnType<typeof warningStrip>;
  cutting: boolean;
  confirming: boolean;
  error: string | null;
  onCut: () => void;
  onMine: () => void;
}) {
  return (
    <section
      aria-label="Warning"
      className="flex flex-wrap items-center gap-x-4 gap-y-2 rounded-lg border border-warning/40 bg-warning/10 px-3 py-2"
    >
      <div className="min-w-0 flex-1 text-sm">
        <p className="font-medium break-words">{strip.title}</p>
        {strip.detail && (
          <p className="font-mono text-xs break-all text-muted-foreground">
            {strip.detail}
          </p>
        )}
        <p className="text-xs text-muted-foreground">{strip.cutoff}</p>
      </div>
      <div className="flex shrink-0 gap-2">
        <Button
          variant="outline"
          size="sm"
          className="text-destructive"
          disabled={cutting || confirming}
          onClick={onCut}
        >
          {cutting ? <Busy>Working</Busy> : "Cut Off Now"}
        </Button>
        <Button size="sm" disabled={cutting || confirming} onClick={onMine}>
          <KeyRound aria-hidden="true" />
          {confirming ? <Waiting /> : "It Was Me"}
        </Button>
      </div>
      {error && (
        <p role="alert" className="basis-full text-sm text-destructive">
          {error}
        </p>
      )}
    </section>
  );
}

function WarningRow({
  node,
  warning,
  now,
}: {
  node: NodeRecord;
  warning: NodeWarning;
  now: number;
}) {
  const cut = useCutOff();
  const mine = useItWasMe(node);
  const error = cut.error ?? mine.error;
  return (
    <WarningStrip
      strip={warningStrip(warning, node.name, now)}
      cutting={cut.isPending}
      confirming={mine.isPending}
      error={error ? errorMessage(error) : null}
      onCut={() => cut.mutate({ nodeId: node.id, id: warning.id })}
      onMine={() => mine.mutate(warning)}
    />
  );
}

export function WarningStrips({
  node,
  now,
}: {
  node: NodeRecord;
  now: number;
}) {
  if (node.quarantine || !node.warnings?.length) return null;
  return (
    <div className="mb-5 space-y-2">
      {node.warnings.map((warning) => (
        <WarningRow key={warning.id} node={node} warning={warning} now={now} />
      ))}
    </div>
  );
}

export function QuarantineCard({
  node,
  now,
  onRelease,
}: {
  node: NodeRecord;
  now: number;
  onRelease: () => void;
}) {
  if (!node.quarantine) return null;
  const card = quarantineCard(
    node.quarantine,
    node.name,
    node.quarantine.tailnet ?? [],
    now,
  );
  return (
    <section
      aria-label={card.chip}
      className="mb-6 flex flex-wrap items-center gap-x-4 gap-y-3 rounded-lg border border-destructive/40 bg-destructive/10 px-4 py-3"
    >
      <div className="min-w-0 flex-1 space-y-1 text-sm">
        <p className="font-medium break-words text-destructive">{card.title}</p>
        <p>{card.body}</p>
        <p className="text-muted-foreground">{card.next}</p>
      </div>
      <Button variant="outline" className="shrink-0" onClick={onRelease}>
        Release Server
      </Button>
    </section>
  );
}

export function WhatHappened({
  view,
  nodeName,
  now,
}: {
  view: QuarantineView | undefined;
  nodeName: string;
  now: number;
}) {
  const record = view?.quarantine;
  const devices = useDevices().data?.devices ?? [];
  return (
    <section aria-labelledby="what-happened">
      <h2 id="what-happened" className={SECTION_TITLE}>
        What Happened
      </h2>
      <ol className="space-y-1.5 rounded-lg border bg-card p-3 font-mono text-xs">
        {record ? (
          whatHappened(record, now, nodeName, devices).map((line, index) => (
            <li
              key={index}
              className="grid grid-cols-[auto_minmax(0,1fr)] gap-3"
            >
              <span className="text-muted-foreground">{line.time}</span>
              <span className="break-words">
                {line.lead && (
                  <span className="font-medium text-destructive">
                    {line.lead}:{" "}
                  </span>
                )}
                {line.text}
              </span>
            </li>
          ))
        ) : (
          <li className="text-muted-foreground">--</li>
        )}
      </ol>
    </section>
  );
}

function ChangeAction({
  row,
  node,
  reshare,
  remove,
  busy,
}: {
  row: ChangeRow;
  node: NodeRecord;
  reshare: ReturnType<typeof useReshareWithout>;
  remove: ReturnType<typeof useRemoveFromTailnet>;
  busy: boolean;
}) {
  if (!row.action) return null;
  if (row.action.kind === "console") {
    return (
      <Button asChild variant="outline" size="sm">
        <a href={TAILSCALE_CONSOLE} target="_blank" rel="noreferrer">
          {row.action.label}
        </a>
      </Button>
    );
  }
  if (row.action.kind === "remove") {
    return (
      <Button
        variant="outline"
        size="sm"
        disabled={remove.isPending}
        onClick={() => remove.mutate(node.id)}
      >
        <KeyRound aria-hidden="true" />
        {remove.isPending ? <Waiting /> : row.action.label}
      </Button>
    );
  }
  if (busy) {
    return (
      <span className="font-mono text-xs text-muted-foreground">
        <Busy>Resharing</Busy>
      </span>
    );
  }
  const addresses = row.action.kind === "unexpose";
  const plan = reshare.plan(addresses);
  const why = !plan.ok
    ? plan.reason
    : !plan.needed
      ? `Nothing of ${node.name} is left to change.`
      : null;
  return (
    <Button
      variant="outline"
      size="sm"
      disabled={why !== null || reshare.operate.isPending}
      title={why ?? undefined}
      onClick={() => reshare.run(addresses)}
    >
      <KeyRound aria-hidden="true" />
      {reshare.operate.isPending ? <Waiting /> : row.action.label}
    </Button>
  );
}

export function ChangeThese({
  node,
  view,
}: {
  node: NodeRecord;
  view: QuarantineView | undefined;
}) {
  const reshare = useReshareWithout(node);
  const reshareTailscale = useReshareWithout(node, "tailscale");
  const remove = useRemoveFromTailnet();
  const connected = !!useTailscale().data?.connected;
  const client = useQueryClient();
  const busy = resharing(useServices().data?.actions ?? []);
  const was = useRef(busy);
  useEffect(() => {
    if (was.current && !busy) {
      void client.invalidateQueries({
        queryKey: queryKeys.quarantine(node.id),
      });
    }
    was.current = busy;
  }, [busy, client, node.id]);
  if (!view) return null;
  const { title, rows } = changeThese(view, node.name, connected);
  const error =
    reshare.operate.error ?? reshareTailscale.operate.error ?? remove.error;
  return (
    <section aria-labelledby="change-these">
      <h2 id="change-these" className={SECTION_TITLE}>
        {title}
      </h2>
      <ul className="divide-y rounded-lg border bg-card">
        {rows.map((row) => (
          <li
            key={row.id}
            className="flex flex-wrap items-center gap-x-3 gap-y-2 px-3 py-2"
          >
            <div className="min-w-0 flex-1 text-sm">
              <p className="break-words">
                <span className="font-mono">{row.title}</span>
                {row.tag && (
                  <span className="text-muted-foreground"> · {row.tag}</span>
                )}
              </p>
              {row.note && (
                <p className="text-xs text-muted-foreground">{row.note}</p>
              )}
            </div>
            <ChangeAction
              row={row}
              node={node}
              reshare={
                row.id === "tailscale-vault" ? reshareTailscale : reshare
              }
              remove={remove}
              busy={busy}
            />
          </li>
        ))}
      </ul>
      {error && (
        <p role="alert" className="mt-2 text-sm text-destructive">
          {errorMessage(error)}
        </p>
      )}
    </section>
  );
}

export function StoppedStackNote({
  node,
  stack,
  now,
}: {
  node: NodeRecord;
  stack: StoppedStack;
  now: number;
}) {
  const [reading, setReading] = useState(false);
  const start = useSignedAction();
  const members = useNetwork().data?.members ?? [];
  const row = stoppedRow(
    stack,
    node.name,
    Object.fromEntries(
      members.flatMap((member) =>
        member.address ? [[member.address, member.name]] : [],
      ),
    ),
    now,
  );
  return (
    <div className="space-y-1 border-t px-3 py-2 text-xs">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <p className="min-w-0 flex-1 font-medium break-words text-destructive">
          {row.title}
        </p>
        <div className="flex shrink-0 gap-1">
          <Button
            variant="ghost"
            size="sm"
            className="h-9 md:h-8"
            onClick={() => setReading(true)}
          >
            Logs
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="h-9 md:h-8"
            disabled={start.isPending}
            onClick={() =>
              start.mutate({
                action: "start",
                targets: [
                  { nodeId: node.id, kind: "compose", name: stack.project },
                ],
              })
            }
          >
            <KeyRound aria-hidden="true" />
            {start.isPending ? <Waiting /> : "Start"}
          </Button>
        </div>
      </div>
      <p className="font-mono break-words text-muted-foreground">
        {row.places}
      </p>
      <p className="text-muted-foreground">{row.note}</p>
      <LogsDialog
        target={{
          nodeId: node.id,
          nodeName: node.name,
          kind: "compose",
          name: stack.project,
        }}
        open={reading}
        onOpenChange={setReading}
      />
    </div>
  );
}
