import {
  agentHasSecurity,
  agentSetsBooleans,
} from "@krynodes/protocol/versions";
import { KeyRound } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router";
import { toast } from "sonner";

import { Waiting } from "@/components/busy";
import { RowMenu } from "@/components/row-menu";
import { StatusDot } from "@/components/status";
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useSignedAction } from "@/features/deploy/use-signed-action";
import { useNetwork, useServices } from "@/lib/api";
import { confinementRow, type ConfineStep } from "@/lib/confine";
import {
  closedText,
  closingPorts,
  fromText,
  listensText,
  openingKey,
  portsArg,
  turnOnRows,
} from "@/lib/firewall";
import { errorMessage } from "@/lib/http";
import { firewallRow, inside } from "@/lib/network";
import {
  findingTone,
  firewallName,
  firewallPorts,
  keysLine,
  offTone,
  protectionDetail,
  protectionsNotice,
  fromUtcHour,
  recipeChoices,
  recommended,
  notesOf,
  toUtcHour,
  type RecipeChoice,
} from "@/lib/security";
import { cn } from "@/lib/utils";
import type {
  Finding,
  NodeRecord,
  SecurityReport,
  ServicesResponse,
} from "@/types";

import {
  BooleanDialog,
  ConfineDialog,
  DenialsDialog,
} from "./confinement-dialogs";
import { FirewallSection } from "./firewall-section";

const sectionTitle = "text-xs font-medium text-muted-foreground";

const offset = () => new Date().getTimezoneOffset();

type Pending =
  | { choice: RecipeChoice; turnOn: boolean; closing?: boolean }
  | { recommend: string[] };

function RecipeDialog({
  node,
  pending,
  internet,
  onClose,
}: {
  node: NodeRecord;
  pending: Pending | null;
  internet: string[];
  onClose: () => void;
}) {
  const run = useSignedAction(false);
  const services = useServices();
  const view = useNetwork().data;
  const entry = services.data?.nodes.find((item) => item.id === node.id);
  const report = entry?.security;
  const stacks = entry?.stacks ?? [];
  const [hour, setHour] = useState("3");
  const [ticked, setTicked] = useState<string[] | null>(null);
  const member = view && inside(view).find((item) => item.nodeId === node.id);
  const locked = member ? firewallRow(member) : null;
  const suggested = (
    report ? [...new Set([...firewallPorts(report), ...internet])] : internet
  ).filter((port) => port !== locked?.port);
  if (!pending) return null;
  const recommend = "recommend" in pending ? pending.recommend : null;
  const choice = "choice" in pending ? pending.choice : null;
  const turnOn = "turnOn" in pending ? pending.turnOn : true;
  const closing = "closing" in pending && pending.closing === true;
  const ids = recommend ?? [choice!.id];
  const needsHour = turnOn && ids.includes("reboot-window");
  const firewall = turnOn && ids.includes("firewall");
  const closedMode =
    firewall && (closing || agentHasSecurity(node.agent_version));
  const wall = report?.firewall;
  const rows = !report
    ? []
    : closing
      ? (wall?.open ?? []).map((opening) => ({
          opening,
          listens: listensText(openingKey(opening), report, stacks),
        }))
      : turnOnRows(report, stacks, locked?.port ?? null);
  const ports =
    ticked ??
    (closedMode
      ? closing
        ? rows.map((row) => openingKey(row.opening))
        : []
      : suggested);
  const toggle = (port: string) =>
    setTicked(
      ports.includes(port)
        ? ports.filter((item) => item !== port)
        : [...ports, port],
    );
  const kept = closing ? (wall?.other ?? []) : [];
  const shutting =
    closedMode && report ? closingPorts(stacks, report, ports) : [];
  const firewallArgs: Record<string, string> = closedMode
    ? {
        closed: "1",
        ports: portsArg(
          rows
            .filter((row) => ports.includes(openingKey(row.opening)))
            .map((row) => row.opening),
        ),
      }
    : { ports: ports.join(",") };
  const argsFor = (id: string): Record<string, string> | undefined => {
    const args = {
      ...(id === "reboot-window"
        ? { hour: String(Math.floor(toUtcHour(Number(hour), offset()))) }
        : {}),
      ...(id === "firewall" ? firewallArgs : {}),
    };
    return Object.keys(args).length > 0 ? args : undefined;
  };
  const detail = (id: string) =>
    !report
      ? null
      : id !== "firewall"
        ? protectionDetail(id, report)
        : closedMode
          ? closedText(firewallName(report), closing ? "close" : "on")
          : protectionDetail(id, report);
  const submit = () =>
    run.mutate(
      {
        action: turnOn ? "apply" : "undo",
        mode: "rolling",
        targets: ids.map((id) => ({
          nodeId: node.id,
          kind: "host" as const,
          name: id,
          ...(turnOn && argsFor(id) ? { args: argsFor(id) } : {}),
        })),
      },
      {
        onSuccess: () => {
          toast.success(`Sent to ${node.name}.`);
          onClose();
        },
      },
    );
  return (
    <AlertDialog open onOpenChange={(open) => !open && onClose()}>
      <AlertDialogContent className="max-sm:top-auto max-sm:bottom-0 max-sm:translate-y-0 max-sm:rounded-b-none">
        <AlertDialogHeader>
          <AlertDialogTitle>
            {recommend
              ? `Apply the recommended steps on ${node.name}?`
              : closing
                ? `Close everything else in the firewall on ${node.name}?`
                : `${turnOn ? "Turn on" : "Turn off"} ${choice!.title.toLowerCase()} on ${node.name}?`}
          </AlertDialogTitle>
          <AlertDialogDescription asChild>
            <div className="space-y-2">
              {ids.map((id) => (
                <p key={id}>{detail(id)}</p>
              ))}
              {!turnOn && (
                <p>The file Krynodes added is removed; nothing else changes.</p>
              )}
            </div>
          </AlertDialogDescription>
        </AlertDialogHeader>
        {needsHour && (
          <div className="space-y-1.5">
            <Label htmlFor="reboot-hour">Restart Hour (Your Time)</Label>
            <Select value={hour} onValueChange={setHour}>
              <SelectTrigger id="reboot-hour" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {Array.from({ length: 24 }, (_, value) => (
                  <SelectItem key={value} value={String(value)}>
                    {String(value).padStart(2, "0")}:00
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        )}
        {closedMode && (
          <fieldset className="space-y-1.5">
            <legend className="text-sm font-medium">
              Keep These Ports Open
            </legend>
            <label className="flex items-center gap-2 text-xs">
              <input type="checkbox" checked disabled />
              SSH
              <span className="text-muted-foreground">· Always open</span>
            </label>
            {locked && (
              <label className="flex items-center gap-2 text-xs">
                <input type="checkbox" checked disabled />
                <span className="font-mono">{locked.port}</span>
                <span className="text-muted-foreground">
                  · Private network · Always open
                </span>
              </label>
            )}
            {rows.map(({ opening, listens }) => {
              const key = openingKey(opening);
              return (
                <label key={key} className="flex items-center gap-2 text-xs">
                  <input
                    type="checkbox"
                    checked={ports.includes(key)}
                    onChange={() => toggle(key)}
                  />
                  <span className="font-mono">{key}</span>
                  <span className="min-w-0 truncate text-muted-foreground">
                    · {listens.text}
                    {opening.from !== "everyone" &&
                      ` · From ${fromText(opening)}`}
                  </span>
                </label>
              );
            })}
            {kept.length > 0 && (
              <div className="space-y-1 pt-1">
                <p className="text-xs">These rules stay as they are:</p>
                <ul className="space-y-0.5 font-mono text-xs text-muted-foreground">
                  {kept.map((rule) => (
                    <li key={rule} className="break-all">
                      {rule}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {shutting.length > 0 && (
              <p className="text-xs text-warning">
                Ports Docker publishes that close: {shutting.join(", ")}
              </p>
            )}
          </fieldset>
        )}
        {firewall && !closedMode && (
          <fieldset className="space-y-1.5">
            <legend className="text-sm font-medium">
              Keep these ports open too
            </legend>
            {locked && (
              <label className="flex items-center gap-2 text-xs">
                <input type="checkbox" checked disabled />
                <span className="font-mono">{locked.port}</span>
                <span className="text-muted-foreground">· {locked.detail}</span>
              </label>
            )}
            {suggested.length === 0 && !locked ? (
              <p className="text-xs text-muted-foreground">
                Only SSH stays open.
              </p>
            ) : (
              suggested.map((port) => (
                <label
                  key={port}
                  className="flex items-center gap-2 font-mono text-xs"
                >
                  <input
                    type="checkbox"
                    checked={ports.includes(port)}
                    onChange={() => toggle(port)}
                  />
                  {port}
                </label>
              ))
            )}
            <p className="text-xs text-muted-foreground">
              SSH always stays open.
              {locked &&
                " So does everything your other servers send over kry0."}
            </p>
          </fieldset>
        )}
        {run.error && (
          <p role="alert" className="text-sm text-destructive">
            {errorMessage(run.error)}
          </p>
        )}
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <Button
            variant={turnOn ? "default" : "destructive"}
            disabled={run.isPending}
            onClick={submit}
          >
            <KeyRound aria-hidden="true" />
            {run.isPending ? (
              <Waiting />
            ) : recommend ? (
              "Apply"
            ) : closing ? (
              "Close Everything Else"
            ) : turnOn ? (
              "Turn On"
            ) : (
              "Turn Off"
            )}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

const CONFINE_LABELS: Record<
  ConfineStep,
  { label: string; destructive?: boolean }
> = {
  denials: { label: "Denials" },
  manage: { label: "Let Krynodes Manage" },
  on: { label: "Turn On" },
  containers: { label: "Confine Containers" },
  uncontain: { label: "Stop Confining Containers", destructive: true },
  boolean: { label: "Change Boolean" },
};

const ROW = "flex items-center gap-2 px-3 py-2";

export function FindingRow({
  node,
  finding,
  hint,
  server = false,
}: {
  node: Pick<NodeRecord, "id" | "name">;
  finding: Finding;
  hint: string | null;
  server?: boolean;
}) {
  return (
    <li className="flex items-start gap-2 px-3 py-2">
      <span className="flex h-5 items-center">
        <StatusDot tone={findingTone(finding)} />
      </span>
      <span className="min-w-0 flex-1 break-words">
        {finding.detail}
        {server && (
          <Link
            to={`/security?server=${encodeURIComponent(node.id)}`}
            replace
            className="ml-2 font-mono text-xs text-muted-foreground underline-offset-4 hover:underline"
          >
            On {node.name}
          </Link>
        )}
        {finding.id === "public-ports" && hint && (
          <span className="block text-xs text-muted-foreground">{hint}</span>
        )}
        {finding.id === "public-ports" && !hint && (
          <span className="block text-xs text-muted-foreground">
            Some of these on a private network? Add its range under{" "}
            <Link
              to="/settings/private-addresses"
              className="underline underline-offset-4"
            >
              Settings, Private Addresses
            </Link>
            .
          </span>
        )}
      </span>
      {finding.id === "updates-pending" && (
        <Link
          to={`/nodes/${node.id}/packages`}
          className="-my-2 inline-flex min-h-9 shrink-0 items-center self-center px-1 text-xs whitespace-nowrap text-primary underline-offset-4 hover:underline md:min-h-8"
        >
          Packages ›
        </Link>
      )}
    </li>
  );
}

export function ServerSecurity({
  node,
  entry,
  report,
  seen,
}: {
  node: NodeRecord;
  entry: ServicesResponse["nodes"][number];
  report: SecurityReport;
  seen: number;
}) {
  const [pending, setPending] = useState<Pending | null>(null);
  const [confining, setConfining] = useState<ConfineStep | null>(null);
  const choices = recipeChoices(report);
  const steps = recommended(report);
  const internet = entry.stacks.flatMap((stack) =>
    stack.access === "full" ? (stack.public ?? []) : [],
  );
  const notice = protectionsNotice(report);
  const notes = notesOf(report);
  const found = report.confinement;
  const confine = confinementRow(found, agentSetsBooleans(node.agent_version));
  const firewall = choices.find((choice) => choice.id === "firewall")!;
  const status = (choice: RecipeChoice) =>
    choice.applied
      ? choice.id === "reboot-window" && report.rebootHour !== null
        ? `On · ${String(Math.floor(fromUtcHour(report.rebootHour, offset()))).padStart(2, "0")}:00`
        : "On"
      : choice.outside
        ? "On · Set up outside Krynodes"
        : "Off";
  const actions = (choice: RecipeChoice) =>
    choice.blocked || choice.outside
      ? []
      : !choice.applied
        ? [
            {
              label: "Turn On",
              onSelect: () => setPending({ choice, turnOn: true }),
            },
          ]
        : [
            ...(choice.undo
              ? [
                  {
                    label: "Turn Off",
                    destructive: true,
                    onSelect: () => setPending({ choice, turnOn: false }),
                  },
                ]
              : []),
            ...(choice.id === "reboot-window"
              ? [
                  {
                    label: "Change",
                    onSelect: () => setPending({ choice, turnOn: true }),
                  },
                ]
              : []),
          ];
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2 lg:items-start">
        <section aria-labelledby="node-protections">
          <div className="mb-2 flex min-h-8 items-center gap-2">
            <h2 id="node-protections" className={sectionTitle}>
              Protections
            </h2>
            {steps.length > 0 && !notice && (
              <Button
                variant="outline"
                size="sm"
                className="ml-auto h-9 md:h-8"
                onClick={() => setPending({ recommend: steps })}
              >
                Apply {steps.length}
              </Button>
            )}
          </div>
          {notice ? (
            <p className="rounded-lg border bg-card px-3 py-2 text-sm text-muted-foreground">
              {notice}
            </p>
          ) : (
            <ul className="divide-y rounded-lg border bg-card text-sm">
              {choices
                .filter((choice) => choice.id !== "firewall")
                .map((choice) => {
                  const items = actions(choice);
                  const line =
                    choice.blocked ??
                    choice.hint ??
                    (choice.id === "ssh-keys-only" ? keysLine(report) : null);
                  return (
                    <li key={choice.id} className={ROW}>
                      <span className="min-w-0 flex-1">
                        <span className="block">{choice.title}</span>
                        {line && (
                          <span className="block text-xs text-muted-foreground">
                            {line}
                          </span>
                        )}
                      </span>
                      <span
                        className={cn(
                          "text-right font-mono text-xs text-muted-foreground",
                          offTone(choice, report) && "text-warning",
                        )}
                      >
                        {status(choice)}
                      </span>
                      {items.length === 0 ? (
                        <span className="size-9 shrink-0 md:size-8" />
                      ) : (
                        <RowMenu
                          label={`${choice.title} actions`}
                          items={items}
                        />
                      )}
                    </li>
                  );
                })}
              <li className={ROW}>
                <span className="min-w-0 flex-1">
                  <span className="block">{confine.title}</span>
                  {confine.line && (
                    <span className="block text-xs text-muted-foreground">
                      {confine.line}
                    </span>
                  )}
                </span>
                <span className="text-right font-mono text-xs text-muted-foreground">
                  {confine.status}
                </span>
                {confine.actions.length === 0 ? (
                  <span className="size-9 shrink-0 md:size-8" />
                ) : (
                  <RowMenu
                    label={`${confine.title} actions`}
                    items={confine.actions.map((step) => ({
                      ...CONFINE_LABELS[step],
                      onSelect: () => setConfining(step),
                    }))}
                  />
                )}
              </li>
            </ul>
          )}
        </section>
        <FirewallSection
          node={node}
          report={report}
          stacks={entry.stacks}
          choice={firewall}
          onTurnOn={(closing) =>
            setPending({ choice: firewall, turnOn: true, closing })
          }
        />
      </div>
      {notes.length > 0 && (
        <section aria-labelledby="security-notes">
          <h2
            id="security-notes"
            className={cn(sectionTitle, "mb-2 flex min-h-8 items-center")}
          >
            Notes
          </h2>
          <ul className="divide-y rounded-lg border bg-card text-sm">
            {notes.map((finding) => (
              <FindingRow
                key={finding.id}
                node={node}
                finding={finding}
                hint={null}
              />
            ))}
          </ul>
        </section>
      )}
      {found && confining === "denials" && (
        <DenialsDialog
          node={node}
          found={found}
          seen={seen}
          onClose={() => setConfining(null)}
        />
      )}
      {confining === "boolean" && (
        <BooleanDialog node={node} onClose={() => setConfining(null)} />
      )}
      {found &&
        confining &&
        confining !== "denials" &&
        confining !== "boolean" && (
          <ConfineDialog
            key={confining}
            node={node}
            found={found}
            step={confining}
            stacks={entry.stacks.map((stack) => stack.project)}
            onClose={() => setConfining(null)}
          />
        )}
      <RecipeDialog
        key={JSON.stringify(pending)}
        node={node}
        pending={pending}
        internet={internet}
        onClose={() => setPending(null)}
      />
    </div>
  );
}
