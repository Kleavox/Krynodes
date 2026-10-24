import { Fingerprint } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router";
import { toast } from "sonner";

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
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useSignedAction } from "@/features/deploy/use-signed-action";
import { useScan, useServices } from "@/lib/api";
import { agentCurrent } from "@/lib/devices";
import { timeAgo } from "@/lib/format";
import { errorMessage } from "@/lib/http";
import {
  findingTone,
  firewallPorts,
  protectionDetail,
  protectionsNotice,
  protectionsText,
  fromUtcHour,
  recipeChoices,
  recommended,
  shownFindings,
  toUtcHour,
  type RecipeChoice,
} from "@/lib/security";
import { cn } from "@/lib/utils";
import type { NodeRecord } from "@/types";

const sectionTitle = "text-xs font-medium text-muted-foreground";

const offset = () => new Date().getTimezoneOffset();

type Pending =
  { choice: RecipeChoice; turnOn: boolean } | { recommend: string[] };

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
  const report = services.data?.nodes.find(
    (entry) => entry.id === node.id,
  )?.security;
  const [hour, setHour] = useState("3");
  const [ticked, setTicked] = useState<string[] | null>(null);
  const [anyway, setAnyway] = useState(false);
  const platform = report?.platform;
  const suggested = report
    ? [...new Set([...firewallPorts(report), ...internet])]
    : internet;
  const ports = ticked ?? suggested;
  if (!pending) return null;
  const recommend = "recommend" in pending ? pending.recommend : null;
  const choice = "choice" in pending ? pending.choice : null;
  const turnOn = "turnOn" in pending ? pending.turnOn : true;
  const ids = recommend ?? [choice!.id];
  const needsHour = turnOn && ids.includes("reboot-window");
  const firewall = turnOn && ids.includes("firewall");
  const needsAnyway =
    turnOn &&
    !!platform &&
    !platform.verified &&
    ids.some((id) => id !== "reboot-window");
  const argsFor = (id: string): Record<string, string> | undefined => {
    const args = {
      ...(id === "reboot-window"
        ? { hour: String(Math.floor(toUtcHour(Number(hour), offset()))) }
        : {}),
      ...(id === "firewall" ? { ports: ports.join(",") } : {}),
      ...(anyway ? { anyway: "yes" } : {}),
    };
    return Object.keys(args).length > 0 ? args : undefined;
  };
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
              : `${turnOn ? "Turn on" : "Turn off"} ${choice!.title.toLowerCase()} on ${node.name}?`}
          </AlertDialogTitle>
          <AlertDialogDescription asChild>
            <div className="space-y-2">
              {ids.map((id) => (
                <p key={id}>{report ? protectionDetail(id, report) : null}</p>
              ))}
              {!turnOn && (
                <p>The file Krynodes added is removed; nothing else changes.</p>
              )}
            </div>
          </AlertDialogDescription>
        </AlertDialogHeader>
        {needsHour && (
          <div className="space-y-1.5">
            <Label htmlFor="reboot-hour">Restart hour (your time)</Label>
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
        {firewall && (
          <fieldset className="space-y-1.5">
            <legend className="text-sm font-medium">
              Keep these ports open too
            </legend>
            {suggested.length === 0 ? (
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
                    onChange={() =>
                      setTicked(
                        ports.includes(port)
                          ? ports.filter((item) => item !== port)
                          : [...ports, port],
                      )
                    }
                  />
                  {port}
                </label>
              ))
            )}
            <p className="text-xs text-muted-foreground">
              SSH always stays open.
            </p>
          </fieldset>
        )}
        {needsAnyway && (
          <label className="flex items-start gap-2 text-sm">
            <input
              type="checkbox"
              className="mt-1"
              checked={anyway}
              onChange={() => setAnyway(!anyway)}
            />
            Run it on {platform.name} anyway
          </label>
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
            disabled={run.isPending || (needsAnyway && !anyway)}
            onClick={submit}
          >
            {!run.isPending && <Fingerprint aria-hidden="true" />}
            {run.isPending
              ? "Waiting for the Fingerprint…"
              : recommend
                ? "Apply"
                : turnOn
                  ? "Turn On"
                  : "Turn Off"}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

export function SecurityPanel({
  node,
  seen,
}: {
  node: NodeRecord;
  seen: number;
}) {
  const services = useServices();
  const scan = useScan();
  const [pending, setPending] = useState<Pending | null>(null);
  const [listing, setListing] = useState(false);
  const entry = services.data?.nodes.find((item) => item.id === node.id);
  const report = entry?.security;
  if (!agentCurrent(node) || !report) return null;
  const choices = recipeChoices(report);
  const steps = recommended(report);
  const internet = (entry?.stacks ?? []).flatMap((stack) =>
    stack.access === "full" ? (stack.public ?? []) : [],
  );
  const notice = protectionsNotice(report);
  const unsupported = report.platform?.family === null;
  const findings = shownFindings(report);
  return (
    <section aria-labelledby="node-security">
      <div className="mb-2 flex min-h-8 items-center gap-2">
        <h2 id="node-security" className={sectionTitle}>
          Security
        </h2>
        <span className="font-mono text-[11px] text-muted-foreground">
          Checked {timeAgo(report.checkedAt, seen)}
        </span>
        <Button
          variant="ghost"
          size="sm"
          className="ml-auto h-8"
          disabled={scan.isPending}
          onClick={() => scan.mutate(node.id)}
        >
          Check Now
        </Button>
      </div>
      <div className="divide-y rounded-lg border bg-card">
        {findings.length > 0 && (
          <ul className="space-y-1.5 p-3 text-sm">
            {findings.map((finding) => (
              <li key={finding.id} className="flex gap-2">
                <span className="pt-1.5">
                  <StatusDot tone={findingTone(finding)} />
                </span>
                <span className="min-w-0">
                  {finding.detail}
                  {finding.id === "public-ports" && (
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
              </li>
            ))}
          </ul>
        )}
        <div className="flex flex-wrap items-center gap-2 px-3 py-2">
          <button
            type="button"
            onClick={() => setListing(true)}
            className="min-w-0 flex-1 text-left text-sm underline-offset-4 hover:underline"
          >
            {protectionsText(report)}
          </button>
          {steps.length > 0 && !unsupported && (
            <Button
              variant="outline"
              size="sm"
              className="h-9 md:h-8"
              onClick={() => setPending({ recommend: steps })}
            >
              Apply {steps.length}
            </Button>
          )}
        </div>
      </div>
      <Dialog open={listing} onOpenChange={setListing}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Protections on {node.name}</DialogTitle>
            <DialogDescription>
              {notice ?? protectionsText(report)}
            </DialogDescription>
          </DialogHeader>
          <ul
            className={cn(
              "divide-y rounded-md border text-sm",
              unsupported && "hidden",
            )}
          >
            {choices.map((choice) => (
              <li key={choice.id} className="flex items-center gap-2 px-3 py-2">
                <span className="min-w-0 flex-1">
                  <span className="block">{choice.title}</span>
                  {(choice.blocked ?? choice.hint) && (
                    <span className="block text-xs text-muted-foreground">
                      {choice.blocked ?? choice.hint}
                    </span>
                  )}
                </span>
                <span className="font-mono text-xs text-muted-foreground">
                  {choice.applied
                    ? choice.id === "reboot-window" &&
                      report.rebootHour !== null
                      ? `On · ${String(Math.floor(fromUtcHour(report.rebootHour, offset()))).padStart(2, "0")}:00`
                      : "On"
                    : choice.outside
                      ? "On · Set up outside Krynodes"
                      : "Off"}
                </span>
                {choice.blocked || choice.outside ? (
                  <span className="size-9 md:size-8" />
                ) : (
                  <RowMenu
                    label={`${choice.title} actions`}
                    items={
                      choice.applied
                        ? [
                            {
                              label: "Turn Off",
                              destructive: true,
                              onSelect: () =>
                                setPending({ choice, turnOn: false }),
                            },
                            ...(choice.id === "reboot-window"
                              ? [
                                  {
                                    label: "Change",
                                    onSelect: () =>
                                      setPending({ choice, turnOn: true }),
                                  },
                                ]
                              : []),
                          ]
                        : [
                            {
                              label: "Turn On",
                              onSelect: () =>
                                setPending({ choice, turnOn: true }),
                            },
                          ]
                    }
                  />
                )}
              </li>
            ))}
          </ul>
        </DialogContent>
      </Dialog>
      <RecipeDialog
        key={JSON.stringify(pending)}
        node={node}
        pending={pending}
        internet={internet}
        onClose={() => setPending(null)}
      />
    </section>
  );
}
