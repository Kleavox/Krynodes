import { Fingerprint } from "lucide-react";
import { useState } from "react";
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
import { orchestrationReady } from "@/lib/devices";
import { timeAgo } from "@/lib/format";
import { errorMessage } from "@/lib/http";
import {
  firewallPorts,
  fromUtcHour,
  recipeChoices,
  recommended,
  toUtcHour,
  type RecipeChoice,
} from "@/lib/security";
import type { Finding, NodeRecord } from "@/types";

const sectionTitle =
  "mb-3 text-[11px] tracking-wider text-muted-foreground uppercase";

const DETAIL: Record<string, string> = {
  "security-updates":
    "Installs security updates every day with Debian's own unattended-upgrades.",
  "reboot-window":
    "When an update needs a restart, the server restarts at the hour you choose, at most once a day.",
  "ssh-keys-only":
    "SSH stops accepting passwords; keys keep working. If you get locked out, Krynodes can turn passwords back on.",
  fail2ban: "Blocks addresses that keep failing to log in over SSH.",
  firewall:
    "Turns on ufw and keeps SSH and the ports you tick open. Ports published by Docker are not affected.",
  "free-port-53":
    "Stops systemd-resolved from holding port 53, so a DNS server such as AdGuard can use it.",
};

const tone = (finding: Finding) =>
  finding.severity === "serious"
    ? "bad"
    : finding.severity === "warning"
      ? "warn"
      : "idle";

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
  const argsFor = (id: string): Record<string, string> | undefined =>
    id === "reboot-window"
      ? { hour: String(Math.floor(toUtcHour(Number(hour), offset()))) }
      : id === "firewall"
        ? { ports: ports.join(",") }
        : undefined;
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
                <p key={id}>{DETAIL[id]}</p>
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
            {!run.isPending && <Fingerprint aria-hidden="true" />}
            {run.isPending
              ? "Waiting for the fingerprint…"
              : recommend
                ? "Apply"
                : turnOn
                  ? "Turn on"
                  : "Turn off"}
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
  const entry = services.data?.nodes.find((item) => item.id === node.id);
  const report = entry?.security;
  if (!orchestrationReady(node) || !report) return null;
  const choices = recipeChoices(report);
  const steps = recommended(report);
  const internet = (entry?.stacks ?? []).flatMap((stack) =>
    stack.access === "full" ? (stack.public ?? []) : [],
  );
  const order = { serious: 0, warning: 1, note: 2 };
  const findings = [...report.findings].sort(
    (a, b) => order[a.severity] - order[b.severity],
  );
  return (
    <section
      aria-labelledby="node-security"
      className="rounded-lg border bg-card p-4"
    >
      <div className="mb-3 flex items-center gap-2">
        <h2 id="node-security" className={sectionTitle + " mb-0"}>
          Security
        </h2>
        <span className="ml-auto font-mono text-xs text-muted-foreground">
          Checked {timeAgo(report.checkedAt, seen)}
        </span>
        <Button
          variant="ghost"
          size="sm"
          className="h-8"
          disabled={scan.isPending}
          onClick={() => scan.mutate(node.id)}
        >
          Check now
        </Button>
      </div>
      <ul className="space-y-1.5 text-sm">
        {findings.map((finding) => (
          <li key={finding.id} className="flex gap-2">
            <StatusDot tone={tone(finding)} />
            <span className="min-w-0">{finding.detail}</span>
          </li>
        ))}
      </ul>
      <h3 className="mt-4 mb-2 text-xs font-medium text-muted-foreground">
        Protections
      </h3>
      <ul className="divide-y rounded-md border text-sm">
        {choices.map((choice) => (
          <li key={choice.id} className="flex items-center gap-2 px-3 py-2">
            <span className="min-w-0 flex-1">
              <span className="block truncate">{choice.title}</span>
              {choice.blocked && (
                <span className="block text-xs text-muted-foreground">
                  {choice.blocked}
                </span>
              )}
            </span>
            <span className="font-mono text-xs text-muted-foreground">
              {choice.applied
                ? choice.id === "reboot-window" && report.rebootHour !== null
                  ? `On · ${String(Math.floor(fromUtcHour(report.rebootHour, offset()))).padStart(2, "0")}:00`
                  : "On"
                : "Off"}
            </span>
            {choice.blocked ? (
              <span className="size-9 md:size-8" />
            ) : (
              <RowMenu
                label={`${choice.title} actions`}
                items={
                  choice.applied
                    ? [
                        {
                          label: "Turn off",
                          destructive: true,
                          onSelect: () => setPending({ choice, turnOn: false }),
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
                          label: "Turn on",
                          onSelect: () => setPending({ choice, turnOn: true }),
                        },
                      ]
                }
              />
            )}
          </li>
        ))}
      </ul>
      {steps.length > 0 && (
        <Button
          className="mt-3 w-full"
          variant="outline"
          onClick={() => setPending({ recommend: steps })}
        >
          Apply recommended · {steps.length}
        </Button>
      )}
      <RecipeDialog
        node={node}
        pending={pending}
        internet={internet}
        onClose={() => setPending(null)}
      />
    </section>
  );
}
