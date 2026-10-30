import { KeyRound } from "lucide-react";
import { useState, type ReactNode } from "react";
import { toast } from "sonner";

import { Waiting } from "@/components/busy";
import { RowMenu } from "@/components/row-menu";
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
import { Input } from "@/components/ui/input";
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
import { agentCurrent } from "@/lib/devices";
import {
  addressesOf,
  fromArg,
  fromText,
  listensText,
  MAX_ADDRESSES,
  openingKey,
  openPortProblem,
} from "@/lib/firewall";
import { errorMessage } from "@/lib/http";
import { firewallRow, inside } from "@/lib/network";
import { firewallName } from "@/lib/security";
import { cn } from "@/lib/utils";
import type { FirewallOpening, NodeRecord } from "@/types";

const sectionTitle = "text-xs font-medium text-muted-foreground";

const AREA =
  "w-full resize-y rounded-md border bg-transparent px-3 py-2 font-mono text-xs shadow-xs outline-none focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50";

const FROM: { value: FirewallOpening["from"]; label: string }[] = [
  { value: "everyone", label: "Everyone" },
  { value: "tailscale", label: "Tailscale" },
  { value: "addresses", label: "Addresses" },
];

type Step =
  | { step: "open" }
  | { step: "from"; opening: FirewallOpening }
  | {
      step: "close";
      opening: FirewallOpening;
      listens: { text: string; idle: boolean };
    }
  | { step: "putback"; rule: string; drift: boolean };

function Row({
  title,
  line,
  tone = "idle",
  menu,
}: {
  title: ReactNode;
  line: string;
  tone?: "idle" | "plain" | "warn";
  menu?: ReactNode;
}) {
  return (
    <li className="flex items-center gap-2 px-3 py-2">
      <span className="min-w-0 flex-1">
        <span className="block break-all">{title}</span>
        <span
          className={cn(
            "block text-xs",
            tone === "idle" && "text-muted-foreground",
            tone === "warn" && "text-warning",
          )}
        >
          {line}
        </span>
      </span>
      {menu ?? <span className="size-9 md:size-8" />}
    </li>
  );
}

function FirewallDialog({
  node,
  step,
  open,
  networkPort,
  tool,
  onClose,
}: {
  node: NodeRecord;
  step: Step;
  open: FirewallOpening[];
  networkPort: string | null;
  tool: string;
  onClose: () => void;
}) {
  const run = useSignedAction(false);
  const start = step.step === "from" ? step.opening : null;
  const [port, setPort] = useState("");
  const [protocol, setProtocol] = useState<FirewallOpening["protocol"]>("tcp");
  const [from, setFrom] = useState(start?.from ?? "everyone");
  const [typed, setTyped] = useState((start?.addresses ?? []).join("\n"));
  const [reviewing, setReviewing] = useState(false);
  const typing = step.step === "open" || step.step === "from";
  const listed = addressesOf(typed);
  const opening: FirewallOpening = {
    ...(step.step === "open"
      ? { port: Number(port), protocol }
      : step.step === "putback"
        ? { port: 0, protocol: "tcp" }
        : { port: step.opening.port, protocol: step.opening.protocol }),
    from,
    ...(from === "addresses" ? { addresses: listed.addresses } : {}),
  };
  const key = openingKey(opening);
  const problem =
    (step.step === "open"
      ? openPortProblem(port, protocol, open, networkPort)
      : null) ?? (from === "addresses" ? listed.problem : null);
  const unchanged =
    step.step === "from" && fromArg(step.opening) === fromArg(opening);
  const send = () =>
    run.mutate(
      {
        action:
          step.step === "close"
            ? "close"
            : step.step === "putback"
              ? "putback"
              : "open",
        targets: [
          {
            nodeId: node.id,
            kind: "host",
            name: "firewall",
            args:
              step.step === "putback"
                ? { rule: step.rule }
                : step.step === "close"
                  ? { port: String(opening.port), protocol: opening.protocol }
                  : {
                      port: String(opening.port),
                      protocol: opening.protocol,
                      from: fromArg(opening),
                    },
          },
        ],
      },
      {
        onSuccess: () => {
          toast.success(`Sent to ${node.name}.`);
          onClose();
        },
      },
    );
  const title =
    step.step === "open"
      ? reviewing
        ? `Open ${key} on ${node.name}?`
        : `Open Port on ${node.name}`
      : step.step === "from"
        ? reviewing
          ? `Change who reaches ${key} on ${node.name}?`
          : `Who Reaches ${key} on ${node.name}`
        : step.step === "close"
          ? `Close ${key} on ${node.name}?`
          : step.drift
            ? `Put back the firewall on ${node.name}?`
            : `Remove this rule on ${node.name}?`;
  const lines =
    step.step === "close"
      ? [
          step.listens.idle
            ? `Nothing listens on ${key} now. SSH stays open.`
            : `${step.listens.text} can no longer be reached from outside on ${key}. SSH stays open.`,
        ]
      : step.step === "putback"
        ? [
            `Takes this rule out of ${tool}. ${step.drift ? "It was added outside Krynodes." : "It was there before Krynodes closed the firewall."}`,
          ]
        : reviewing
          ? [
              opening.from === "everyone"
                ? `Anyone on the internet can reach ${key}.`
                : opening.from === "tailscale"
                  ? `Only devices on your tailnet can reach ${key}.`
                  : `Only ${fromText(opening)} can reach ${key}.`,
            ]
          : [
              `Opens a port in ${tool}. SSH and the private network stay open as they are.`,
            ];
  const direct = step.step === "close" || step.step === "putback";
  return (
    <AlertDialog open onOpenChange={(next) => !next && onClose()}>
      <AlertDialogContent className="max-sm:top-auto max-sm:bottom-0 max-sm:translate-y-0 max-sm:rounded-b-none">
        <AlertDialogHeader>
          <AlertDialogTitle>{title}</AlertDialogTitle>
          <AlertDialogDescription asChild>
            <div className="space-y-2">
              {lines.map((line) => (
                <p key={line}>{line}</p>
              ))}
              {step.step === "putback" && (
                <p className="font-mono text-xs break-all">{step.rule}</p>
              )}
            </div>
          </AlertDialogDescription>
        </AlertDialogHeader>
        {typing && !reviewing && (
          <div className="space-y-3">
            {step.step === "open" && (
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <Label htmlFor="firewall-port">Port</Label>
                  <Input
                    id="firewall-port"
                    inputMode="numeric"
                    autoComplete="off"
                    className="font-mono"
                    value={port}
                    onChange={(event) => setPort(event.target.value.trim())}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="firewall-protocol">Protocol</Label>
                  <Select
                    value={protocol}
                    onValueChange={(value) =>
                      setProtocol(value as FirewallOpening["protocol"])
                    }
                  >
                    <SelectTrigger id="firewall-protocol" className="w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="tcp">TCP</SelectItem>
                      <SelectItem value="udp">UDP</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
            )}
            <fieldset className="space-y-1.5">
              <legend className="text-sm font-medium">From</legend>
              {FROM.map((choice) => (
                <label
                  key={choice.value}
                  className="flex cursor-pointer items-center gap-2 text-sm"
                >
                  <input
                    type="radio"
                    name="firewall-from"
                    checked={from === choice.value}
                    onChange={() => setFrom(choice.value)}
                  />
                  {choice.label}
                </label>
              ))}
              {from === "addresses" && (
                <textarea
                  aria-label="Addresses"
                  value={typed}
                  rows={3}
                  spellCheck={false}
                  autoCapitalize="off"
                  onChange={(event) => setTyped(event.target.value)}
                  className={AREA}
                />
              )}
              <p className="text-xs text-muted-foreground">
                {from === "tailscale"
                  ? "Only from devices on your tailnet, through tailscale0."
                  : from === "addresses"
                    ? `IPv4 or IPv6 addresses or ranges, one per line, up to ${MAX_ADDRESSES}.`
                    : "From anywhere on the internet."}
              </p>
            </fieldset>
            {problem && (port !== "" || from === "addresses") && (
              <p role="alert" className="text-xs text-destructive">
                {problem}
              </p>
            )}
          </div>
        )}
        {run.error && (
          <p role="alert" className="text-sm text-destructive">
            {errorMessage(run.error)}
          </p>
        )}
        <AlertDialogFooter>
          {direct || reviewing ? (
            <>
              {reviewing ? (
                <Button
                  variant="outline"
                  disabled={run.isPending}
                  onClick={() => {
                    run.reset();
                    setReviewing(false);
                  }}
                >
                  Back
                </Button>
              ) : (
                <AlertDialogCancel>Cancel</AlertDialogCancel>
              )}
              <Button
                variant={direct ? "destructive" : "default"}
                disabled={run.isPending}
                onClick={send}
              >
                <KeyRound aria-hidden="true" />
                {run.isPending ? (
                  <Waiting />
                ) : step.step === "close" ? (
                  "Close Port"
                ) : step.step === "putback" ? (
                  step.drift ? (
                    "Put Back"
                  ) : (
                    "Remove Rule"
                  )
                ) : step.step === "from" ? (
                  "Change From"
                ) : (
                  "Open Port"
                )}
              </Button>
            </>
          ) : (
            <>
              <AlertDialogCancel>Cancel</AlertDialogCancel>
              <Button
                disabled={problem !== null || unchanged}
                onClick={() => setReviewing(true)}
              >
                Review
              </Button>
            </>
          )}
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

export function FirewallSection({ node }: { node: NodeRecord }) {
  const services = useServices();
  const view = useNetwork().data;
  const [step, setStep] = useState<Step | null>(null);
  const entry = services.data?.nodes.find((item) => item.id === node.id);
  const report = entry?.security;
  const wall = report?.firewall;
  if (!agentCurrent(node) || !report || !wall?.closed) return null;
  const stacks = entry?.stacks ?? [];
  const member = view && inside(view).find((item) => item.nodeId === node.id);
  const locked = member ? firewallRow(member) : null;
  const tool = firewallName(report);
  return (
    <section aria-labelledby="node-firewall">
      <div className="mb-2 flex min-h-8 items-center gap-2">
        <h2 id="node-firewall" className={sectionTitle}>
          Firewall
        </h2>
        <span className="font-mono text-[11px] text-muted-foreground">
          {tool} · Closed
        </span>
        <Button
          variant="ghost"
          size="sm"
          className="ml-auto h-8"
          onClick={() => setStep({ step: "open" })}
        >
          Open Port
        </Button>
      </div>
      <ul className="divide-y rounded-lg border bg-card text-sm">
        <Row title="SSH" line="Always open" />
        {locked && (
          <Row
            title={
              <>
                <span className="font-mono">{locked.port}</span> · Private
                network
              </>
            }
            line="Always open"
          />
        )}
        {wall.open.map((opening) => {
          const key = openingKey(opening);
          const listens = listensText(key, report, stacks);
          return (
            <Row
              key={key}
              title={
                <>
                  <span className="font-mono">{key}</span> · {fromText(opening)}
                </>
              }
              line={listens.text}
              tone={listens.idle ? "idle" : "plain"}
              menu={
                <RowMenu
                  label={`${key} actions`}
                  items={[
                    {
                      label: "Change From",
                      onSelect: () => setStep({ step: "from", opening }),
                    },
                    {
                      label: "Close Port",
                      destructive: true,
                      onSelect: () =>
                        setStep({ step: "close", opening, listens }),
                    },
                  ]}
                />
              }
            />
          );
        })}
        {(wall.drift ?? []).map((rule) => (
          <Row
            key={`drift:${rule}`}
            title={<span className="font-mono text-xs">{rule}</span>}
            line="Added outside Krynodes"
            tone="warn"
            menu={
              <RowMenu
                label="Rule actions"
                items={[
                  {
                    label: "Put Back",
                    destructive: true,
                    onSelect: () =>
                      setStep({ step: "putback", rule, drift: true }),
                  },
                ]}
              />
            }
          />
        ))}
        {wall.other.map((rule) => (
          <Row
            key={`kept:${rule}`}
            title={<span className="font-mono text-xs">{rule}</span>}
            line="Kept as it was"
            menu={
              <RowMenu
                label="Rule actions"
                items={[
                  {
                    label: "Remove Rule",
                    destructive: true,
                    onSelect: () =>
                      setStep({ step: "putback", rule, drift: false }),
                  },
                ]}
              />
            }
          />
        ))}
      </ul>
      {step && (
        <FirewallDialog
          key={JSON.stringify(step)}
          node={node}
          step={step}
          open={wall.open}
          networkPort={locked?.port ?? null}
          tool={tool}
          onClose={() => setStep(null)}
        />
      )}
    </section>
  );
}
