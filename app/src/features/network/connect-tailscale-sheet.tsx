import { TAILSCALE } from "@krynodes/protocol";
import { MIN_AGENT_VERSION } from "@krynodes/protocol/versions";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Said, SHEET, SignButton } from "@/features/packages/lines";
import { listOf } from "@/lib/network";
import { cn } from "@/lib/utils";
import { splitHolders } from "@/lib/vault";

import { CONSOLE, useConnect, useTailnet, type Started } from "./use-tailscale";

const TAG_LINE = `"${TAILSCALE.tag}": ["autogroup:admin"],`;
const SCOPES = [
  "Policy File Write",
  "Devices Core Write",
  "Auth Keys Write",
  `Tags ${TAILSCALE.tag}`,
];

function Copy({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button
      variant="outline"
      size="sm"
      onClick={() =>
        navigator.clipboard.writeText(text).then(
          () => setCopied(true),
          () => setCopied(false),
        )
      }
    >
      {copied ? "Copied" : "Copy"}
    </Button>
  );
}

function Out({ href, label }: { href: string; label: string }) {
  return (
    <Button asChild variant="outline" size="sm">
      <a href={href} target="_blank" rel="noreferrer">
        {label} ↗
      </a>
    </Button>
  );
}

function Step({
  number,
  title,
  children,
}: {
  number: number;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <li className="grid grid-cols-[24px_minmax(0,1fr)] gap-x-3 gap-y-2">
      <span className="flex size-6 items-center justify-center rounded-full border font-mono text-xs">
        {number}
      </span>
      <div className="min-w-0 space-y-2 text-sm">
        <p className="font-medium">{title}</p>
        {children}
      </div>
    </li>
  );
}

export function ConnectTailscaleSheet({
  change,
  onStarted,
  onClose,
}: {
  change: boolean;
  onStarted: (started: Started) => void;
  onClose: () => void;
}) {
  const { data, nodesFor } = useTailnet();
  const connect = useConnect();
  const [clientId, setClientId] = useState(data?.connected?.clientId ?? "");
  const [secret, setSecret] = useState("");
  const [webhookSecret, setWebhookSecret] = useState("");
  const tailnet =
    data?.connected?.tailnet ??
    data?.servers.find((server) => server.report?.tailnet)?.report?.tailnet ??
    null;
  const holders = splitHolders(nodesFor(null), "tailscale");
  const names = holders.map(
    (holder) =>
      data?.servers.find((server) => server.nodeId === holder.nodeId)?.name ??
      "--",
  );
  const problem = !tailnet
    ? "No server is on a tailnet yet. Sign one in from its Packages page first."
    : holders.length < 2
      ? `Connect needs two servers with agent ${MIN_AGENT_VERSION} that this device reaches; ${holders.length} is.`
      : null;
  const ready =
    problem === null &&
    clientId.trim().length > 0 &&
    secret.trim().startsWith("tskey-client-") &&
    (change || webhookSecret.trim().length > 0);

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className={cn(SHEET, "sm:max-w-[672px]")}>
        <DialogHeader>
          <DialogTitle>
            {change ? "Change Credential" : "Connect Tailscale"}
          </DialogTitle>
          <DialogDescription>
            {change
              ? "Make a new trust credential in Tailscale's admin console and paste it here. Delete the old one there once this is done."
              : "Steps 1, 2 and 4 happen in Tailscale's admin console. Paste what it gives you here."}
          </DialogDescription>
        </DialogHeader>
        <ol className="space-y-5">
          {!change && (
            <Step number={1} title="Let Krynodes use the tag kry">
              <p className="rounded-md border bg-background p-2.5 font-mono text-xs select-all">
                {TAG_LINE}
              </p>
              <p className="text-xs text-muted-foreground">
                Add it inside "tagOwners" in your policy file. Krynodes gives
                this tag to your servers only.
              </p>
              <div className="flex flex-wrap gap-2">
                <Copy text={TAG_LINE} />
                <Out href={CONSOLE.policy} label="Open Policy File" />
              </div>
            </Step>
          )}
          <Step number={change ? 1 : 2} title="Generate a Trust Credential">
            <ul className="flex flex-wrap gap-1.5">
              {SCOPES.map((scope) => (
                <li
                  key={scope}
                  className="rounded border px-1.5 py-0.5 font-mono text-xs"
                >
                  {scope}
                </li>
              ))}
            </ul>
            <p className="text-xs text-muted-foreground">
              Tailscale adds the read scopes the policy file needs by itself.
              Leave every other scope off.
            </p>
            <Out href={CONSOLE.credentials} label="Open Trust Credentials" />
          </Step>
          <Step number={change ? 2 : 3} title="Paste It Here">
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="tailscale-client">Client ID</Label>
                <Input
                  id="tailscale-client"
                  value={clientId}
                  autoComplete="off"
                  onChange={(event) => setClientId(event.target.value)}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="tailscale-secret">Client Secret</Label>
                <Input
                  id="tailscale-secret"
                  type="password"
                  value={secret}
                  autoComplete="off"
                  onChange={(event) => setSecret(event.target.value)}
                />
              </div>
            </div>
          </Step>
          <Step number={change ? 3 : 4} title="Add a Webhook">
            <div className="flex flex-wrap items-center gap-2">
              <span className="min-w-0 rounded-md border bg-background p-2 font-mono text-xs break-all select-all">
                {data?.hook ?? "--"}
              </span>
              {data?.hook && <Copy text={data.hook} />}
            </div>
            <p className="text-xs text-muted-foreground">
              {change
                ? "Krynodes keeps the webhook secret it has. Paste one only if you made a new webhook."
                : "Add it as an endpoint on the Webhooks page, with the events nodeCreated and policyUpdate. Then paste the secret Tailscale shows once."}
            </p>
            <Out href={CONSOLE.webhooks} label="Open Webhooks" />
            <div className="space-y-1.5">
              <Label htmlFor="tailscale-webhook">Webhook Secret</Label>
              <Input
                id="tailscale-webhook"
                type="password"
                value={webhookSecret}
                autoComplete="off"
                onChange={(event) => setWebhookSecret(event.target.value)}
              />
            </div>
          </Step>
        </ol>
        <div className="space-y-1 rounded-md border bg-background p-3 text-sm">
          <p className="font-medium">Where the Secret Goes</p>
          <p className="text-xs text-muted-foreground">
            {holders.length > 0
              ? `Your browser splits it into ${holders.length} pieces, one for each of ${listOf(names)}. Any two rebuild it, only for a change you sign with your fingerprint, and the server erases it after. Krynodes' Worker never sees it.`
              : `No server with agent ${MIN_AGENT_VERSION} that this device reaches can hold a piece yet.`}
          </p>
        </div>
        <Said text={problem} />
        <Said text={connect.error?.message ?? null} />
        {connect.isPending && (
          <p role="status" className="text-sm text-muted-foreground">
            {change
              ? "Your servers are storing the pieces…"
              : "Your servers are storing the pieces, then reading your policy file. This takes up to a minute."}
          </p>
        )}
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline">Cancel</Button>
          </DialogClose>
          <SignButton
            label={change ? "Change Credential" : "Connect"}
            pending={connect.isPending}
            disabled={!ready}
            onClick={() =>
              connect.mutate(
                {
                  secret,
                  clientId,
                  webhookSecret,
                  tailnet: tailnet ?? "",
                  change,
                },
                {
                  onSuccess: (started) => {
                    setSecret("");
                    setWebhookSecret("");
                    if (started) onStarted(started);
                    else onClose();
                  },
                },
              )
            }
          />
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
