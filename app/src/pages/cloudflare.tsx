import { useState } from "react";
import { toast } from "sonner";

import { PageHeader } from "@/components/page-header";
import { StatusDot } from "@/components/status";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useSignedOperation } from "@/features/deploy/use-signed-action";
import { useCloudflare, useOverview, useServices } from "@/lib/api";
import { errorMessage } from "@/lib/http";
import {
  planSpread,
  reshareSteps,
  splitSteps,
  vaultNodes,
  type VaultNode,
} from "@/lib/vault";

const PERMISSIONS = [
  "Account · Cloudflare Tunnel · Edit",
  "Account · Access: Apps and Policies · Edit",
];

function Holders({
  nodes,
  setId,
}: {
  nodes: VaultNode[];
  setId: string | null;
}) {
  const holding = nodes.filter(
    (node) => setId !== null && node.vault?.set === setId,
  );
  const missing = nodes.filter(
    (node) => node.sealKey && !holding.includes(node),
  );
  return (
    <ul className="divide-y rounded-lg border bg-card text-sm">
      {holding.map((node) => (
        <li key={node.id} className="flex items-center gap-2 px-3 py-2.5">
          <StatusDot tone={node.online ? "ok" : "bad"} />
          <span className="truncate">{node.name}</span>
          <span className="ml-auto font-mono text-xs text-muted-foreground">
            {node.online ? "Holds a piece" : "Holds a piece · offline"}
          </span>
        </li>
      ))}
      {missing.map((node) => (
        <li key={node.id} className="flex items-center gap-2 px-3 py-2.5">
          <StatusDot tone="warn" />
          <span className="truncate">{node.name}</span>
          <span className="ml-auto font-mono text-xs text-muted-foreground">
            No piece yet
          </span>
        </li>
      ))}
      {holding.length === 0 && missing.length === 0 && (
        <li className="px-3 py-2.5 text-muted-foreground">
          No server runs agent 0.5.0 yet.
        </li>
      )}
    </ul>
  );
}

export function CloudflarePage() {
  const overview = useOverview();
  const services = useServices();
  const settings = useCloudflare();
  const operate = useSignedOperation(false);
  const [token, setToken] = useState("");
  const [zone, setZone] = useState<string | null>(null);
  const seen = overview.dataUpdatedAt;
  const nodes =
    services.data && overview.data
      ? vaultNodes(services.data, overview.data.nodes, null, seen)
      : [];
  const setId = settings.data?.setId ?? null;
  const chosenZone = zone ?? settings.data?.zone ?? "";
  const holding = nodes.filter(
    (node) => setId !== null && node.vault?.set === setId,
  );
  const stale =
    setId !== null &&
    nodes.some((node) => node.sealKey && node.vault?.set !== setId);
  const nodesFor = (fingerprint: string) =>
    services.data && overview.data
      ? vaultNodes(services.data, overview.data.nodes, fingerprint, seen)
      : [];

  const split = () =>
    operate.mutate(
      {
        kind: "split",
        zone: chosenZone,
        reach: [],
        build: (fingerprint) => {
          const holders = nodesFor(fingerprint)
            .filter((node) => node.reachable && node.sealKey)
            .map((node) => ({ nodeId: node.id, sealKey: node.sealKey! }));
          if (holders.length === 0) {
            throw new Error("This device reaches no server with agent 0.5.0.");
          }
          return splitSteps(token, holders, crypto.randomUUID());
        },
      },
      {
        onSuccess: (batch) => {
          setToken("");
          toast.success(
            `The token is being split across ${batch.actions.length} ${batch.actions.length === 1 ? "server" : "servers"}.`,
          );
        },
      },
    );

  const spread = () =>
    operate.mutate(
      {
        kind: "reshare",
        reach: [],
        build: (fingerprint) => {
          const all = nodesFor(fingerprint);
          const plan = planSpread(all, setId);
          if (!plan.ok) throw new Error(plan.reason);
          return reshareSteps({
            releaser: plan.releaser,
            assembler: plan.assembler,
            holders: plan.holders,
            keyOf: Object.fromEntries(
              all.map((node) => [node.id, node.sealKey ?? ""]),
            ),
            set: crypto.randomUUID(),
            zone: chosenZone,
            forgets: plan.forgets,
          });
        },
      },
      { onSuccess: () => toast.success("Spreading the token again.") },
    );

  return (
    <>
      <PageHeader
        title="Cloudflare"
        meta={
          <span className="font-mono text-xs text-muted-foreground">
            Web addresses use this token
          </span>
        }
      />
      <div className="max-w-2xl space-y-8">
        <section aria-labelledby="pieces" className="space-y-3">
          <h2
            id="pieces"
            className="text-[11px] tracking-wider text-muted-foreground uppercase"
          >
            Where the token is
          </h2>
          <p className="text-sm text-muted-foreground">
            The token is split into pieces, one for each server this device can
            reach. Any two pieces rebuild it for a few seconds, and only after a
            fingerprint. One piece alone is useless.
          </p>
          <Holders nodes={nodes} setId={setId} />
          {settings.data?.expiresAt && (
            <p className="font-mono text-xs text-muted-foreground">
              Expires{" "}
              {new Date(settings.data.expiresAt).toLocaleDateString(undefined, {
                day: "numeric",
                month: "short",
                year: "numeric",
              })}
            </p>
          )}
          {stale && holding.length > 0 && (
            <Button
              variant="outline"
              disabled={operate.isPending}
              onClick={spread}
            >
              Spread again
            </Button>
          )}
        </section>

        <section aria-labelledby="paste" className="space-y-3">
          <h2
            id="paste"
            className="text-[11px] tracking-wider text-muted-foreground uppercase"
          >
            {setId ? "Replace token" : "Add a token"}
          </h2>
          <p className="text-sm text-muted-foreground">
            In Cloudflare, make an API token with only these permissions and an
            end date a year from now:
          </p>
          <ul className="list-disc space-y-1 pl-5 font-mono text-xs">
            {PERMISSIONS.map((permission) => (
              <li key={permission}>{permission}</li>
            ))}
            <li>Zone · DNS · Edit, for {chosenZone || "your zone"} only</li>
          </ul>
          <a
            className="text-sm underline underline-offset-4"
            href="https://dash.cloudflare.com/profile/api-tokens"
            target="_blank"
            rel="noreferrer"
          >
            Open Cloudflare API tokens
          </a>
          <div className="space-y-2">
            <Label htmlFor="cloudflare-zone">Zone</Label>
            <Input
              id="cloudflare-zone"
              value={chosenZone}
              autoComplete="off"
              onChange={(event) => setZone(event.target.value.trim())}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="cloudflare-token">Token</Label>
            <Input
              id="cloudflare-token"
              type="password"
              value={token}
              autoComplete="off"
              onChange={(event) => setToken(event.target.value)}
            />
          </div>
          {operate.error && (
            <p role="alert" className="text-sm text-destructive">
              {errorMessage(operate.error)}
            </p>
          )}
          <Button
            disabled={
              operate.isPending || token.trim().length < 20 || !chosenZone
            }
            onClick={split}
          >
            {operate.isPending
              ? "Waiting for the fingerprint…"
              : "Split across my servers"}
          </Button>
        </section>
      </div>
    </>
  );
}
