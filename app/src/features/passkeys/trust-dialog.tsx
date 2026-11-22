import { useQueryClient, type QueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";

import { Busy } from "@/components/busy";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { deliver } from "@/features/actions/run-action";
import { failure } from "@/lib/passkeys";
import { queryKeys } from "@/lib/query-client";
import { buildChange, signChange, type TrustKey } from "@/lib/sign";
import { cn } from "@/lib/utils";
import type { Device, FleetNode } from "@/types";

export interface TrustStep {
  node: FleetNode;
  version: number;
  core: TrustKey[];
  access: Record<string, string[]>;
  adds: boolean;
}

interface Outcome {
  name: string;
  text: string;
  failed: boolean;
}

export function trustPlan(
  device: Device,
  devices: Device[],
  nodes: FleetNode[],
  wanted: ReadonlySet<string>,
): TrustStep[] | string {
  const steps: TrustStep[] = [];
  for (const node of nodes) {
    const trust = node.trust;
    if (!trust) continue;
    const adds = wanted.has(node.id);
    if (trust.core.includes(device.id) === adds) continue;
    if (!node.online) return `${node.name} is offline.`;
    const keep = (ids: string[]) => ids.filter((id) => id !== device.id);
    const core = adds ? [...trust.core, device.id] : keep(trust.core);
    const access = adds
      ? [...keep(trust.access), device.id]
      : keep(trust.access);
    if (core.length === 0) return `${node.name} would have no passkey left.`;
    if (access.length === 0) {
      return `${node.name} would have no passkey that can act on it.`;
    }
    const keys = core.map((id) => devices.find((entry) => entry.id === id));
    if (keys.some((key) => !key)) {
      return `${node.name} trusts a passkey that is not listed here.`;
    }
    steps.push({
      node,
      version: trust.version + 1,
      core: keys.map((key) => ({
        id: key!.id,
        name: key!.name,
        alg: key!.alg,
        publicKey: key!.publicKey,
      })),
      access: { [node.id]: access },
      adds,
    });
  }
  return steps;
}

export function unreported(nodes: FleetNode[]): string | null {
  const names = nodes.filter((node) => !node.trust).map((node) => node.name);
  if (names.length === 0) return null;
  return names.length === 1
    ? `${names[0]} has not reported its trust yet, so it is not listed.`
    : `${names.join(", ")} have not reported their trust yet, so they are not listed.`;
}

export async function applyTrust(
  client: QueryClient,
  input: {
    device: Device;
    devices: Device[];
    nodes: FleetNode[];
    wanted: ReadonlySet<string>;
    origin: string;
  },
  signal?: AbortSignal,
): Promise<Outcome[]> {
  const plan = trustPlan(
    input.device,
    input.devices,
    input.nodes,
    input.wanted,
  );
  if (typeof plan === "string") throw new Error(plan);
  const rpId = new URL(input.origin).hostname;
  const outcomes: Promise<Outcome>[] = [];
  for (const step of plan) {
    const name = step.node.name;
    let signed: string;
    try {
      signed = await signChange(
        buildChange({ origin: input.origin, ...step }),
        step.node.trust!.core,
        rpId,
      );
    } catch (error) {
      outcomes.push(
        Promise.resolve({ name, text: failure(error), failed: true }),
      );
      break;
    }
    outcomes.push(
      deliver(
        client,
        step.node,
        {
          id: crypto.randomUUID(),
          kind: "trust",
          action: "apply",
          title: `${step.adds ? "Trust" : "Stop Trusting"} ${input.device.name}`,
          signed,
        },
        undefined,
        signal,
      ).then(
        (row) => ({
          name,
          text: row.message ?? "--",
          failed: row.status === "failed",
        }),
        (error: unknown) => ({ name, text: failure(error), failed: true }),
      ),
    );
  }
  return Promise.all(outcomes);
}

export function TrustDialog({
  device,
  devices,
  nodes,
  onClose,
}: {
  device: Device;
  devices: Device[];
  nodes: FleetNode[];
  onClose: () => void;
}) {
  const client = useQueryClient();
  const listed = nodes.filter((node) => node.trust);
  const [wanted, setWanted] = useState<ReadonlySet<string>>(
    () =>
      new Set(
        listed
          .filter((node) => node.trust!.core.includes(device.id))
          .map((node) => node.id),
      ),
  );
  const [working, setWorking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [outcomes, setOutcomes] = useState<Outcome[] | null>(null);
  const plan = trustPlan(device, devices, nodes, wanted);
  const left = unreported(nodes);
  const quit = useRef<AbortController | null>(null);
  useEffect(() => () => quit.current?.abort(), []);

  const apply = () => {
    setWorking(true);
    setError(null);
    quit.current = new AbortController();
    void applyTrust(
      client,
      { device, devices, nodes, wanted, origin: window.location.origin },
      quit.current.signal,
    )
      .then(
        (done) => {
          setOutcomes(done);
          void client.invalidateQueries({ queryKey: queryKeys.devices });
        },
        (cause: unknown) => setError(failure(cause)),
      )
      .finally(() => setWorking(false));
  };

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Trust {device.name} on Servers</DialogTitle>
          <DialogDescription>
            Choose the servers that trust {device.name}. Each server that
            changes asks a passkey it trusts now to approve.
          </DialogDescription>
        </DialogHeader>
        {outcomes ? (
          <ul className="space-y-1 text-sm">
            {outcomes.map((outcome) => (
              <li
                key={outcome.name}
                role={outcome.failed ? "alert" : undefined}
                className={cn(outcome.failed && "text-destructive")}
              >
                {outcome.name}: {outcome.text}
              </li>
            ))}
          </ul>
        ) : listed.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No server has reported its trust yet.
          </p>
        ) : (
          <fieldset className="space-y-2" disabled={working}>
            <legend className="sr-only">Servers</legend>
            {listed.map((node) => (
              <label key={node.id} className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  className="size-4 accent-primary"
                  checked={wanted.has(node.id)}
                  disabled={!node.online}
                  onChange={(event) =>
                    setWanted((current) => {
                      const next = new Set(current);
                      if (event.target.checked) next.add(node.id);
                      else next.delete(node.id);
                      return next;
                    })
                  }
                />
                {node.name}
                {!node.online && (
                  <span className="text-muted-foreground">Offline</span>
                )}
              </label>
            ))}
          </fieldset>
        )}
        {!outcomes && listed.length > 0 && left && (
          <p className="text-sm text-muted-foreground">{left}</p>
        )}
        {!outcomes && typeof plan === "string" && (
          <p role="alert" className="text-sm text-destructive">
            {plan}
          </p>
        )}
        {error && (
          <p role="alert" className="text-sm text-destructive">
            {error}
          </p>
        )}
        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>
            {outcomes ? "Close" : "Cancel"}
          </Button>
          {!outcomes && (
            <Button
              disabled={
                working || typeof plan === "string" || plan.length === 0
              }
              onClick={apply}
            >
              {working ? <Busy>Applying</Busy> : "Apply"}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
