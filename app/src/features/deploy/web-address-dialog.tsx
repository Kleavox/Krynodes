import { Fingerprint } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useCloudflare, useOverview, useServices } from "@/lib/api";
import { portsOf, servicesOf } from "@/lib/compose";
import { errorMessage } from "@/lib/http";
import {
  addressProblem,
  exposeSteps,
  hostnameFor,
  planAddress,
  unexposeSteps,
  vaultNodes,
} from "@/lib/vault";
import type { WebAddress } from "@/types";

import { Reading, SHEET, type StackTarget } from "./compose-dialog";
import { useComposeRead } from "./use-compose-read";
import { useSignedOperation } from "./use-signed-action";

type Mode = WebAddress["mode"];

const MODES: { value: Mode; label: string; detail: string }[] = [
  {
    value: "allow",
    label: "Only people I allow",
    detail: "The same login as the Krynodes dashboard guards the whole site.",
  },
  {
    value: "path",
    label: "Login only for a path",
    detail:
      "Pages under the path need the login; the rest stays public, like listmonk's subscription pages.",
  },
  {
    value: "everyone",
    label: "Everyone",
    detail: "No login in front. The app's own login protects it.",
  },
];

function usePlan(nodeId: string) {
  const services = useServices();
  const overview = useOverview();
  const settings = useCloudflare();
  const nodes =
    services.data && overview.data
      ? vaultNodes(
          services.data,
          overview.data.nodes,
          null,
          overview.dataUpdatedAt,
        )
      : [];
  const setId = settings.data?.setId ?? null;
  return {
    settings: settings.data,
    plan: setId === null ? null : planAddress(nodes, nodeId, setId),
  };
}

function NoToken() {
  return (
    <p className="text-sm text-muted-foreground">
      Add a Cloudflare token first under{" "}
      <Link to="/settings/cloudflare" className="underline underline-offset-4">
        Settings, Cloudflare
      </Link>
      .
    </p>
  );
}

export function WebAddressDialog({
  target,
  open,
  onOpenChange,
}: {
  target: StackTarget;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      {open && <OpenForm target={target} onClose={() => onOpenChange(false)} />}
    </Dialog>
  );
}

function OpenForm({
  target,
  onClose,
}: {
  target: StackTarget;
  onClose: () => void;
}) {
  const { read, failure, retry } = useComposeRead({
    nodeId: target.nodeId,
    name: target.project,
  });
  const { settings, plan } = usePlan(target.nodeId);
  const operate = useSignedOperation(false);
  const names = read ? servicesOf(read.compose) : [];
  const [service, setService] = useState<string | null>(null);
  const chosen = service ?? names[0] ?? "";
  const ports = read && chosen ? portsOf(read.compose, chosen) : [];
  const [port, setPort] = useState<string | null>(null);
  const chosenPort = port ?? (ports[0] ? String(ports[0]) : "");
  const [mode, setMode] = useState<Mode>("allow");
  const [path, setPath] = useState("/admin");
  const zone = settings?.zone ?? "";
  const suggested = hostnameFor(target.project, target.nodeName, zone).replace(
    `.${zone}`,
    "",
  );
  const [label, setLabel] = useState<string | null>(null);
  const hostname = `${label ?? suggested}.${zone}`;
  const needsLogin = mode !== "everyone";
  const blocked = !settings?.setId
    ? "token"
    : plan && !plan.ok
      ? plan.reason
      : needsLogin && !settings.aud
        ? "Krynodes runs without Cloudflare Access here, so a login cannot be reused. Choose Everyone."
        : read
          ? addressProblem(label ?? suggested, chosenPort)
          : null;

  const submit = () => {
    if (!plan?.ok || !settings) return;
    operate.mutate(
      {
        kind: "expose",
        reach: [target.nodeId, ...(plan.releaser ? [plan.releaser] : [])],
        build: () =>
          exposeSteps({
            target: target.nodeId,
            targetKey: target.sealKey ?? "",
            project: target.project,
            service: chosen,
            port: Number(chosenPort),
            hostname,
            mode,
            path,
            zone,
            aud: settings.aud ?? "",
            releaser: plan.releaser,
          }),
      },
      {
        onSuccess: () => {
          toast.success(`Opening ${hostname}.`);
          onClose();
        },
      },
    );
  };

  return (
    <DialogContent className={SHEET}>
      <DialogHeader>
        <DialogTitle>
          Web address · {target.project} on {target.nodeName}
        </DialogTitle>
        <DialogDescription>
          Krynodes makes an HTTPS address through a Cloudflare Tunnel. No port
          opens on the server.
        </DialogDescription>
      </DialogHeader>
      {blocked === "token" ? (
        <NoToken />
      ) : !read ? (
        <Reading server={target.nodeName} failure={failure} retry={retry} />
      ) : (
        <div className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="address-service">Service</Label>
              <Select
                value={chosen}
                onValueChange={(value) => {
                  setService(value);
                  setPort(null);
                }}
              >
                <SelectTrigger id="address-service" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {names.map((name) => (
                    <SelectItem key={name} value={name}>
                      {name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="address-port">Port inside the container</Label>
              <Input
                id="address-port"
                inputMode="numeric"
                value={chosenPort}
                onChange={(event) =>
                  setPort(event.target.value.replace(/\D/gu, ""))
                }
              />
            </div>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="address-name">Address</Label>
            <div className="flex items-center gap-2">
              <Input
                id="address-name"
                value={label ?? suggested}
                autoComplete="off"
                onChange={(event) =>
                  setLabel(
                    event.target.value
                      .toLowerCase()
                      .replace(/[^a-z0-9-]/gu, ""),
                  )
                }
              />
              <span className="shrink-0 font-mono text-xs text-muted-foreground">
                .{zone}
              </span>
            </div>
          </div>
          <div
            role="radiogroup"
            aria-label="Who can open it"
            className="space-y-2"
          >
            {MODES.map((option) => (
              <label
                key={option.value}
                className="flex cursor-pointer gap-2 rounded-md border px-3 py-2"
              >
                <input
                  type="radio"
                  name="address-mode"
                  checked={mode === option.value}
                  onChange={() => setMode(option.value)}
                />
                <span>
                  <span className="block text-sm font-medium">
                    {option.label}
                  </span>
                  <span className="block text-xs text-muted-foreground">
                    {option.detail}
                  </span>
                </span>
              </label>
            ))}
          </div>
          {mode === "path" && (
            <div className="space-y-1.5">
              <Label htmlFor="address-path">Path that needs the login</Label>
              <Input
                id="address-path"
                value={path}
                onChange={(event) => setPath(event.target.value)}
              />
            </div>
          )}
          {blocked && <p className="text-sm text-destructive">{blocked}</p>}
        </div>
      )}
      {operate.error && (
        <p role="alert" className="text-sm text-destructive">
          {errorMessage(operate.error)}
        </p>
      )}
      <DialogFooter>
        <Button variant="outline" onClick={onClose}>
          Cancel
        </Button>
        <Button
          disabled={
            !read ||
            blocked !== null ||
            !chosen ||
            !chosenPort ||
            operate.isPending
          }
          onClick={submit}
        >
          {!operate.isPending && <Fingerprint aria-hidden="true" />}
          {operate.isPending ? "Waiting for the fingerprint…" : "Open"}
        </Button>
      </DialogFooter>
    </DialogContent>
  );
}

export function CloseAddressDialog({
  target,
  addresses,
  disposal,
  open,
  onOpenChange,
}: {
  target: StackTarget;
  addresses: WebAddress[];
  disposal?: "remove" | "purge";
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      {open && (
        <CloseForm
          target={target}
          addresses={addresses}
          disposal={disposal}
          onClose={() => onOpenChange(false)}
        />
      )}
    </Dialog>
  );
}

function CloseForm({
  target,
  addresses,
  disposal,
  onClose,
}: {
  target: StackTarget;
  addresses: WebAddress[];
  disposal?: "remove" | "purge";
  onClose: () => void;
}) {
  const { settings, plan } = usePlan(target.nodeId);
  const operate = useSignedOperation(false);
  const [hostname, setHostname] = useState(addresses[0]?.hostname ?? "");
  const blocked = !settings?.setId
    ? "token"
    : plan && !plan.ok
      ? plan.reason
      : null;

  const close = async () => {
    if (!plan?.ok || !settings) return;
    const chosen = disposal
      ? addresses.map((address) => address.hostname)
      : [hostname];
    try {
      for (const [index, name] of chosen.entries()) {
        await operate.mutateAsync({
          kind: "unexpose",
          reach: [target.nodeId, ...(plan.releaser ? [plan.releaser] : [])],
          build: () =>
            unexposeSteps({
              target: target.nodeId,
              targetKey: target.sealKey ?? "",
              project: target.project,
              hostname: name,
              zone: settings.zone,
              releaser: plan.releaser,
              ...(disposal && index === chosen.length - 1 ? { disposal } : {}),
            }),
        });
      }
    } catch {
      return;
    }
    toast.success(
      disposal
        ? `Closing the addresses of ${target.project}.`
        : `Closing ${hostname}.`,
    );
    onClose();
  };

  return (
    <DialogContent className={SHEET}>
      <DialogHeader>
        <DialogTitle>
          {disposal
            ? `${disposal === "purge" ? "Delete" : "Remove"} ${target.project} and close its web addresses`
            : `Close a web address of ${target.project}`}
        </DialogTitle>
        <DialogDescription>
          {disposal
            ? "The stack has web addresses. Krynodes closes them in Cloudflare first, then goes on."
            : "The address, its login and its tunnel route are removed from Cloudflare."}
        </DialogDescription>
      </DialogHeader>
      {blocked === "token" ? (
        <NoToken />
      ) : (
        <div className="space-y-2">
          {disposal ? (
            <ul className="list-disc pl-5 font-mono text-xs">
              {addresses.map((address) => (
                <li key={address.hostname}>{address.hostname}</li>
              ))}
            </ul>
          ) : (
            addresses.map((address) => (
              <label
                key={address.hostname}
                className="flex cursor-pointer items-center gap-2 font-mono text-xs"
              >
                <input
                  type="radio"
                  name="close-address"
                  checked={hostname === address.hostname}
                  onChange={() => setHostname(address.hostname)}
                />
                {address.hostname}
              </label>
            ))
          )}
          {blocked && <p className="text-sm text-destructive">{blocked}</p>}
        </div>
      )}
      {operate.error && (
        <p role="alert" className="text-sm text-destructive">
          {errorMessage(operate.error)}
        </p>
      )}
      <DialogFooter>
        <Button variant="outline" onClick={onClose}>
          Cancel
        </Button>
        <Button
          variant="destructive"
          disabled={blocked !== null || operate.isPending}
          onClick={() => void close()}
        >
          {operate.isPending
            ? "Waiting for the fingerprint…"
            : disposal
              ? disposal === "purge"
                ? "Delete permanently"
                : "Remove"
              : "Close address"}
        </Button>
      </DialogFooter>
    </DialogContent>
  );
}
