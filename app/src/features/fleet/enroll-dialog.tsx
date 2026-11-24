import { useState } from "react";
import { Link } from "react-router";

import { Busy } from "@/components/busy";
import { CopyCommand } from "@/components/copy-command";
import { EmptyState } from "@/components/empty-state";
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
import { Skeleton } from "@/components/ui/skeleton";
import { ApproveDialog } from "@/features/network/approve-dialog";
import { useNetworkView } from "@/features/network/use-network";
import { useDevices } from "@/lib/api";
import { stampTime } from "@/lib/format";
import { errorMessage } from "@/lib/http";
import type { Device, Enrollment, JoinRequest } from "@/types";

import { useCreateEnrollment, useEnrollment } from "./use-fleet";

export type EnrollStep = "form" | "waiting" | "enrolled";

export function enrollStep(
  enrollment: Enrollment | undefined,
  nodeId: string | null | undefined,
): EnrollStep {
  if (!enrollment) return "form";
  return nodeId ? "enrolled" : "waiting";
}

export function chosenPasskeys(
  devices: Device[],
  unchecked: ReadonlySet<string>,
): string[] {
  return devices
    .filter((device) => !unchecked.has(device.id))
    .map((device) => device.id);
}

export function EnrollDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent onInteractOutside={(event) => event.preventDefault()}>
        <Enroll onClose={() => onOpenChange(false)} />
      </DialogContent>
    </Dialog>
  );
}

function Enroll({ onClose }: { onClose: () => void }) {
  const devices = useDevices();
  const create = useCreateEnrollment();
  const enrollment = useEnrollment(create.data?.id);
  const [name, setName] = useState("");
  const [approving, setApproving] = useState<JoinRequest | null>(null);
  const nodeId = enrollment.data?.nodeId;
  const step = enrollStep(create.data, nodeId);
  const view = useNetworkView();
  const network = view.data?.network;

  return (
    <>
      <DialogHeader>
        {step === "form" && (
          <>
            <DialogTitle>Enroll a Server</DialogTitle>
            <DialogDescription>
              Krynodes makes a one-time install command. The server trusts the
              passkeys you choose from the start.
            </DialogDescription>
          </>
        )}
        {step === "waiting" && create.data && (
          <>
            <DialogTitle>Install the Agent</DialogTitle>
            <DialogDescription>
              Paste this into a terminal on the server. It downloads the agent,
              enrolls the server and starts it. The command works once and
              expires at {stampTime(create.data.expiresAt)}.
            </DialogDescription>
          </>
        )}
        {step === "enrolled" && (
          <>
            <DialogTitle>Server Enrolled</DialogTitle>
            <DialogDescription>
              {name} is enrolled. It shows its state in Fleet as soon as its
              agent reports.
            </DialogDescription>
          </>
        )}
      </DialogHeader>
      {step === "form" && devices.data && (
        <EnrollForm
          devices={devices.data}
          pending={create.isPending}
          error={create.error}
          onCancel={onClose}
          onCreate={(body) => {
            setName(body.name);
            create.mutate(body);
          }}
        />
      )}
      {step === "form" && devices.isPending && <Skeleton className="h-24" />}
      {step === "form" && devices.isError && (
        <p role="alert" className="text-sm text-destructive">
          {errorMessage(devices.error)}
        </p>
      )}
      {step === "waiting" && create.data && (
        <Install enrollment={create.data} onClose={onClose} />
      )}
      {step === "enrolled" && nodeId && (
        <Arrived
          name={name}
          nodeId={nodeId}
          network={
            view.data === undefined
              ? undefined
              : Boolean(network && !network.deleted)
          }
          request={view.data?.requests.find(
            (request) => request.node === nodeId,
          )}
          onApprove={setApproving}
          onClose={onClose}
        />
      )}
      {approving && (
        <ApproveDialog
          request={approving}
          onClose={() => {
            setApproving(null);
            onClose();
          }}
        />
      )}
    </>
  );
}

export function EnrollForm({
  devices,
  pending,
  error,
  onCancel,
  onCreate,
  label = "Server Name",
}: {
  label?: string;
  devices: Device[];
  pending: boolean;
  error: Error | null;
  onCancel: () => void;
  onCreate: (body: { name: string; trust: string[] }) => void;
}) {
  const [name, setName] = useState("");
  const [unchecked, setUnchecked] = useState<ReadonlySet<string>>(new Set());
  const trust = chosenPasskeys(devices, unchecked);

  if (devices.length === 0) {
    return (
      <EmptyState
        title="Register a passkey first."
        body="A server or laptop needs at least one passkey to trust before it can enroll."
        action={
          <Button asChild variant="outline">
            <Link to="/passkeys">Go to Passkeys</Link>
          </Button>
        }
      />
    );
  }
  return (
    <form
      className="space-y-4"
      onSubmit={(event) => {
        event.preventDefault();
        onCreate({ name: name.trim(), trust });
      }}
    >
      <div className="space-y-2">
        <Label htmlFor="machine-name">{label}</Label>
        <Input
          id="machine-name"
          value={name}
          maxLength={64}
          autoComplete="off"
          onChange={(event) => setName(event.target.value)}
        />
      </div>
      <fieldset className="space-y-2">
        <legend className="text-sm font-medium">Passkeys to Trust</legend>
        {devices.map((device) => (
          <label key={device.id} className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              className="size-4 accent-primary"
              checked={!unchecked.has(device.id)}
              onChange={(event) =>
                setUnchecked((current) => {
                  const next = new Set(current);
                  if (event.target.checked) next.delete(device.id);
                  else next.add(device.id);
                  return next;
                })
              }
            />
            {device.name}
          </label>
        ))}
      </fieldset>
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {errorMessage(error)}
        </p>
      )}
      <DialogFooter>
        <Button type="button" variant="ghost" onClick={onCancel}>
          Cancel
        </Button>
        <Button
          type="submit"
          disabled={pending || name.trim() === "" || trust.length === 0}
        >
          {pending ? <Busy>Creating</Busy> : "Create Install Command"}
        </Button>
      </DialogFooter>
    </form>
  );
}

export function Install({
  enrollment,
  onClose,
}: {
  enrollment: Enrollment;
  onClose: () => void;
}) {
  return (
    <>
      <CopyCommand command={enrollment.command} />
      <p role="status" className="text-sm text-muted-foreground">
        <Busy>Waiting for the server to enroll</Busy>
      </p>
      <DialogFooter>
        <Button variant="ghost" onClick={onClose}>
          Close
        </Button>
      </DialogFooter>
    </>
  );
}

export function Arrived({
  name,
  nodeId,
  network,
  request,
  onApprove,
  onClose,
}: {
  name: string;
  nodeId: string;
  network: boolean | undefined;
  request: JoinRequest | undefined;
  onApprove: (request: JoinRequest) => void;
  onClose: () => void;
}) {
  if (network) {
    const waiting = !request
      ? `Waiting for ${name} to ask to join.`
      : request.ready
        ? null
        : request.reason
          ? `${name} cannot join yet: ${request.reason}`
          : `${name} is not ready to join yet.`;
    return (
      <>
        {request && (
          <p className="text-sm">{name} asked to join the private network.</p>
        )}
        {waiting && (
          <p role="status" className="text-sm text-muted-foreground">
            {waiting}
          </p>
        )}
        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>
            Not Now
          </Button>
          <Button
            disabled={!request?.ready}
            onClick={() => request && onApprove(request)}
          >
            Approve
          </Button>
        </DialogFooter>
      </>
    );
  }
  return (
    <>
      {network === false && (
        <p className="text-sm">
          Create a private network on the{" "}
          <Link to="/network" className="underline underline-offset-4">
            Network page
          </Link>{" "}
          to connect your servers.
        </p>
      )}
      <DialogFooter>
        <Button asChild>
          <a href={`#server-${nodeId}`} onClick={onClose}>
            Show {name}
          </a>
        </Button>
      </DialogFooter>
    </>
  );
}
