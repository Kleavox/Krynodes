import { useEffect } from "react";
import { Link } from "react-router";
import { CircleCheck } from "lucide-react";
import { useQueryClient } from "@tanstack/react-query";

import { StatusDot } from "@/components/status";
import { GuardIcon } from "@/components/confirm-dialog";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  useCreateEnrollment,
  useDevices,
  useEnrollmentStatus,
} from "@/lib/api";
import { enrollmentStep } from "@/lib/enrollment";
import { errorMessage } from "@/lib/http";
import { queryKeys } from "@/lib/query-client";

import { EnrollmentCommand } from "./enrollment-command";

export function EnrollDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const client = useQueryClient();
  const create = useCreateEnrollment();
  const deviceCount = useDevices().data?.devices.length ?? 0;
  const status = useEnrollmentStatus(open ? create.data?.id : undefined);
  const step = enrollmentStep(Boolean(create.data), status.data);
  const node = status.data?.status === "used" ? status.data.node : null;

  useEffect(() => {
    if (step === "connected") {
      void client.invalidateQueries({ queryKey: queryKeys.overview });
    }
  }, [step, client]);

  const close = (next: boolean) => {
    if (!next) create.reset();
    onOpenChange(next);
  };

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent>
        {step === "start" && (
          <>
            <DialogHeader>
              <DialogTitle>Enroll a server</DialogTitle>
              <DialogDescription>
                Krynodes makes a one-time install command. The server shows up
                here once it enrolls, named after its hostname and reporting
                every minute.
              </DialogDescription>
              <p className="text-xs text-muted-foreground">
                {deviceCount > 0
                  ? `This server will trust your ${deviceCount} trusted ${deviceCount === 1 ? "device" : "devices"} from the start.`
                  : "No trusted device yet. Set one up first (Trusted devices in the account menu) so this server trusts it from the start; until then it takes the first devices the dashboard sends."}
              </p>
            </DialogHeader>
            {create.error && (
              <p role="alert" className="text-sm text-destructive">
                {errorMessage(create.error)}
              </p>
            )}
            <DialogFooter>
              <Button variant="ghost" onClick={() => close(false)}>
                Cancel
              </Button>
              <Button
                onClick={() => create.mutate()}
                disabled={create.isPending}
                autoFocus
              >
                {!create.isPending && <GuardIcon />}
                {create.isPending ? "Creating…" : "Create install command"}
              </Button>
            </DialogFooter>
          </>
        )}

        {step === "waiting" && create.data && (
          <>
            <DialogHeader>
              <DialogTitle>Install the agent</DialogTitle>
              <DialogDescription>
                Paste this into a terminal on the server. It downloads the
                agent, enrolls the server and starts it. The command works once.
              </DialogDescription>
            </DialogHeader>
            <EnrollmentCommand enrollment={create.data} />
            <p
              role="status"
              className="flex items-center gap-2 text-sm text-muted-foreground"
            >
              <StatusDot tone="warn" className="motion-safe:animate-pulse" />
              Waiting for the server to enroll…
            </p>
            <DialogFooter>
              <Button variant="ghost" onClick={() => close(false)}>
                Close
              </Button>
            </DialogFooter>
          </>
        )}

        {step === "connected" && (
          <>
            <DialogHeader>
              <CircleCheck aria-hidden="true" className="size-8 text-success" />
              <DialogTitle>
                {node ? `${node.name} is connected` : "Server connected"}
              </DialogTitle>
              <DialogDescription role="status">
                It reports every minute. Rename it from its Actions menu. The
                install command no longer works.
              </DialogDescription>
            </DialogHeader>
            <DialogFooter>
              <Button variant="ghost" onClick={() => close(false)}>
                Done
              </Button>
              {node && (
                <Button asChild>
                  <Link to={`/nodes/${node.id}`} onClick={() => close(false)}>
                    Open node
                  </Link>
                </Button>
              )}
            </DialogFooter>
          </>
        )}

        {step === "expired" && (
          <>
            <DialogHeader>
              <DialogTitle>This command expired</DialogTitle>
              <DialogDescription>
                Nothing enrolled with it, and nothing was added to the fleet.
                Create a new command to try again.
              </DialogDescription>
            </DialogHeader>
            <DialogFooter>
              <Button variant="ghost" onClick={() => close(false)}>
                Cancel
              </Button>
              <Button
                onClick={() => {
                  create.reset();
                  create.mutate();
                }}
                disabled={create.isPending}
              >
                Create a new command
              </Button>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
