import { useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";

import { Busy } from "@/components/busy";
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
  useEnrollDefaults,
  useEnrollmentStatus,
  useUpdateEnrollment,
  type SetupChoice,
} from "@/lib/api";
import { adminNameProblem } from "@/lib/admin-user";
import { enrollSetup } from "@/lib/enroll";
import { enrollmentStep } from "@/lib/enrollment";
import { errorMessage } from "@/lib/http";
import { queryKeys } from "@/lib/query-client";

import { EnrollmentCommand } from "./enrollment-command";
import { SetupOptions } from "./setup-options";

const FALLBACK: SetupChoice = {
  docker: true,
  hour: 3,
  network: false,
};

export function EnrollDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const client = useQueryClient();
  const create = useCreateEnrollment();
  const update = useUpdateEnrollment();
  const defaults = useEnrollDefaults(open);
  const [chosen, setChosen] = useState<SetupChoice | null>(null);
  const keys = defaults.data?.keys ?? [];
  const setup =
    chosen ?? (defaults.data ? { ...defaults.data, adminName: "" } : FALLBACK);
  const adminName = (setup.adminName ?? "").trim();
  const unnamed =
    keys.length === 0 ||
    adminName === "" ||
    adminNameProblem(adminName) !== null;
  const deviceCount = useDevices().data?.devices.length ?? 0;
  const status = useEnrollmentStatus(open ? create.data?.id : undefined);
  const step = enrollmentStep(Boolean(create.data), status.data);

  const close = (next: boolean) => {
    if (!next) {
      create.reset();
      update.reset();
      setChosen(null);
    }
    onOpenChange(next);
  };

  useEffect(() => {
    if (step !== "connected") return;
    void client.invalidateQueries({ queryKey: queryKeys.overview });
  }, [step, client]);

  const offset = () => new Date().getTimezoneOffset();
  const start = () => create.mutate(enrollSetup(setup, offset()));
  const change = (next: SetupChoice) => {
    setChosen(next);
    if (create.data) {
      update.mutate({ id: create.data.id, setup: enrollSetup(next, offset()) });
    }
  };

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent onInteractOutside={(event) => event.preventDefault()}>
        {step === "start" && (
          <>
            <DialogHeader>
              <DialogTitle>Enroll a Server</DialogTitle>
              <DialogDescription>
                Krynodes makes a one-time install command. The server shows up
                here once it enrolls, named after its hostname and reporting
                every minute.
              </DialogDescription>
              <p className="text-xs text-muted-foreground">
                {deviceCount > 0
                  ? `This server will trust your ${deviceCount} trusted ${deviceCount === 1 ? "passkey" : "passkeys"} from the start, and the passkey you confirm with can reach it right away.`
                  : "No trusted passkey yet. Set one up first (Passkeys in the account menu) so this server trusts it from the start; until then it takes the first passkeys the dashboard sends."}
              </p>
            </DialogHeader>
            <SetupOptions value={setup} onChange={change} keys={keys} />
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
                onClick={start}
                disabled={create.isPending || unnamed}
                autoFocus
              >
                {!create.isPending && <GuardIcon />}
                {create.isPending ? (
                  <Busy>Creating</Busy>
                ) : (
                  "Create Install Command"
                )}
              </Button>
            </DialogFooter>
          </>
        )}

        {step === "waiting" && create.data && (
          <>
            <DialogHeader>
              <DialogTitle>Install the Agent</DialogTitle>
              <DialogDescription>
                Paste this into a terminal on the server. It downloads the
                agent, enrolls the server and starts it. The command works once.
              </DialogDescription>
            </DialogHeader>
            <EnrollmentCommand
              enrollment={create.data}
              setup={setup}
              onSetupChange={change}
              keys={keys}
            />
            {update.error && (
              <p role="alert" className="text-sm text-destructive">
                {errorMessage(update.error)}
              </p>
            )}
            <p
              role="status"
              className="flex items-center gap-2 text-sm text-muted-foreground"
            >
              <StatusDot tone="warn" className="motion-safe:animate-pulse" />
              <Busy>Waiting for the server to enroll</Busy>
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
              <DialogTitle>Server Enrolled</DialogTitle>
              <DialogDescription>
                Setup goes on in the terminal: answer its questions there.
                Closing this does not stop it. The server&apos;s card in Fleet
                shows each step and opens when setup is done.
              </DialogDescription>
            </DialogHeader>
            <DialogFooter>
              <Button onClick={() => close(false)} autoFocus>
                Done
              </Button>
            </DialogFooter>
          </>
        )}

        {step === "expired" && (
          <>
            <DialogHeader>
              <DialogTitle>This Command Expired</DialogTitle>
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
                  start();
                }}
                disabled={create.isPending}
              >
                Create a New Command
              </Button>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
