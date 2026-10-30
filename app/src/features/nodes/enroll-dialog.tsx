import { useEffect, useState } from "react";
import { Link } from "react-router";
import { CircleCheck } from "lucide-react";
import { dnsName } from "@krynodes/protocol";
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
  useNetwork,
  useNetworkNext,
  useOverview,
  useUpdateEnrollment,
  type SetupChoice,
} from "@/lib/api";
import { adminNameProblem, loginLine } from "@/lib/admin-user";
import { enrollSetup } from "@/lib/enroll";
import { enrollmentStep } from "@/lib/enrollment";
import { errorMessage } from "@/lib/http";
import { queryKeys } from "@/lib/query-client";

import { CopyCommand } from "@/components/copy-command";

import { EnrollmentCommand } from "./enrollment-command";
import { SetupOptions } from "./setup-options";

const FALLBACK: SetupChoice = {
  recommended: true,
  docker: true,
  hour: 3,
  network: false,
  confine: false,
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
    chosen ??
    (defaults.data
      ? { ...defaults.data, adminUser: keys.length > 0, adminName: "" }
      : FALLBACK);
  const adminName = (setup.adminName ?? "").trim();
  const adding = setup.adminUser === true && keys.length > 0;
  const unnamed =
    adding && (adminName === "" || adminNameProblem(adminName) !== null);
  const deviceCount = useDevices().data?.devices.length ?? 0;
  const status = useEnrollmentStatus(open ? create.data?.id : undefined);
  const step = enrollmentStep(Boolean(create.data), status.data);
  const node = status.data?.status === "used" ? status.data.node : null;
  const network = useNetwork().data;
  const waiting = network?.waiting.find((entry) => entry.nodeId === node?.id);
  const next = useNetworkNext(waiting ? [waiting.nodeId] : []);
  const gets = next.data?.addresses[0]?.address ?? null;
  const overview = useOverview();
  const login = adding
    ? loginLine(
        adminName,
        overview.data?.nodes
          .find((entry) => entry.id === node?.id)
          ?.addresses?.find(
            (address) => address.family === 4 && !address.router,
          )?.address ?? null,
      )
    : null;

  useEffect(() => {
    if (step === "connected") {
      void client.invalidateQueries({ queryKey: queryKeys.overview });
    }
  }, [step, client]);

  const close = (next: boolean) => {
    if (!next) {
      create.reset();
      update.reset();
      setChosen(null);
    }
    onOpenChange(next);
  };
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
      <DialogContent>
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
              <CircleCheck aria-hidden="true" className="size-8 text-success" />
              <DialogTitle>
                {node ? `${node.name} is connected` : "Server Connected"}
              </DialogTitle>
              <DialogDescription role="status">
                It reports every minute. Rename it from its Actions menu. The
                install command no longer works.
              </DialogDescription>
            </DialogHeader>
            {setup.network && node && network?.network && (
              <div className="flex flex-wrap items-center gap-3 rounded-lg border px-3.5 py-2.5 text-sm">
                <span className="min-w-0 flex-1">
                  <span className="font-medium">Private Network</span>{" "}
                  <span className="font-mono text-xs text-muted-foreground">
                    {waiting ? (
                      `Ready · gets ${gets ?? "--"} · ${dnsName(node.name)}.kry`
                    ) : (
                      <Busy>Getting ready</Busy>
                    )}
                  </span>
                </span>
                {waiting && (
                  <Button asChild size="sm" className="h-9 md:h-8">
                    <Link
                      to={`/network?join=${encodeURIComponent(node.id)}`}
                      onClick={() => close(false)}
                    >
                      Join
                    </Link>
                  </Button>
                )}
              </div>
            )}
            {adding && node && (
              <div className="space-y-2 rounded-lg border px-3.5 py-3 text-sm">
                <p className="font-medium">Log In as {adminName} Now</p>
                <p className="text-xs text-muted-foreground">
                  Root can no longer log in over SSH. Check this works before
                  you close the root session.
                </p>
                {login ? (
                  <CopyCommand command={login} />
                ) : (
                  <p className="font-mono text-xs text-muted-foreground">--</p>
                )}
              </div>
            )}
            <DialogFooter>
              <Button variant="ghost" onClick={() => close(false)}>
                Done
              </Button>
              {node && (
                <Button asChild>
                  <Link to={`/nodes/${node.id}`} onClick={() => close(false)}>
                    Open Server
                  </Link>
                </Button>
              )}
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
