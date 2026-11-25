import { useQuery } from "@tanstack/react-query";
import { useState, type ReactNode } from "react";

import { Busy, Waiting } from "@/components/busy";
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
  approve,
  fingerprintOf,
  type ApproveDeps,
  type ApproveStep,
} from "@/lib/approve";
import { networkFailure } from "@/lib/network";
import type { JoinRequest } from "@/types";

import { useOneTimeCheck } from "./one-time-check";
import { useRefreshNetwork } from "./use-network";

export interface ApproveState {
  phase: "confirm" | "running" | "done";
  steps: ApproveStep[];
  error?: string;
}

type Shown = Awaited<ReturnType<typeof fingerprintOf>>;

export async function runApprove(
  request: JoinRequest,
  expected: string,
  deps: Omit<ApproveDeps, "onStep">,
  set: (update: (state: ApproveState) => ApproveState) => void,
) {
  set(() => ({ phase: "running", steps: [] }));
  try {
    await approve(request, expected, {
      ...deps,
      onStep: (step) =>
        set((state) => ({
          ...state,
          steps: [
            ...state.steps.filter(
              (one) => one.kind !== "applied" || step.kind !== "applied",
            ),
            step,
          ],
        })),
    });
    set((state) => ({ ...state, phase: "done" }));
  } catch (error) {
    set((state) => ({ ...state, phase: "done", error: networkFailure(error) }));
  }
}

const stepLines = (step: ApproveStep, name: string): string[] => {
  switch (step.kind) {
    case "session":
      return ["Passkey confirmed."];
    case "inspect":
      return [`Checking ${name}.`];
    case "prepare":
      return [`Preparing ${name}.`];
    case "probe":
      return [`Checking that ${name} can be reached.`];
    case "sign":
      return ["Signing the network document."];
    case "applied":
      return step.members.map((member) => `${member.name}: ${member.state}`);
  }
};

export function ApproveBody({
  request,
  shown,
  error,
  state,
  checking,
  onApprove,
  onClose,
  children,
}: {
  request: JoinRequest;
  shown: Shown | undefined;
  error?: string;
  state: ApproveState;
  checking: boolean;
  onApprove: (expected: string) => void;
  onClose: () => void;
  children?: ReactNode;
}) {
  const lines = state.steps.flatMap((step) => stepLines(step, request.name));
  return (
    <>
      {shown ? (
        <div className="space-y-1">
          <p className="font-mono text-lg tracking-wider">
            {shown.fingerprint}
          </p>
          <p className="text-sm text-muted-foreground">{shown.line}</p>
        </div>
      ) : (
        <p role={error ? "alert" : "status"} className="text-sm">
          {error ?? <Busy>Computing the fingerprint</Busy>}
        </p>
      )}
      {lines.length > 0 && (
        <ol aria-label="Progress" className="space-y-1 font-mono text-xs">
          {lines.map((line, index) => (
            <li key={index}>{line}</li>
          ))}
        </ol>
      )}
      {state.error && (
        <p role="alert" className="text-sm text-destructive">
          {state.error}
        </p>
      )}
      {children}
      <DialogFooter>
        <Button
          variant="ghost"
          disabled={state.phase === "running"}
          onClick={onClose}
        >
          {state.phase === "confirm" ? "Cancel" : "Close"}
        </Button>
        {state.phase !== "done" && (
          <Button
            disabled={!shown || state.phase === "running"}
            onClick={() => shown && onApprove(shown.fingerprint)}
          >
            {state.phase === "running" && !checking ? <Waiting /> : "Approve"}
          </Button>
        )}
      </DialogFooter>
    </>
  );
}

export function ApproveDialog({
  request,
  onClose,
}: {
  request: JoinRequest;
  onClose: () => void;
}) {
  const refresh = useRefreshNetwork();
  const { check, panel, checking } = useOneTimeCheck();
  const shown = useQuery({
    queryKey: [
      "fingerprint",
      request.node,
      request.key,
      request.signer,
      request.sealKey,
    ],
    queryFn: () => fingerprintOf(request),
    staleTime: Infinity,
    retry: false,
  });
  const [state, setState] = useState<ApproveState>({
    phase: "confirm",
    steps: [],
  });
  const running = state.phase === "running";
  const close = () => {
    if (!running) onClose();
  };
  return (
    <Dialog open onOpenChange={(open) => !open && close()}>
      <DialogContent
        showCloseButton={!running}
        onInteractOutside={(event) => event.preventDefault()}
        onEscapeKeyDown={(event) => running && event.preventDefault()}
      >
        <DialogHeader>
          <DialogTitle>Approve {request.name}</DialogTitle>
          <DialogDescription>
            {request.name} joins the private network. Your passkey signs the new
            network document.
          </DialogDescription>
        </DialogHeader>
        <ApproveBody
          request={request}
          shown={shown.data}
          error={shown.error ? networkFailure(shown.error) : undefined}
          state={state}
          checking={checking}
          onApprove={(expected) =>
            void runApprove(request, expected, { check }, setState).finally(
              refresh,
            )
          }
          onClose={close}
        >
          {panel}
        </ApproveBody>
      </DialogContent>
    </Dialog>
  );
}
