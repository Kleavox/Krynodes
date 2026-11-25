import { useRef, useState, type ReactNode } from "react";

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
import { renewKeys } from "@/lib/approve";
import { networkFailure } from "@/lib/network";

import { useOneTimeCheck } from "./one-time-check";
import { useCurrentDocument, useRefreshNetwork } from "./use-network";

type KeysPhase = "confirm" | "making" | "made" | "signing" | "done";

export interface KeysState {
  phase: KeysPhase;
  shown?: { fingerprint: string; line: string };
  said?: { text: string; failed: boolean };
}

export function KeysBody({
  name,
  loaded,
  state,
  checking,
  onMake,
  onUse,
  onClose,
  children,
}: {
  name: string;
  loaded: boolean;
  state: KeysState;
  checking: boolean;
  onMake: () => void;
  onUse: () => void;
  onClose: () => void;
  children?: ReactNode;
}) {
  const { phase, shown, said } = state;
  return (
    <>
      {!loaded && phase === "confirm" && (
        <p role="status" className="text-sm text-muted-foreground">
          <Busy>Reading the network document</Busy>
        </p>
      )}
      {phase === "making" && !checking && (
        <p role="status" className="text-sm text-muted-foreground">
          <Busy>{`Waiting for ${name}`}</Busy>
        </p>
      )}
      {shown && (
        <div className="space-y-1">
          <p className="font-mono text-lg tracking-wider">
            {shown.fingerprint}
          </p>
          <p className="text-sm text-muted-foreground">{shown.line}</p>
        </div>
      )}
      {said && (
        <p
          role={said.failed ? "alert" : "status"}
          className={said.failed ? "text-sm text-destructive" : "text-sm"}
        >
          {said.text}
        </p>
      )}
      {children}
      <DialogFooter>
        <Button
          variant="ghost"
          disabled={phase === "making" || phase === "signing"}
          onClick={onClose}
        >
          {phase === "confirm" ? "Cancel" : "Close"}
        </Button>
        {(phase === "confirm" || phase === "making") && (
          <Button disabled={!loaded || phase === "making"} onClick={onMake}>
            {phase === "making" && !checking ? <Waiting /> : "Make New Keys"}
          </Button>
        )}
        {(phase === "made" || phase === "signing") && (
          <Button disabled={phase === "signing"} onClick={onUse}>
            {phase === "signing" ? <Busy>Signing</Busy> : "Use New Keys"}
          </Button>
        )}
      </DialogFooter>
    </>
  );
}

export function KeysDialog({
  node,
  name,
  onClose,
}: {
  node: string;
  name: string;
  onClose: () => void;
}) {
  const current = useCurrentDocument();
  const refresh = useRefreshNetwork();
  const { check, panel, checking } = useOneTimeCheck();
  const [state, setState] = useState<KeysState>({ phase: "confirm" });
  const decide = useRef<((use: boolean) => void) | null>(null);
  const busy = state.phase === "making" || state.phase === "signing";
  const close = () => {
    if (busy) return;
    decide.current?.(false);
    onClose();
  };
  const make = () => {
    setState({ phase: "making" });
    void renewKeys(
      node,
      (shown) =>
        new Promise<boolean>((resolve) => {
          decide.current = resolve;
          setState({ phase: "made", shown });
        }),
      { check },
    )
      .then(
        (version) =>
          setState((now) => ({
            ...now,
            phase: "done",
            said:
              version === null
                ? undefined
                : {
                    text: `Signed and sent as version ${version}.`,
                    failed: false,
                  },
          })),
        (error: unknown) =>
          setState((now) => ({
            ...now,
            phase: "done",
            said: { text: networkFailure(error), failed: true },
          })),
      )
      .finally(refresh);
  };
  return (
    <Dialog open onOpenChange={(open) => !open && close()}>
      <DialogContent
        showCloseButton={!busy}
        onInteractOutside={(event) => event.preventDefault()}
      >
        <DialogHeader>
          <DialogTitle>New Keys for {name}</DialogTitle>
          <DialogDescription>
            {name} makes a new network key. You check its fingerprint, then the
            same passkey touch signs a network document with it, and the old key
            stops working.
          </DialogDescription>
        </DialogHeader>
        <KeysBody
          name={name}
          loaded={current.isSuccess && current.data !== null}
          state={
            current.isError && state.phase === "confirm"
              ? {
                  ...state,
                  said: { text: networkFailure(current.error), failed: true },
                }
              : state
          }
          checking={checking}
          onMake={make}
          onUse={() => {
            setState((now) => ({ ...now, phase: "signing" }));
            decide.current?.(true);
          }}
          onClose={close}
        >
          {panel}
        </KeysBody>
      </DialogContent>
    </Dialog>
  );
}
