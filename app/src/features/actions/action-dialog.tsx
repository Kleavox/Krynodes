import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState, type ReactNode } from "react";

import { Busy } from "@/components/busy";
import {
  AlertDialog,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useDeleteNode } from "@/features/fleet/use-fleet";
import { errorMessage } from "@/lib/http";
import { failure } from "@/lib/passkeys";
import { cn } from "@/lib/utils";
import type { ActionRow, FleetNode } from "@/types";

import { runAction, type ActionRequest } from "./run-action";

export interface Ask extends ActionRequest {
  heading: string;
  body: string;
  confirm: string;
  destructive?: boolean;
}

export interface RunState {
  phase: "confirm" | "sending" | "result";
  lines: string[];
  row?: ActionRow;
  error?: string;
}

export function ActionBody({ state, name }: { state: RunState; name: string }) {
  const { row } = state;
  return (
    <>
      {state.lines.length > 0 && (
        <ol aria-label="Progress" className="space-y-1 font-mono text-xs">
          {state.lines.map((line, index) => (
            <li key={index}>{line}</li>
          ))}
        </ol>
      )}
      {state.phase === "sending" && (
        <p role="status" className="text-sm text-muted-foreground">
          <Busy>{`Waiting for ${name}`}</Busy>
        </p>
      )}
      {state.error && (
        <p role="alert" className="text-sm text-destructive">
          {state.error}
        </p>
      )}
      {row && (
        <p
          role={row.status === "failed" ? "alert" : "status"}
          className={cn(
            "text-sm",
            row.status === "failed" && "text-destructive",
          )}
        >
          {row.message ?? (row.status === "done" ? "Done." : "--")}
        </p>
      )}
      {row?.output && (
        <pre className="max-h-48 overflow-auto rounded-md border bg-muted p-2 font-mono text-xs whitespace-pre-wrap">
          {row.output}
        </pre>
      )}
    </>
  );
}

const PLAIN = {
  Root: Dialog,
  Content: DialogContent,
  Header: DialogHeader,
  Title: DialogTitle,
  Description: DialogDescription,
  Footer: DialogFooter,
};

const ALERT = {
  Root: AlertDialog,
  Content: AlertDialogContent,
  Header: AlertDialogHeader,
  Title: AlertDialogTitle,
  Description: AlertDialogDescription,
  Footer: AlertDialogFooter,
};

export function ActionDialog({
  node,
  ask,
  onClose,
  onDone,
  ready = true,
  children,
}: {
  node: FleetNode;
  ask: Ask;
  onClose: () => void;
  onDone?: (row: ActionRow) => void;
  ready?: boolean;
  children?: ReactNode;
}) {
  const Part = ask.destructive ? ALERT : PLAIN;
  const client = useQueryClient();
  const [state, setState] = useState<RunState>({ phase: "confirm", lines: [] });
  const quit = useRef<AbortController | null>(null);
  useEffect(() => () => quit.current?.abort(), []);
  const drop = useDeleteNode(node.id, onClose);
  const start = () => {
    setState({ phase: "sending", lines: [] });
    quit.current = new AbortController();
    void runAction(
      client,
      node,
      ask,
      (line) => setState((now) => ({ ...now, lines: [...now.lines, line] })),
      quit.current.signal,
    ).then(
      (row) => {
        setState((now) => ({ ...now, phase: "result", row }));
        onDone?.(row);
      },
      (error: unknown) =>
        setState((now) => ({ ...now, phase: "result", error: failure(error) })),
    );
  };
  const removed =
    ask.kind === "agent" &&
    ask.action === "remove" &&
    state.row?.status === "done";

  return (
    <Part.Root open onOpenChange={(open) => !open && onClose()}>
      <Part.Content>
        <Part.Header>
          <Part.Title>{ask.heading}</Part.Title>
          <Part.Description>
            {removed
              ? `${node.name} no longer runs Krynodes. Delete it from Fleet.`
              : ask.body}
          </Part.Description>
        </Part.Header>
        {state.phase === "confirm" && children}
        <ActionBody state={state} name={node.name} />
        {drop.error && (
          <p role="alert" className="text-sm text-destructive">
            {errorMessage(drop.error)}
          </p>
        )}
        <Part.Footer>
          <Button variant="ghost" onClick={onClose}>
            {state.phase === "confirm" ? "Cancel" : "Close"}
          </Button>
          {state.phase === "confirm" && (
            <Button
              variant={ask.destructive ? "destructive" : "default"}
              disabled={!ready}
              onClick={start}
            >
              {ask.confirm}
            </Button>
          )}
          {removed && (
            <Button
              variant="destructive"
              disabled={drop.isPending}
              onClick={() => drop.mutate()}
            >
              {drop.isPending ? <Busy>Deleting</Busy> : `Delete ${node.name}`}
            </Button>
          )}
        </Part.Footer>
      </Part.Content>
    </Part.Root>
  );
}
