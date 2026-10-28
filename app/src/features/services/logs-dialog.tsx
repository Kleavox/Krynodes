import { useEffect, useRef, useState } from "react";

import { Busy } from "@/components/busy";
import { StatusDot } from "@/components/status";
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { useSignedAction } from "@/features/deploy/use-signed-action";
import { useAction } from "@/lib/api";
import { clockTime } from "@/lib/format";
import { errorMessage } from "@/lib/http";
import { displayName } from "@/lib/services";
import type { ActionKind } from "@/types";

export interface LogsTarget {
  nodeId: string;
  nodeName: string;
  kind: Exclude<ActionKind, "trust" | "host">;
  name: string;
}

export function LogsDialog({
  target,
  open,
  onOpenChange,
}: {
  target: LogsTarget;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      {open && <LogsView target={target} />}
    </AlertDialog>
  );
}

export function useLogsRead(target: LogsTarget) {
  const run = useSignedAction(false);
  const [id, setId] = useState<string | null>(null);
  const action = useAction(id).data?.action;
  const started = useRef(false);
  const fetchLogs = () => {
    setId(null);
    run.mutate(
      {
        action: "logs",
        targets: [
          { nodeId: target.nodeId, kind: target.kind, name: target.name },
        ],
      },
      { onSuccess: (batch) => setId(batch.actions[0]?.id ?? null) },
    );
  };
  useEffect(() => {
    if (started.current) return;
    started.current = true;
    fetchLogs();
  });

  const waiting =
    run.isPending ||
    (id !== null &&
      (!action || action.status === "queued" || action.status === "sent"));
  const done = !waiting && action?.status === "done";
  const output = done ? action.output || "No log lines." : null;
  const problem = run.error
    ? errorMessage(run.error)
    : !waiting && !done && action
      ? action.output || "The server did not answer. Try again."
      : null;
  return { waiting, done, output, problem, action, fetchLogs };
}

function LogsView({ target }: { target: LogsTarget }) {
  const { waiting, done, output, problem, action, fetchLogs } =
    useLogsRead(target);
  const block = useRef<HTMLPreElement>(null);
  const [copied, setCopied] = useState<"Copied" | "Copy Failed" | null>(null);
  useEffect(() => {
    if (output && block.current) {
      block.current.scrollTop = block.current.scrollHeight;
    }
  }, [output]);

  const copy = () => {
    if (!output) return;
    const show = (label: "Copied" | "Copy Failed") => {
      setCopied(label);
      setTimeout(() => setCopied(null), 2_000);
    };
    navigator.clipboard.writeText(output).then(
      () => show("Copied"),
      () => show("Copy Failed"),
    );
  };
  const name = displayName(target.kind, target.name);

  return (
    <AlertDialogContent className="max-sm:top-auto max-sm:bottom-0 max-sm:translate-y-0 max-sm:rounded-b-none sm:max-w-3xl">
      <AlertDialogHeader>
        <AlertDialogTitle>
          Logs · {name} on {target.nodeName}
        </AlertDialogTitle>
        <AlertDialogDescription asChild>
          <p className="flex items-center gap-2 font-mono text-xs">
            {waiting ? (
              <>
                <StatusDot tone="warn" pulse />
                <Busy>{`Fetching the last 300 lines from ${target.nodeName}`}</Busy>
              </>
            ) : done && action?.finishedAt ? (
              `Last 300 Lines · Fetched ${clockTime(action.finishedAt)}`
            ) : null}
          </p>
        </AlertDialogDescription>
      </AlertDialogHeader>
      {problem && (
        <p role="alert" className="text-sm text-destructive">
          {problem}
        </p>
      )}
      {output && (
        <pre
          ref={block}
          tabIndex={0}
          aria-label={`Last log lines of ${name}`}
          className="max-h-[60dvh] min-w-0 overflow-auto rounded-md border bg-muted/40 p-3 font-mono text-[11px] leading-relaxed whitespace-pre-wrap [overflow-wrap:anywhere] motion-safe:animate-in motion-safe:fade-in-0"
        >
          {output}
        </pre>
      )}
      <AlertDialogFooter>
        <AlertDialogCancel>Close</AlertDialogCancel>
        {output && (
          <Button variant="outline" onClick={copy}>
            {copied ?? "Copy"}
          </Button>
        )}
        <Button disabled={waiting} onClick={fetchLogs}>
          Load Again
        </Button>
      </AlertDialogFooter>
    </AlertDialogContent>
  );
}
