import { useState, type FormEvent } from "react";

import { Busy } from "@/components/busy";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { useSignedAction } from "@/features/deploy/use-signed-action";
import { errorMessage } from "@/lib/http";
import { installLines, type InstallPreview, type Match } from "@/lib/packages";
import { cn } from "@/lib/utils";
import type { NodeRecord } from "@/types";

import { Lines, Said, SHEET, SignButton } from "./lines";
import { useQuestion } from "./use-question";

export function InstallDialog({
  node,
  name,
  onClose,
  onStarted,
}: {
  node: NodeRecord;
  name?: string;
  onClose: () => void;
  onStarted: (id: string) => void;
}) {
  const [term, setTerm] = useState(name ?? "");
  const [picked, setPicked] = useState<string | null>(name ?? null);
  const find = useQuestion<{ matches: Match[] }>();
  const preview = useQuestion<InstallPreview>(
    name
      ? {
          nodeId: node.id,
          action: "preview",
          name,
          args: { what: "install" },
        }
      : undefined,
  );
  const run = useSignedAction(false);
  const matches = find.value?.matches ?? [];
  const lines = preview.value ? installLines(preview.value, node.name) : null;

  const search = (event: FormEvent) => {
    event.preventDefault();
    const value = term.trim().toLowerCase();
    if (value.length < 2) return;
    setPicked(null);
    find.ask({
      nodeId: node.id,
      action: "find",
      name: "system",
      args: { term: value },
    });
  };

  const pick = (name: string) => {
    setPicked(name);
    preview.ask({
      nodeId: node.id,
      action: "preview",
      name,
      args: { what: "install" },
    });
  };

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className={SHEET}>
        <DialogHeader>
          <DialogTitle>Install Package · {node.name}</DialogTitle>
          <DialogDescription>
            From the sources {node.name} already has. To get a package from
            somewhere else, add its repository first.
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={search} className="flex gap-2">
          <Input
            type="search"
            value={term}
            onChange={(event) => setTerm(event.target.value)}
            placeholder="Package name"
            aria-label="Package name"
            autoFocus
          />
          <Button
            type="submit"
            variant="outline"
            disabled={term.trim().length < 2 || find.waiting}
          >
            Search
          </Button>
        </form>
        {find.waiting && (
          <p className="text-sm text-muted-foreground">
            <Busy>{`Asking ${node.name}`}</Busy>
          </p>
        )}
        <Said text={find.error} />
        {find.value && matches.length === 0 && (
          <p className="text-sm text-muted-foreground">
            No package by that name in the sources {node.name} has.
          </p>
        )}
        {matches.length > 0 && (
          <ul className="max-h-56 divide-y overflow-y-auto rounded-md border">
            {matches.map((match) => (
              <li key={match.name}>
                <button
                  type="button"
                  aria-pressed={picked === match.name}
                  disabled={match.installed !== null}
                  onClick={() => pick(match.name)}
                  className={cn(
                    "w-full px-3 py-2 text-left text-sm hover:bg-accent disabled:cursor-default disabled:opacity-60 disabled:hover:bg-transparent",
                    picked === match.name && "bg-accent",
                  )}
                >
                  <span className="flex flex-wrap items-center gap-x-2">
                    <span className="font-medium">{match.name}</span>
                    <span className="font-mono text-xs text-muted-foreground">
                      {match.version}
                    </span>
                    {match.installed !== null && (
                      <Badge variant="secondary">Installed</Badge>
                    )}
                    <span className="ml-auto text-xs text-muted-foreground">
                      {match.from ?? "--"}
                    </span>
                  </span>
                  {match.summary && (
                    <span className="block truncate text-xs text-muted-foreground">
                      {match.summary}
                    </span>
                  )}
                </button>
              </li>
            ))}
          </ul>
        )}
        {picked && (
          <div className="space-y-2">
            <h3 className="text-xs font-medium text-muted-foreground">
              What Happens
            </h3>
            {preview.waiting ? (
              <p className="text-sm text-muted-foreground">
                <Busy>{`Trying ${picked} on ${node.name} without installing anything`}</Busy>
              </p>
            ) : (
              <>
                <Said text={preview.error} />
                {lines && <Lines lines={lines} />}
              </>
            )}
          </div>
        )}
        <Said text={run.error ? errorMessage(run.error) : null} />
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline">Cancel</Button>
          </DialogClose>
          <SignButton
            label="Install"
            pending={run.isPending}
            disabled={
              !picked ||
              preview.waiting ||
              !preview.value ||
              preview.value.refused !== null
            }
            onClick={() =>
              run.mutate(
                {
                  action: "install",
                  mode: "parallel",
                  targets: [{ nodeId: node.id, kind: "apt", name: picked! }],
                },
                { onSuccess: (sent) => onStarted(sent.actions[0]!.id) },
              )
            }
          />
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
