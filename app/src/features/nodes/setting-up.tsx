import { Ellipsis } from "lucide-react";
import { useState } from "react";

import { StatusChip } from "@/components/status";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Skeleton } from "@/components/ui/skeleton";
import type { SetupView } from "@/lib/setup";
import { cn } from "@/lib/utils";
import type { NodeRecord } from "@/types";

import { DeleteNodeDialog } from "./delete-node-dialog";

export function SetupProgress() {
  return (
    <div
      role="status"
      aria-label="Setting Up"
      className="h-1.5 overflow-hidden rounded-full bg-muted"
    >
      <div className="h-full w-1/3 rounded-full bg-primary motion-safe:animate-loading" />
    </div>
  );
}

export function failedLine(step: string | null) {
  if (step === null) return "Never connected";
  if (step === "Restarting") return "Did not come back after its restart";
  return `Went silent at ${step}`;
}

export function SetupActions({ node }: { node: NodeRecord }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <DropdownMenu modal={false}>
        <DropdownMenuTrigger asChild>
          <Button
            variant="ghost"
            size="icon"
            className="size-9 shrink-0 text-muted-foreground md:size-8"
            aria-label={`Actions for ${node.name}`}
          >
            <Ellipsis aria-hidden="true" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuItem
            variant="destructive"
            onSelect={() => setOpen(true)}
          >
            Delete Node
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
      <DeleteNodeDialog node={node} open={open} onOpenChange={setOpen} />
    </>
  );
}

export function SettingUpCard({
  node,
  view,
}: {
  node: NodeRecord;
  view: SetupView;
}) {
  const still = view.failed && "animate-none";
  return (
    <article
      aria-busy={view.failed ? undefined : true}
      className="flex flex-col gap-3 rounded-lg border bg-card p-3.5"
    >
      <div>
        <div className="flex items-center justify-between gap-2">
          <h2 className="min-w-0 truncate font-medium" title={node.name}>
            {node.name}
          </h2>
          <div className="flex shrink-0 items-center gap-1">
            {view.failed ? (
              <StatusChip tone="bad" label="Setup Failed" />
            ) : (
              <StatusChip tone="work" label="Setting Up" pulse />
            )}
            <SetupActions node={node} />
          </div>
        </div>
        {view.failed || view.step ? (
          <p
            className={cn(
              "mt-1 truncate font-mono text-[11px]",
              view.failed ? "text-destructive" : "text-muted-foreground",
            )}
          >
            {view.failed ? failedLine(view.step) : view.step}
          </p>
        ) : (
          <Skeleton className="mt-1.5 h-3 w-2/5" />
        )}
      </div>
      <div>
        <Skeleton className={cn("h-2.5 w-24", still)} />
        <Skeleton className={cn("mt-1.5 h-8", still)} />
      </div>
      <div className="grid grid-cols-3 gap-3">
        {["cpu", "memory", "disk"].map((key) => (
          <div key={key}>
            <Skeleton className={cn("h-3 w-3/4", still)} />
            <Skeleton className={cn("mt-1 h-1.5", still)} />
          </div>
        ))}
      </div>
      {!view.failed && <SetupProgress />}
      <p className="mt-auto border-t pt-2.5 font-mono text-[11px] text-muted-foreground">
        {view.failed
          ? "Delete it and enroll the server again"
          : "Opens when setup is done"}
      </p>
    </article>
  );
}
