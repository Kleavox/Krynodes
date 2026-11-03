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

export function SettingUpCard({ node }: { node: NodeRecord }) {
  return (
    <article
      aria-busy="true"
      className="flex flex-col gap-3 rounded-lg border bg-card p-3.5"
    >
      <div>
        <div className="flex items-center justify-between gap-2">
          <h2 className="min-w-0 truncate font-medium" title={node.name}>
            {node.name}
          </h2>
          <div className="flex shrink-0 items-center gap-1">
            <StatusChip tone="work" label="Setting Up" pulse />
            <SetupActions node={node} />
          </div>
        </div>
        <Skeleton className="mt-1.5 h-3 w-2/5" />
      </div>
      <div>
        <Skeleton className="h-2.5 w-24" />
        <Skeleton className="mt-1.5 h-8" />
      </div>
      <div className="grid grid-cols-3 gap-3">
        {["cpu", "memory", "disk"].map((key) => (
          <div key={key}>
            <Skeleton className="h-3 w-3/4" />
            <Skeleton className="mt-1 h-1.5" />
          </div>
        ))}
      </div>
      <SetupProgress />
      <p className="mt-auto border-t pt-2.5 font-mono text-[11px] text-muted-foreground">
        Opens when setup is done
      </p>
    </article>
  );
}
