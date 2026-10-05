import { useState } from "react";
import { toast } from "sonner";

import { ConfirmDialog } from "@/components/confirm-dialog";
import { RowMenu } from "@/components/row-menu";
import { useDeleteCheck, useUpdateCheck } from "@/lib/api";
import { errorMessage } from "@/lib/http";
import type { CheckRecord, NodeRecord } from "@/types";

import { AutoRestartDialog } from "./auto-restart-dialog";
import { CheckDialog } from "./check-dialog";
import { StatusPageDialog } from "./status-page-dialog";

type Open = "edit" | "status" | "remove" | "auto" | null;

export function CheckMenu({
  check,
  nodes,
  restart,
}: {
  check: CheckRecord;
  nodes: NodeRecord[];
  restart?: () => void;
}) {
  const [open, setOpen] = useState<Open>(null);
  const update = useUpdateCheck();
  const remove = useDeleteCheck();
  const paused = !check.enabled;

  const togglePause = () =>
    update.mutate(
      { id: check.id, enabled: paused },
      {
        onSuccess: () =>
          toast.success(
            paused
              ? `${check.name} runs again from its next report.`
              : `${check.name} is paused. Any open incident is closed.`,
          ),
        onError: (error) => toast.error(errorMessage(error)),
      },
    );

  return (
    <>
      <RowMenu
        label={`${check.name} actions`}
        items={[
          { label: "Edit", onSelect: () => setOpen("edit") },
          { label: paused ? "Resume" : "Pause", onSelect: togglePause },
          ...(restart ? [{ label: "Restart service", onSelect: restart }] : []),
          ...(check.kind === "SERVICE"
            ? [
                {
                  label: "Restart automatically",
                  onSelect: () => setOpen("auto"),
                },
              ]
            : []),
          { label: "Status page", onSelect: () => setOpen("status") },
          {
            label: "Remove",
            destructive: true,
            onSelect: () => setOpen("remove"),
          },
        ]}
      />
      <CheckDialog
        open={open === "edit"}
        onOpenChange={(next) => setOpen(next ? "edit" : null)}
        check={check}
        nodes={nodes}
      />
      <AutoRestartDialog
        check={check}
        node={nodes.find((node) => node.id === check.node_id)}
        open={open === "auto"}
        onOpenChange={(next) => setOpen(next ? "auto" : null)}
      />
      <StatusPageDialog
        check={check}
        open={open === "status"}
        onOpenChange={(next) => setOpen(next ? "status" : null)}
      />
      <ConfirmDialog
        open={open === "remove"}
        onOpenChange={(next) => setOpen(next ? "remove" : null)}
        title={`Remove ${check.name}?`}
        description="Its results and incidents are deleted with it. To stop it for a while instead, pause it."
        confirmLabel="Remove check"
        guarded
        mutation={remove}
        variables={check.id}
      />
    </>
  );
}
