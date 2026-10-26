import { useState } from "react";
import { Link } from "react-router";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useAction, useServices } from "@/lib/api";
import { canRestartServer } from "@/lib/devices";
import { reachedStacks } from "@/lib/network";
import { jobLines, outcomeOf, packageText, runningJob } from "@/lib/packages";
import { isPending } from "@/lib/services";
import { useNow } from "@/lib/use-now";
import type { ActionRecord, AptReport, NodeRecord } from "@/types";

import { HoldDialog } from "./hold-dialog";
import { InstallDialog } from "./install-dialog";
import { Lines, SHEET, type PackagesDialog } from "./lines";
import { RemoveDialog } from "./remove-dialog";
import { DropRepoDialog, RepoDialog } from "./repo-dialog";
import { SignInDialog } from "./sign-in-dialog";
import { UpgradeDialog } from "./upgrade-dialog";

function JobDialog({
  node,
  id,
  known,
  onClose,
}: {
  node: NodeRecord;
  id: string;
  known: ActionRecord | undefined;
  onClose: () => void;
}) {
  const [signIn, setSignIn] = useState(false);
  const services = useServices();
  const now = useNow(1_000);
  const action = useAction(id).data?.action ?? known;
  const entry = services.data?.nodes.find((item) => item.id === node.id);
  if (signIn) {
    return (
      <SignInDialog node={node} again={false} open onOpenChange={onClose} />
    );
  }
  const running = !action || isPending(action);
  const job = action ? runningJob(action, node.name, now) : null;
  const lines = action
    ? jobLines(action, {
        nodeName: node.name,
        stacks: entry?.stacks ?? [],
        tailscale: node.tailscale,
      })
    : [];
  const old = action ? (outcomeOf(action)?.old ?? []) : [];
  const tailnet =
    !running &&
    action?.action === "install" &&
    action.name === "tailscale" &&
    action.status === "done" &&
    node.tailscale?.state !== "running";
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className={SHEET}>
        <DialogHeader>
          <DialogTitle>
            {running || !action
              ? (job?.title ?? `Starting on ${node.name}`)
              : `${packageText(action, node.name) ?? "Done"} · ${node.name}`}
          </DialogTitle>
          <DialogDescription>
            {running || !action
              ? "Closing this does not stop it. Progress stays on the Packages page."
              : action.status === "done"
                ? "Finished."
                : "It did not finish."}
          </DialogDescription>
        </DialogHeader>
        {running && job?.step && (
          <p className="font-mono text-xs break-words text-muted-foreground">
            {job.step}
          </p>
        )}
        {lines.length > 0 && <Lines lines={lines} />}
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Close
          </Button>
          {tailnet && <Button onClick={() => setSignIn(true)}>Sign In</Button>}
          {old.length > 0 && canRestartServer(node, entry?.trust ?? null) && (
            <Button asChild variant="destructive">
              <Link to={`/nodes/${node.id}?restart=1`}>Restart Server</Link>
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function PackageDialogs({
  dialog,
  onDialog,
  node,
  report,
  actions,
}: {
  dialog: PackagesDialog | null;
  onDialog: (dialog: PackagesDialog | null) => void;
  node: NodeRecord;
  report: AptReport;
  actions: ActionRecord[];
}) {
  const services = useServices();
  const entry = services.data?.nodes.find((item) => item.id === node.id);
  const stacks = (entry?.stacks ?? []).map((stack) => stack.project);
  const reached = reachedStacks(entry && { ...entry, name: node.name });
  const close = () => onDialog(null);
  const started = (id: string) => onDialog({ kind: "job", id });
  switch (dialog?.kind) {
    case "install":
      return (
        <InstallDialog
          node={node}
          name={dialog.name}
          onClose={close}
          onStarted={started}
        />
      );
    case "repo":
      return (
        <RepoDialog
          node={node}
          report={report}
          onClose={close}
          onStarted={started}
        />
      );
    case "upgrade":
      return (
        <UpgradeDialog
          node={node}
          report={report}
          stacks={stacks}
          reached={reached}
          onClose={close}
          onStarted={started}
        />
      );
    case "remove":
      return (
        <RemoveDialog
          node={node}
          report={report}
          name={dialog.name}
          onClose={close}
          onStarted={started}
        />
      );
    case "hold":
      return (
        <HoldDialog
          node={node}
          report={report}
          name={dialog.name}
          held={dialog.held}
          onClose={close}
        />
      );
    case "droprepo":
      return (
        <DropRepoDialog
          node={node}
          name={dialog.name}
          label={dialog.label}
          onClose={close}
        />
      );
    case "job":
      return (
        <JobDialog
          node={node}
          id={dialog.id}
          known={actions.find((action) => action.id === dialog.id)}
          onClose={close}
        />
      );
    default:
      return null;
  }
}
