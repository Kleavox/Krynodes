import { agentHasFeatures } from "@krynodes/protocol/versions";
import { KeyRound } from "lucide-react";
import { useState } from "react";

import { Waiting } from "@/components/busy";
import { CopyCommand } from "@/components/copy-command";
import {
  AlertDialog,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useSignedAction } from "@/features/deploy/use-signed-action";
import {
  adminArgs,
  adminBlocker,
  adminCommand,
  adminNameProblem,
  keyText,
  type EnrollAdmin,
} from "@/lib/admin-user";
import { agentState } from "@/lib/agent";
import {
  useEnrollDefaults,
  useOverview,
  useRequestAgentUpdate,
} from "@/lib/api";
import { errorMessage } from "@/lib/http";
import type { NodeRecord } from "@/types";

const SHEET =
  "max-sm:top-auto max-sm:bottom-0 max-sm:translate-y-0 max-sm:rounded-b-none";

export function AdminUserForm({
  admin,
  name,
  onName,
  blocker,
  pending,
  error,
  onGet,
  onCancel,
  onUpdate,
}: {
  admin: EnrollAdmin | null;
  name: string;
  onName: (name: string) => void;
  blocker: string | null;
  pending: boolean;
  error: string | null;
  onGet: () => void;
  onCancel: () => void;
  onUpdate?: () => void;
}) {
  const wrong = name.trim() === "" ? null : adminNameProblem(name.trim());
  return (
    <div className="grid gap-4">
      <div className="grid gap-1.5">
        <label htmlFor="admin-user-name" className="text-sm font-medium">
          Name
        </label>
        <Input
          id="admin-user-name"
          className="font-mono"
          autoComplete="off"
          spellCheck={false}
          value={name}
          aria-invalid={wrong !== null}
          onChange={(event) => onName(event.target.value)}
        />
        {wrong && <p className="text-xs text-destructive">{wrong}</p>}
      </div>
      <div className="grid gap-1.5">
        <span className="text-sm font-medium">SSH Public Keys</span>
        {admin && admin.keys.length > 0 && (
          <ul className="space-y-0.5 font-mono text-xs text-muted-foreground">
            {admin.keys.map((key) => (
              <li key={key.line} className="truncate">
                {keyText(key)}
              </li>
            ))}
          </ul>
        )}
        <span className="text-xs text-muted-foreground">
          From Enroll Defaults.
        </span>
      </div>
      {blocker && (
        <div className="flex flex-wrap items-center gap-2 rounded-md border border-warning/40 bg-warning/10 px-3 py-2 text-sm">
          <span className="min-w-0 flex-1">{blocker}</span>
          {onUpdate && (
            <Button variant="outline" size="sm" onClick={onUpdate}>
              Update Agent
            </Button>
          )}
        </div>
      )}
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
        <Button variant="outline" onClick={onCancel}>
          Cancel
        </Button>
        <Button
          disabled={
            pending || blocker !== null || name.trim() === "" || wrong !== null
          }
          onClick={onGet}
        >
          <KeyRound aria-hidden="true" />
          {pending ? <Waiting /> : "Get Command"}
        </Button>
      </div>
    </div>
  );
}

export function AdminCommandView({
  nodeName,
  name,
}: {
  nodeName: string;
  name: string;
}) {
  return (
    <div className="grid gap-3">
      <CopyCommand command={adminCommand(name)} />
      <p className="text-sm text-muted-foreground">
        It shows the keys, asks for {name}&apos;s password on {nodeName}&apos;s
        screen, then turns on SSH Keys Only and No Root Login once key login
        works for {name}.
      </p>
    </div>
  );
}

export function AdminUserDialog({
  node,
  open,
  onOpenChange,
}: {
  node: NodeRecord;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const defaults = useEnrollDefaults(open);
  const admin = defaults.data?.admin ?? null;
  const run = useSignedAction(false);
  const update = useRequestAgentUpdate();
  const release = useOverview().data?.agentRelease.version ?? null;
  const [typed, setTyped] = useState<string | null>(null);
  const [sent, setSent] = useState<string | null>(null);
  const name = typed ?? admin?.name ?? "";
  const blocker = defaults.data
    ? adminBlocker(node, admin)
    : defaults.error
      ? errorMessage(defaults.error)
      : "Loading…";
  const updatable =
    !agentHasFeatures(node.agent_version) &&
    release !== null &&
    ["available", "failed"].includes(agentState(node, release, Date.now()));
  const close = (next: boolean) => {
    if (!next) {
      run.reset();
      setTyped(null);
      setSent(null);
    }
    onOpenChange(next);
  };
  const get = () => {
    if (!admin) return;
    const chosen = name.trim();
    run.mutate(
      {
        action: "admin",
        targets: [
          {
            nodeId: node.id,
            kind: "host",
            name: "server",
            args: adminArgs(chosen, admin.keys),
          },
        ],
      },
      { onSuccess: () => setSent(chosen) },
    );
  };
  return (
    <AlertDialog open={open} onOpenChange={close}>
      <AlertDialogContent className={SHEET}>
        <AlertDialogHeader>
          <AlertDialogTitle>Add Admin User on {node.name}</AlertDialogTitle>
          <AlertDialogDescription>
            {sent
              ? `Run this on ${node.name} as root within 30 minutes.`
              : `A sudo user that logs in with your keys. Its password is typed on ${node.name}'s own screen; Krynodes never sees it.`}
          </AlertDialogDescription>
        </AlertDialogHeader>
        {sent ? (
          <>
            <AdminCommandView nodeName={node.name} name={sent} />
            <div className="flex justify-end">
              <Button variant="outline" onClick={() => close(false)}>
                Close
              </Button>
            </div>
          </>
        ) : (
          <AdminUserForm
            admin={admin}
            name={name}
            onName={setTyped}
            blocker={blocker}
            pending={run.isPending}
            error={run.error ? errorMessage(run.error) : null}
            onGet={get}
            onCancel={() => close(false)}
            onUpdate={
              updatable && !update.isPending
                ? () => update.mutate(node.id)
                : undefined
            }
          />
        )}
      </AlertDialogContent>
    </AlertDialog>
  );
}
