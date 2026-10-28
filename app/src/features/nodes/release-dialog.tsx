import { KeyRound } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { Waiting } from "@/components/busy";
import { CopyCommand } from "@/components/copy-command";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { useQuarantine, useServices } from "@/lib/api";
import { errorMessage } from "@/lib/http";
import { releaseCodeProblem, releaseSteps } from "@/lib/quarantine";
import type { NodeRecord } from "@/types";

import { useRelease } from "./use-quarantine";

const STEP =
  "flex size-6 shrink-0 items-center justify-center rounded-full border font-mono text-xs";

export function ReleaseDialog({
  node,
  open,
  onOpenChange,
}: {
  node: NodeRecord;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const [typed, setTyped] = useState("");
  const [problem, setProblem] = useState<string | null>(null);
  const release = useRelease(node);
  const quarantine = useQuarantine(node.id, open);
  const locked =
    useServices().data?.nodes.find((entry) => entry.id === node.id)?.security
      ?.lockdown ?? false;
  const steps = releaseSteps(node.name);
  const close = (next: boolean) => {
    if (!next) {
      setTyped("");
      setProblem(null);
      release.reset();
    }
    onOpenChange(next);
  };
  const error = problem ?? (release.error ? errorMessage(release.error) : null);

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent>
        <form
          className="space-y-4"
          onSubmit={(event) => {
            event.preventDefault();
            void quarantine.refetch().then(async ({ data }) => {
              const view = data ?? quarantine.data;
              const { code, problem: found } = await releaseCodeProblem(
                typed,
                view?.release ?? null,
                node.name,
                Date.now(),
              );
              setProblem(found);
              if (found || !view) return;
              release.mutate(
                { view, code, locked },
                {
                  onSuccess: () => {
                    toast.success(
                      `Releasing ${node.name}. It makes new keys and reports again.`,
                    );
                    close(false);
                  },
                },
              );
            });
          }}
        >
          <DialogHeader>
            <DialogTitle>{steps.title}</DialogTitle>
            <DialogDescription>{steps.intro}</DialogDescription>
          </DialogHeader>
          <ol className="space-y-4 text-sm">
            <li className="flex gap-3">
              <span className={STEP}>1</span>
              <div className="min-w-0 flex-1 space-y-2">
                <p>{steps.run}</p>
                <CopyCommand command={steps.command} />
              </div>
            </li>
            <li className="flex gap-3">
              <span className={STEP}>2</span>
              <div className="min-w-0 flex-1 space-y-2">
                <label htmlFor="release-code" className="block">
                  {steps.type}
                  <span className="text-muted-foreground">
                    {" "}
                    · {steps.lasts}
                  </span>
                </label>
                <Input
                  id="release-code"
                  value={typed}
                  onChange={(event) => {
                    setTyped(event.target.value.toUpperCase());
                    setProblem(null);
                  }}
                  maxLength={11}
                  autoComplete="off"
                  spellCheck={false}
                  placeholder="7K43Q-MZ2PA"
                  className="font-mono tracking-widest uppercase"
                  required
                />
              </div>
            </li>
          </ol>
          <p className="text-sm text-muted-foreground">{steps.keys}</p>
          {error && (
            <p role="alert" className="text-sm text-destructive">
              {error}
            </p>
          )}
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => close(false)}>
              Cancel
            </Button>
            <Button
              type="submit"
              disabled={release.isPending || quarantine.isFetching}
            >
              <KeyRound aria-hidden="true" />
              {release.isPending ? <Waiting /> : "Release"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
