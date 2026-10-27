import { TAILSCALE, type TailnetRule } from "@krynodes/protocol";
import { useState } from "react";

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
import { Said, SHEET, SignButton } from "@/features/packages/lines";
import { clockTime } from "@/lib/format";
import { listOf } from "@/lib/network";
import { losesAccess, proposals } from "@/lib/tailscale";
import { cn } from "@/lib/utils";

import type { Changed } from "./changed-rule-dialog";
import {
  CONSOLE,
  useReadPolicy,
  useSaveRules,
  useTailnet,
  type Started,
} from "./use-tailscale";

const LABEL = "Start With These Rules";
const heading = "text-xs font-medium text-muted-foreground";

export function StartRulesSheet({
  started,
  onChanged,
  onClose,
}: {
  started: Started;
  onChanged: (changed: Changed) => void;
  onClose: () => void;
}) {
  const { data, listeners } = useTailnet();
  const save = useSaveRules();
  const again = useReadPolicy();
  const [current, setCurrent] = useState(started);
  const servers = data?.servers ?? [];
  const rows = proposals(servers, listeners, current.inUse);
  const [ticked, setTicked] = useState(() =>
    rows.filter((row) => row.ticked).map((row) => row.id),
  );
  const toggle = (id: string) =>
    setTicked(
      ticked.includes(id)
        ? ticked.filter((each) => each !== id)
        : [...ticked, id],
    );
  const rules: TailnetRule[] = [
    ...(current.read.open ? [{ from: "devices", to: "rest" } as const] : []),
    ...rows.flatMap((row) =>
      row.rule && ticked.includes(row.id) ? [row.rule] : [],
    ),
  ];
  const untagged = servers
    .filter(
      (server) => server.report && !server.report.tags?.includes(TAILSCALE.tag),
    )
    .map((server) => server.name);
  const busy = save.isPending || again.isPending;

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent className={cn(SHEET, "sm:max-w-[672px]")}>
        <DialogHeader>
          <DialogTitle>{LABEL}</DialogTitle>
          <DialogDescription>
            Read from your policy file at {clockTime(current.read.at)}. Nothing
            changes until you save.
          </DialogDescription>
        </DialogHeader>
        {!current.read.kry && (
          <div className="space-y-2 rounded-md border border-warning/40 p-3 text-sm">
            <p className="font-medium text-warning">
              Your policy file does not let Krynodes use the tag kry yet
            </p>
            <p className="text-xs text-muted-foreground">
              Add "{TAILSCALE.tag}": ["autogroup:admin"], inside "tagOwners",
              then read the file again.
            </p>
            <div className="flex flex-wrap gap-2">
              <Button asChild variant="outline" size="sm">
                <a href={CONSOLE.policy} target="_blank" rel="noreferrer">
                  Open Policy File ↗
                </a>
              </Button>
              <SignButton
                label="Read Again"
                pending={again.isPending}
                disabled={busy}
                onClick={() =>
                  again.mutate(null, { onSuccess: (next) => setCurrent(next) })
                }
              />
            </div>
          </div>
        )}
        {current.read.open && (
          <section className="space-y-2">
            <h3 className={heading}>One rule of yours changes</h3>
            <div className="space-y-1 rounded-md border bg-background p-3 font-mono text-xs">
              <p className="text-destructive">- Everyone → everything</p>
              <p className="text-success">
                + Your devices → everything except your servers
              </p>
            </div>
            <p className="text-xs text-muted-foreground">
              Your laptop, phone and other people's devices keep reaching each
              other, subnet routes and exit nodes as before.
            </p>
          </section>
        )}
        <section className="space-y-2">
          <h3 className={heading}>Who May Reach Your Servers</h3>
          <ul className="divide-y rounded-md border">
            {rows.map((row) => (
              <li key={row.id}>
                <label
                  className={cn(
                    "flex items-center gap-3 px-3 py-2 text-sm",
                    row.locked && "text-muted-foreground",
                  )}
                >
                  {row.locked ? (
                    <span
                      aria-hidden="true"
                      className="w-4 text-center text-destructive"
                    >
                      ✕
                    </span>
                  ) : (
                    <input
                      type="checkbox"
                      className="size-4 shrink-0 accent-primary"
                      checked={ticked.includes(row.id)}
                      disabled={busy}
                      onChange={() => toggle(row.id)}
                    />
                  )}
                  <span className="flex min-w-0 flex-1 flex-col gap-0.5 sm:flex-row sm:items-center sm:gap-3">
                    <span className="min-w-0 break-words sm:flex-1">
                      {row.from} → {row.to}
                    </span>
                    <span className="font-mono text-xs">{row.ports}</span>
                  </span>
                  {row.inUse && (
                    <span className="shrink-0 rounded border px-1.5 py-0.5 text-xs text-muted-foreground">
                      In Use Now
                    </span>
                  )}
                </label>
              </li>
            ))}
          </ul>
          <p className="text-xs text-muted-foreground">
            Ports come from what listens on each server. In Use Now is what your
            servers saw open on Tailscale at {clockTime(current.read.at)}; a job
            that runs at night does not show here.
          </p>
        </section>
        <section className="space-y-1.5">
          <h3 className={heading}>Also</h3>
          {untagged.length > 0 && (
            <p className="text-sm">
              Gives {listOf(untagged)} the tag kry and turns off their key
              expiry. They stop belonging to your user.
            </p>
          )}
          <p className="text-sm">
            Tailscale checks the whole policy file before it is saved.
          </p>
        </section>
        <section className="space-y-1.5">
          <h3 className={heading}>Loses Access</h3>
          <ul className="space-y-1 text-sm">
            {losesAccess(servers, rows, ticked).map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </section>
        <Said text={again.error?.message ?? save.error?.message ?? null} />
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline" disabled={busy}>
              Not Now
            </Button>
          </DialogClose>
          <SignButton
            label="Save Rules"
            pending={save.isPending}
            disabled={busy || !current.read.kry || rules.length === 0}
            onClick={() =>
              save.mutate(
                {
                  rules,
                  expected: current.read.hash,
                  tag: true,
                  label: LABEL,
                },
                {
                  onSuccess: (saved) =>
                    saved.saved
                      ? onClose()
                      : onChanged({
                          wanted: rules,
                          block: saved.block,
                          now: saved.now,
                          tag: true,
                          label: LABEL,
                        }),
                },
              )
            }
          />
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
