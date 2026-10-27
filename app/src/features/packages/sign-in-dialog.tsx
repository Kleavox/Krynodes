import { agentHasFeatures } from "@krynodes/protocol/versions";
import { useEffect, useState } from "react";

import { Elapsed } from "@/components/node-status";
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
import { useSignedAction } from "@/features/deploy/use-signed-action";
import { useJoinTailnet, useTailnet } from "@/features/network/use-tailscale";
import { useAction } from "@/lib/api";
import { errorMessage } from "@/lib/http";
import { signedIn, signedInLines, signInRows } from "@/lib/packages";
import { openSealed, sealPair, type SealPair } from "@/lib/seal";
import { isPending } from "@/lib/services";
import { joinedLines } from "@/lib/tailscale";
import type { NodeRecord } from "@/types";

import { Lines, Said, SHEET, SignButton } from "./lines";

function SignIn({
  node,
  again,
  onClose,
}: {
  node: NodeRecord;
  again: boolean;
  onClose: () => void;
}) {
  const [start] = useState(node.tailscale);
  const [pair, setPair] = useState<SealPair | null>(null);
  const [id, setId] = useState<string | null>(null);
  const [link, setLink] = useState<{ url: string; at: number } | null>(null);
  const [unreadable, setUnreadable] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const run = useSignedAction(false);
  const action = useAction(id).data?.action;
  const answer = action?.status === "done" ? action.output : null;
  const already = answer?.includes('"running":true') ?? false;
  const approved = already || (!!start && signedIn(start, node.tailscale));

  useEffect(() => {
    if (!answer || !pair || link || already) return;
    let sealed: string | undefined;
    try {
      sealed = (JSON.parse(answer) as { sealed?: string }).sealed;
    } catch {
      sealed = undefined;
    }
    if (!sealed) return;
    openSealed(pair, sealed).then(
      (text) => {
        const url = (JSON.parse(text) as { url?: unknown }).url;
        if (typeof url === "string" && url.startsWith("https://")) {
          setLink({ url, at: Date.now() });
        } else {
          setUnreadable("The sign-in link that came back is not usable.");
        }
      },
      () => setUnreadable("The sign-in link could not be opened here."),
    );
  }, [answer, pair, link, already]);

  const begin = () => {
    setUnreadable(null);
    sealPair().then(
      (fresh) => {
        setPair(fresh);
        run.mutate(
          {
            action: "signin",
            mode: "parallel",
            targets: [
              {
                nodeId: node.id,
                kind: "host",
                name: "tailscale",
                args: { key: fresh.public },
              },
            ],
          },
          { onSuccess: (sent) => setId(sent.actions[0]!.id) },
        );
      },
      () => setUnreadable("This browser could not make a one-time key."),
    );
  };

  const failed =
    action && !isPending(action) && action.status !== "done"
      ? action.output || "tailscaled gave no sign-in link."
      : null;

  return (
    <>
      <DialogHeader>
        <DialogTitle>Sign in {node.name} to Tailscale</DialogTitle>
        <DialogDescription>
          {approved
            ? "Signed in."
            : `Open the link where you are signed in to Tailscale, and approve ${node.name} there. Only this browser can see the link.`}
        </DialogDescription>
      </DialogHeader>
      {approved && node.tailscale ? (
        <Lines lines={signedInLines(node.tailscale, node.name)} />
      ) : (
        <>
          {link && (
            <div className="space-y-2">
              <p className="rounded-md border bg-background p-3 font-mono text-xs break-all select-all max-sm:hidden">
                {link.url}
              </p>
              <div className="flex flex-wrap gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  className="max-sm:hidden"
                  onClick={() =>
                    navigator.clipboard.writeText(link.url).then(
                      () => setCopied(true),
                      () => setCopied(false),
                    )
                  }
                >
                  {copied ? "Copied" : "Copy"}
                </Button>
                <Button asChild size="sm">
                  <a href={link.url} target="_blank" rel="noreferrer">
                    Open Link
                  </a>
                </Button>
              </div>
            </div>
          )}
          <ul className="space-y-1.5 text-sm text-muted-foreground">
            {signInRows(node.name, again).map((row) => (
              <li key={row}>· {row}</li>
            ))}
            {link && (
              <li>
                … Waiting for you to approve {node.name} ·{" "}
                <Elapsed since={link.at} />
              </li>
            )}
            {id !== null && !link && !failed && !unreadable && (
              <li>… Asking tailscaled on {node.name} for a sign-in link</li>
            )}
          </ul>
        </>
      )}
      <Said text={failed ?? unreadable} />
      <Said text={run.error ? errorMessage(run.error) : null} />
      <DialogFooter>
        {approved ? (
          <Button onClick={onClose}>Close</Button>
        ) : (
          <>
            <DialogClose asChild>
              <Button variant="outline">Cancel</Button>
            </DialogClose>
            {id === null && (
              <SignButton
                label={again ? "Sign In Again" : "Sign In"}
                pending={run.isPending}
                onClick={begin}
              />
            )}
          </>
        )}
      </DialogFooter>
    </>
  );
}

function Keyed({ node, onClose }: { node: NodeRecord; onClose: () => void }) {
  const { data } = useTailnet();
  const join = useJoinTailnet();
  const done = join.data;
  const connected = data?.connected;
  const joined =
    done && connected
      ? joinedLines(done.report, node.name, connected, done.servers)
      : null;

  return (
    <>
      <DialogHeader>
        <DialogTitle>
          {joined?.title ?? `Sign in ${node.name} to Tailscale`}
        </DialogTitle>
        <DialogDescription>
          {joined?.intro ??
            `A server that holds a piece of your Tailscale credential makes a one-time key tagged kry, sealed to ${node.name}. There is nothing to approve in Tailscale.`}
        </DialogDescription>
      </DialogHeader>
      {joined && <Lines lines={joined.lines} />}
      {done && !done.saved.saved && (
        <p className="text-sm text-warning">
          A Krynodes rule was changed in Tailscale's admin console, so your
          rules do not name {node.name} yet. Save them again on Network.
        </p>
      )}
      {join.isPending && (
        <p role="status" className="text-sm text-muted-foreground">
          … Signing in {node.name} and saving your rules
        </p>
      )}
      <Said text={join.error?.message ?? null} />
      <DialogFooter>
        {done ? (
          <Button onClick={onClose}>Close</Button>
        ) : (
          <>
            <DialogClose asChild>
              <Button variant="outline" disabled={join.isPending}>
                Cancel
              </Button>
            </DialogClose>
            <SignButton
              label="Sign In"
              pending={join.isPending}
              onClick={() => join.mutate(node.id)}
            />
          </>
        )}
      </DialogFooter>
    </>
  );
}

export function SignInDialog({
  node,
  again,
  open,
  onOpenChange,
}: {
  node: NodeRecord;
  again: boolean;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const connected = !!useTailnet().data?.connected;
  const keyed = connected && agentHasFeatures(node.agent_version);
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className={SHEET}>
        {open &&
          (keyed ? (
            <Keyed node={node} onClose={() => onOpenChange(false)} />
          ) : (
            <SignIn
              node={node}
              again={again}
              onClose={() => onOpenChange(false)}
            />
          ))}
      </DialogContent>
    </Dialog>
  );
}
