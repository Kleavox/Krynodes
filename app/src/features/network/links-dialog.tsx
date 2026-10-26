import { StatusDot } from "@/components/status";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { SHEET } from "@/features/packages/lines";
import {
  peerRows,
  serverRow,
  type PairState,
  type Presence,
} from "@/lib/network";
import { cn } from "@/lib/utils";
import type { NetworkServer, NetworkView } from "@/types";

const DOT: Record<PairState, "ok" | "bad" | "idle"> = {
  up: "ok",
  down: "bad",
  offline: "idle",
  nat: "idle",
  unknown: "idle",
};

export function LinksDialog({
  server,
  view,
  presence,
  now,
  onClose,
  onTest,
  onTestPair,
  onRemove,
}: {
  server: NetworkServer;
  view: NetworkView;
  presence: Presence;
  now: number;
  onClose: () => void;
  onTest: () => void;
  onTestPair: (peer: string) => void;
  onRemove: () => void;
}) {
  const row = serverRow(server, view, presence, now);
  const peers = peerRows(server, view, presence, now);
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className={cn(SHEET, "sm:max-w-[512px]")}>
        <DialogHeader>
          <DialogTitle>{server.name}</DialogTitle>
          <DialogDescription className="font-mono text-xs">
            {row.address} · {row.endpoint}
          </DialogDescription>
        </DialogHeader>
        {row.offline && (
          <p className="text-sm text-muted-foreground">{row.offline}</p>
        )}
        {peers.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            {server.name} is the only server in the network.
          </p>
        ) : (
          <ul className="divide-y rounded-lg border bg-card">
            {peers.map((peer) => (
              <li
                key={peer.nodeId}
                className="flex items-start gap-2.5 px-3.5 py-2.5 text-sm"
              >
                <StatusDot tone={DOT[peer.state]} className="mt-1.5" />
                <span
                  className={cn(
                    "min-w-0 flex-1 break-words",
                    peer.state === "down" && "text-destructive",
                  )}
                >
                  {peer.text}
                </span>
                {peer.test && (
                  <Button
                    variant="outline"
                    size="sm"
                    className="h-9 md:h-7"
                    onClick={() => onTestPair(peer.nodeId)}
                  >
                    Test Link
                  </Button>
                )}
              </li>
            ))}
          </ul>
        )}
        <p className="text-xs text-muted-foreground">
          &quot;--&quot; means not measured, never 0 ms.
        </p>
        <DialogFooter>
          <Button variant="outline" onClick={onRemove}>
            Remove from Network
          </Button>
          <Button disabled={peers.length === 0} onClick={onTest}>
            Test Links
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
