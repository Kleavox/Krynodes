import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { Busy, Waiting } from "@/components/busy";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { runAction } from "@/features/actions/run-action";
import { networkFailure, testLines, testPeers } from "@/lib/network";
import type { FleetNode, NetworkView } from "@/types";

export function TestDialog({
  node,
  view,
  onClose,
}: {
  node: FleetNode;
  view: NetworkView;
  onClose: () => void;
}) {
  const client = useQueryClient();
  const peers = testPeers(view, node.id);
  const [peer, setPeer] = useState(peers[0]?.node ?? "");
  const [running, setRunning] = useState(false);
  const [lines, setLines] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const chosen = peers.find((member) => member.node === peer);
  const start = () => {
    if (!chosen || !view.network) return;
    setRunning(true);
    setLines([]);
    setError(null);
    void runAction(client, node, {
      kind: "network",
      action: "test",
      title: `Test Link to ${chosen.name}`,
      args: {
        peer: chosen.node,
        address: chosen.address!,
        mtu: String(view.network.mtu),
      },
    })
      .then((row) => {
        if (row.status === "failed") {
          throw new Error(row.message ?? `${node.name} could not finish.`);
        }
        setLines(testLines(row.message, node.name, chosen.name));
      })
      .catch((failed: unknown) => setError(networkFailure(failed)))
      .finally(() => setRunning(false));
  };
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Test Link from {node.name}</DialogTitle>
          <DialogDescription>
            {node.name} checks its tunnel, the firewall, a handshake and the
            round trip to the member you choose.
          </DialogDescription>
        </DialogHeader>
        {peers.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            There is no other member to test a link to.
          </p>
        ) : (
          <div className="space-y-2">
            <Label htmlFor="test-peer">Member</Label>
            <Select value={peer} onValueChange={setPeer}>
              <SelectTrigger id="test-peer" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {peers.map((member) => (
                  <SelectItem key={member.node} value={member.node}>
                    {member.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        )}
        {running && (
          <p role="status" className="text-sm text-muted-foreground">
            <Busy>{`Waiting for ${node.name}`}</Busy>
          </p>
        )}
        {lines.length > 0 && (
          <ul aria-label="Result" className="space-y-1 text-sm">
            {lines.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        )}
        {error && (
          <p role="alert" className="text-sm text-destructive">
            {error}
          </p>
        )}
        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>
            Close
          </Button>
          <Button disabled={running || !chosen} onClick={start}>
            {running ? <Waiting /> : "Test Link"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
