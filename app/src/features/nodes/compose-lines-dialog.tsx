import { useState } from "react";
import { toast } from "sonner";

import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { composeLines, composeNote, type BridgeNetwork } from "@/lib/bridges";

export function ComposeLinesDialog({
  serverName,
  network,
  onClose,
}: {
  serverName: string;
  network: BridgeNetwork | null;
  onClose: () => void;
}) {
  const [copied, setCopied] = useState(false);
  const lines = network
    ? composeLines(network, network.members[0]?.service ?? "app")
    : "";
  const copy = () => {
    navigator.clipboard.writeText(lines).then(
      () => setCopied(true),
      () => toast.error("Copy failed. Select the lines and copy them by hand."),
    );
  };
  return (
    <AlertDialog
      open={network !== null}
      onOpenChange={(open) => {
        if (!open) {
          setCopied(false);
          onClose();
        }
      }}
    >
      <AlertDialogContent className="max-sm:top-auto max-sm:bottom-0 max-sm:translate-y-0 max-sm:rounded-b-none">
        {network && (
          <>
            <AlertDialogHeader>
              <AlertDialogTitle>Use {network.name} in a Stack</AlertDialogTitle>
              <AlertDialogDescription>
                Add these lines to the stack&apos;s compose file, then Deploy.
              </AlertDialogDescription>
            </AlertDialogHeader>
            <pre className="overflow-x-auto rounded-md border p-3 font-mono text-xs leading-relaxed select-all">
              {lines}
            </pre>
            <p className="text-sm text-muted-foreground">
              {composeNote(network.kind, serverName)}
            </p>
            <AlertDialogFooter>
              <AlertDialogCancel>Close</AlertDialogCancel>
              <Button onClick={copy}>{copied ? "Copied" : "Copy"}</Button>
            </AlertDialogFooter>
          </>
        )}
      </AlertDialogContent>
    </AlertDialog>
  );
}
