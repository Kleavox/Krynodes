import { KeyRound } from "lucide-react";
import { useState } from "react";

import { Busy, Waiting } from "@/components/busy";
import { Field } from "@/components/field";
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
import {
  useNetworkKeys,
  useSignChange,
} from "@/features/network/use-network-sign";
import { useNetwork, useUpdateNode } from "@/lib/api";
import { errorMessage } from "@/lib/http";
import { networkText } from "@/lib/network";
import type { NodeRecord } from "@/types";

export function EditNodeDialog({
  node,
  open,
  onOpenChange,
}: {
  node: NodeRecord;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const [name, setName] = useState(node.name);
  const save = useUpdateNode();
  const network = useNetwork().data;
  const member = network?.members.find(
    (entry) => entry.nodeId === node.id && entry.state === "in",
  );
  const told = useSignChange();
  const keys = useNetworkKeys(network?.members ?? []);
  const close = (next: boolean) => {
    if (!next) {
      setName(node.name);
      save.reset();
      told.reset();
    }
    onOpenChange(next);
  };

  const trimmed = name.trim();
  const changed = trimmed !== "" && trimmed !== node.name;

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent>
        <form
          className="space-y-4"
          onSubmit={(event) => {
            event.preventDefault();
            const tell = () =>
              told.mutate(
                {
                  change: { kind: "rename", nodeId: node.id, name: trimmed },
                  text: networkText.rename(member!.name, trimmed),
                  signers: keys.signers,
                },
                { onSuccess: () => onOpenChange(false) },
              );
            if (save.isSuccess && member) return tell();
            save.mutate(
              { id: node.id, name: trimmed },
              { onSuccess: () => (member ? tell() : onOpenChange(false)) },
            );
          }}
        >
          <DialogHeader>
            <DialogTitle>Rename {node.name}</DialogTitle>
            <DialogDescription>
              Every server reports once a minute.
              {member &&
                " It is in the private network, so your passkey tells the others its new name; containers take it at their next deploy."}
            </DialogDescription>
          </DialogHeader>
          <Field id="node-name" label="Name">
            <Input
              id="node-name"
              value={name}
              onChange={(event) => setName(event.target.value)}
              maxLength={100}
              required
            />
          </Field>
          {(save.error ?? told.error) && (
            <p role="alert" className="text-sm text-destructive">
              {errorMessage(save.error ?? told.error)}
            </p>
          )}
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => close(false)}>
              Cancel
            </Button>
            <Button
              type="submit"
              disabled={
                save.isPending ||
                told.isPending ||
                (!changed && !save.isSuccess)
              }
            >
              {member && !save.isPending && !told.isPending && (
                <KeyRound aria-hidden="true" />
              )}
              {save.isPending ? (
                <Busy>Saving</Busy>
              ) : told.isPending ? (
                <Waiting />
              ) : (
                "Save"
              )}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
