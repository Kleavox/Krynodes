import { useState } from "react";

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
import { Label } from "@/components/ui/label";
import { buildChange, moveChange } from "@/lib/devices";
import type { DeviceRecord } from "@/types";

import type { Fleet } from "./use-fleet";

const ADDRESS = /^[^\s@]+@[^\s@]+$/u;

export function accountProblem(
  value: string,
  device: Pick<DeviceRecord, "name" | "owner">,
): string | null {
  const account = value.trim();
  if (account === "") return "";
  if (account.length > 254 || !ADDRESS.test(account)) {
    return "Enter the address that account signs in with.";
  }
  return account === device.owner
    ? `${device.name} already belongs to this account.`
    : null;
}

export function MoveDialog({
  fleet,
  device,
  onClose,
  onReview,
}: {
  fleet: Fleet;
  device: DeviceRecord | null;
  onClose: () => void;
  onReview: (text: string) => void;
}) {
  const [account, setAccount] = useState("");
  const close = () => {
    setAccount("");
    onClose();
  };
  const problem = device ? accountProblem(account, device) : "";
  const others = [
    ...new Set(
      fleet.devices
        .map((entry) => entry.owner)
        .filter(
          (owner): owner is string => Boolean(owner) && owner !== device?.owner,
        ),
    ),
  ];
  return (
    <Dialog open={device !== null} onOpenChange={(open) => !open && close()}>
      {device && (
        <DialogContent className="sm:max-w-sm">
          <form
            className="grid gap-4"
            onSubmit={(event) => {
              event.preventDefault();
              if (problem !== null) return;
              const text = buildChange(
                fleet.view,
                moveChange(fleet.view, device, account.trim()),
              );
              setAccount("");
              onReview(text);
            }}
          >
            <DialogHeader>
              <DialogTitle>Move {device.name} to Another Account</DialogTitle>
              <DialogDescription>
                It stays trusted and keeps its servers. Afterwards only the
                other account signs with it, and you no longer can.
              </DialogDescription>
            </DialogHeader>
            <div className="grid gap-1.5">
              <Label htmlFor="move-account">Account</Label>
              <Input
                id="move-account"
                type="email"
                list="move-accounts"
                maxLength={254}
                autoComplete="off"
                autoFocus
                value={account}
                aria-invalid={Boolean(problem)}
                aria-describedby={problem ? "move-problem" : undefined}
                onChange={(event) => setAccount(event.target.value)}
              />
              <datalist id="move-accounts">
                {others.map((owner) => (
                  <option key={owner} value={owner} />
                ))}
              </datalist>
              {problem && (
                <p id="move-problem" className="text-sm text-destructive">
                  {problem}
                </p>
              )}
            </div>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={close}>
                Cancel
              </Button>
              <Button type="submit" disabled={problem !== null}>
                Review
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      )}
    </Dialog>
  );
}
