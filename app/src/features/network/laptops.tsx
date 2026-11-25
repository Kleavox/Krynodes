import { useMutation } from "@tanstack/react-query";
import { useState, type ReactNode } from "react";

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
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { EnrollForm } from "@/features/fleet/enroll-dialog";
import { networkApi, useDevices } from "@/lib/api";
import { changeNetwork } from "@/lib/approve";
import { stampTime } from "@/lib/format";
import { errorMessage } from "@/lib/http";
import { laptopInstall, networkFailure, withDns } from "@/lib/network";
import type { LaptopCode } from "@/types";

import { useOneTimeCheck } from "./one-time-check";
import { useRefreshNetwork } from "./use-network";

export function LaptopCodeSheet({ code }: { code: LaptopCode }) {
  return (
    <div className="space-y-3">
      <p className="text-sm">
        On the laptop, download Krynodes for Windows to Downloads, then run this
        in PowerShell as Administrator.
      </p>
      <a
        className="block w-fit text-sm underline underline-offset-4"
        href={code.download}
      >
        Download Krynodes for Windows
      </a>
      <CopyCommand command={laptopInstall(code)} />
      <p className="text-xs text-muted-foreground">
        The code works once and expires at {stampTime(code.expiresAt)}. The
        laptop then asks to join, and joins when you approve it.
      </p>
    </div>
  );
}

export function AddLaptopDialog({ onClose }: { onClose: () => void }) {
  const devices = useDevices();
  const add = useMutation({ mutationFn: networkApi.addLaptop });
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent onInteractOutside={(event) => event.preventDefault()}>
        <DialogHeader>
          <DialogTitle>Add Laptop</DialogTitle>
          <DialogDescription>
            A laptop joins the private network and reaches the servers on their
            private addresses.
          </DialogDescription>
        </DialogHeader>
        {add.data ? (
          <>
            <LaptopCodeSheet code={add.data} />
            <DialogFooter>
              <Button variant="ghost" onClick={onClose}>
                Done
              </Button>
            </DialogFooter>
          </>
        ) : devices.data ? (
          <EnrollForm
            label="Laptop Name"
            devices={devices.data}
            pending={add.isPending}
            error={add.error}
            onCancel={onClose}
            onCreate={(body) => add.mutate(body)}
          />
        ) : devices.isError ? (
          <p role="alert" className="text-sm text-destructive">
            {errorMessage(devices.error)}
          </p>
        ) : (
          <Skeleton className="h-24" />
        )}
      </DialogContent>
    </Dialog>
  );
}

export function LaptopDnsBody({
  first,
  second,
  error,
  saved,
  pending,
  checking,
  onFirst,
  onSecond,
  onSave,
  children,
}: {
  first: string;
  second: string;
  error: string | null;
  saved: boolean;
  pending: boolean;
  checking: boolean;
  onFirst: (value: string) => void;
  onSecond: (value: string) => void;
  onSave: () => void;
  children?: ReactNode;
}) {
  return (
    <form
      className="space-y-3 rounded-lg border bg-card p-4"
      onSubmit={(event) => {
        event.preventDefault();
        onSave();
      }}
    >
      <div>
        <h3 className="text-sm font-medium">Laptop DNS</h3>
        <p className="text-xs text-muted-foreground">
          A laptop that sends its traffic out through an exit node asks these
          DNS servers. Saving takes your passkey.
        </p>
      </div>
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="space-y-2">
          <Label htmlFor="laptop-dns-first">First Address</Label>
          <Input
            id="laptop-dns-first"
            value={first}
            inputMode="decimal"
            spellCheck={false}
            className="font-mono"
            placeholder="--"
            onChange={(event) => onFirst(event.target.value)}
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="laptop-dns-second">Second Address</Label>
          <Input
            id="laptop-dns-second"
            value={second}
            inputMode="decimal"
            spellCheck={false}
            className="font-mono"
            placeholder="--"
            onChange={(event) => onSecond(event.target.value)}
          />
        </div>
      </div>
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      {children}
      <div className="flex items-center justify-end gap-3">
        {saved && (
          <span role="status" className="text-xs text-success">
            Saved
          </span>
        )}
        <Button type="submit" size="sm" disabled={pending}>
          {pending && !checking ? <Waiting /> : "Save"}
        </Button>
      </div>
    </form>
  );
}

export function LaptopDns({ dns }: { dns: string[] | null }) {
  const refresh = useRefreshNetwork();
  const { check, panel, checking } = useOneTimeCheck();
  const [first, setFirst] = useState(dns?.[0] ?? "");
  const [second, setSecond] = useState(dns?.[1] ?? "");
  const save = useMutation({
    mutationFn: (typed: string[]) =>
      changeNetwork(
        (next) => withDns(next, typed),
        "Change the DNS for laptops on an exit node",
        { check },
      ),
    onSettled: refresh,
  });
  return (
    <LaptopDnsBody
      first={first}
      second={second}
      error={save.error ? networkFailure(save.error) : null}
      saved={save.isSuccess}
      pending={save.isPending}
      checking={checking}
      onFirst={setFirst}
      onSecond={setSecond}
      onSave={() => save.mutate([first, second])}
    >
      {panel}
    </LaptopDnsBody>
  );
}
