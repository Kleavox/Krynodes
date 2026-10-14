import { Check, Copy, Lock, LockOpen } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import {
  maskAddress,
  serverAddresses,
  type ServerAddress,
} from "@/lib/addresses";
import { useAddressDisplay } from "@/lib/api";
import { setAddressesShown, useAddressesShown } from "@/lib/reveal";
import { cn } from "@/lib/utils";
import type { NodeRecord } from "@/types";

function useAddressView() {
  const display = useAddressDisplay();
  const shown = useAddressesShown();
  const always = display.data?.display === "shown";
  return { visible: always || shown, lockable: !always };
}

export function AddressLock({ className }: { className?: string }) {
  const { visible, lockable } = useAddressView();
  if (!lockable) return null;
  const Icon = visible ? LockOpen : Lock;
  return (
    <Button
      variant="ghost"
      size="sm"
      className={cn("h-8 text-muted-foreground", className)}
      aria-pressed={visible}
      aria-label={visible ? "Hide server addresses" : "Show server addresses"}
      title={visible ? "Hide server addresses" : "Show server addresses"}
      onClick={() => setAddressesShown(!visible)}
    >
      <Icon aria-hidden="true" />
      <span className="hidden lg:inline">
        {visible ? "Hide addresses" : "Show addresses"}
      </span>
    </Button>
  );
}

export function CopyAddress({
  address,
  nodeName,
}: {
  address: ServerAddress;
  nodeName: string;
}) {
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) return;
    const timer = setTimeout(() => setCopied(false), 1500);
    return () => clearTimeout(timer);
  }, [copied]);
  const label = `Copy the IPv${address.family} address of ${nodeName}`;
  return (
    <button
      type="button"
      aria-label={copied ? "Copied" : label}
      title={copied ? "Copied" : label}
      className="relative z-10 grid size-6 shrink-0 place-items-center rounded text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
      onClick={(event) => {
        event.stopPropagation();
        navigator.clipboard.writeText(address.address).then(
          () => setCopied(true),
          () =>
            toast.error("Copy failed. Show the address and copy it by hand."),
        );
      }}
    >
      {copied ? (
        <Check aria-hidden="true" className="size-3.5 text-success" />
      ) : (
        <Copy aria-hidden="true" className="size-3.5" />
      )}
    </button>
  );
}

export function AddressText({ address }: { address: ServerAddress }) {
  const { visible } = useAddressView();
  return (
    <span className="min-w-0 truncate" translate="no">
      {visible ? address.address : maskAddress(address)}
    </span>
  );
}

export function AddressLine({
  node,
  className,
}: {
  node: NodeRecord;
  className?: string;
}) {
  const addresses = serverAddresses(node);
  if (addresses.length === 0) return null;
  return (
    <p
      className={cn(
        "relative z-10 flex min-w-0 flex-wrap items-center gap-x-3 font-mono text-[11px] text-muted-foreground",
        className,
      )}
    >
      {addresses.map((address) => (
        <span key={address.family} className="flex min-w-0 items-center gap-1">
          <span className="text-muted-foreground/70">IPv{address.family}</span>
          <AddressText address={address} />
          <CopyAddress address={address} nodeName={node.name} />
        </span>
      ))}
    </p>
  );
}
