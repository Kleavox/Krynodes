import { Check, Copy, Ellipsis, Globe, Lock } from "lucide-react";
import { Fragment, useEffect, useState } from "react";
import { toast } from "sonner";

import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { addressCount, STAND_IN } from "@/lib/addresses";
import { useUpdateNode } from "@/lib/api";
import { errorMessage } from "@/lib/http";
import { cn } from "@/lib/utils";
import type { Address, NodeRecord } from "@/types";

function CopyAddress({
  address,
  nodeName,
}: {
  address: Address;
  nodeName: string;
}) {
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) return;
    const timer = setTimeout(() => setCopied(false), 1500);
    return () => clearTimeout(timer);
  }, [copied]);
  const label = `Copy the ${address.label} address of ${nodeName}`;
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
          () => toast.error("Copy failed. Copy the address by hand."),
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

function RouterTag({ nodeName }: { nodeName: string }) {
  return (
    <span
      title={`Not on ${nodeName} itself: the router it reaches the internet through.`}
      className="shrink-0 rounded border border-warning/40 px-1 font-mono text-[10px] leading-4 text-warning"
    >
      Router
    </span>
  );
}

function AddressStandIn({ nodeName }: { nodeName: string }) {
  return (
    <div className="space-y-2">
      <div
        aria-hidden="true"
        className="flex items-center gap-3 font-mono text-xs blur-[3.5px] select-none"
      >
        <span className="text-muted-foreground">{STAND_IN.label}</span>
        <span>{STAND_IN.address}</span>
      </div>
      <p className="text-xs text-muted-foreground">
        Only accounts trusted on {nodeName} see its addresses.
      </p>
    </div>
  );
}

const OWNER_CHOICES = [
  { value: "own", label: "Its own address" },
  { value: "router", label: "A router's address" },
  { value: "detect", label: "Detect automatically" },
] as const;

function OwnerMenu({ node, address }: { node: NodeRecord; address: Address }) {
  const update = useUpdateNode();
  return (
    <DropdownMenu modal={false}>
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          aria-label={`Whose ${address.label} address this is`}
          className="grid size-6 shrink-0 place-items-center rounded text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
        >
          <Ellipsis aria-hidden="true" className="size-3.5" />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuLabel className="font-mono text-xs font-normal text-muted-foreground">
          {address.label} {address.address}
        </DropdownMenuLabel>
        <DropdownMenuRadioGroup
          value={address.owner ?? "detect"}
          onValueChange={(value) =>
            update.mutate(
              {
                id: node.id,
                addressOwner: {
                  family: address.family,
                  owner: value === "own" || value === "router" ? value : null,
                },
              },
              { onError: (error) => toast.error(errorMessage(error)) },
            )
          }
        >
          {OWNER_CHOICES.map((choice) => (
            <DropdownMenuRadioItem key={choice.value} value={choice.value}>
              {choice.label}
            </DropdownMenuRadioItem>
          ))}
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

export function AddressRows({
  node,
  correct = false,
}: {
  node: NodeRecord;
  correct?: boolean;
}) {
  if (node.addresses === null) return <AddressStandIn nodeName={node.name} />;
  const addresses = node.addresses ?? [];
  if (addresses.length === 0) {
    return (
      <p className="text-xs text-muted-foreground">No address reported yet.</p>
    );
  }
  return (
    <dl className="grid grid-cols-[auto_minmax(0,1fr)_auto] items-start gap-x-3 gap-y-1.5 font-mono text-xs">
      {addresses.map((address) => (
        <Fragment key={`${address.label} ${address.address}`}>
          <dt className="leading-6 text-muted-foreground">{address.label}</dt>
          <dd className="min-w-0 leading-6">
            <span className="flex min-w-0 flex-wrap items-center gap-x-1.5">
              <span className="min-w-0 break-all" translate="no">
                {address.address}
              </span>
              {address.router && <RouterTag nodeName={node.name} />}
            </span>
            {address.network && (
              <span className="block truncate font-sans text-[11px] leading-4 text-muted-foreground">
                {address.network}
              </span>
            )}
          </dd>
          <dd className="flex items-center">
            <CopyAddress address={address} nodeName={node.name} />
            {correct && address.label === `IPv${address.family}` && (
              <OwnerMenu node={node} address={address} />
            )}
          </dd>
        </Fragment>
      ))}
    </dl>
  );
}

export function AddressesButton({
  node,
  className,
}: {
  node: NodeRecord;
  className?: string;
}) {
  const hidden = node.addresses === null;
  const count = node.addresses?.length ?? 0;
  if (!hidden && count === 0) return null;
  const Icon = hidden ? Lock : Globe;
  const text = hidden ? "Addresses" : addressCount(count);
  return (
    <div className={className}>
      <Popover>
        <PopoverTrigger asChild>
          <button
            type="button"
            aria-label={`${text} of ${node.name}`}
            onClick={(event) => event.stopPropagation()}
            className="relative z-10 -ml-1 inline-flex h-6 items-center gap-1.5 rounded px-1 font-mono text-[11px] text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none data-[state=open]:bg-accent data-[state=open]:text-foreground"
          >
            <Icon aria-hidden="true" className="size-3.5" />
            {text}
          </button>
        </PopoverTrigger>
        <PopoverContent
          align="start"
          className="w-80 max-w-[calc(100vw-2rem)] p-3"
          onClick={(event) => event.stopPropagation()}
        >
          <AddressRows node={node} />
        </PopoverContent>
      </Popover>
    </div>
  );
}
