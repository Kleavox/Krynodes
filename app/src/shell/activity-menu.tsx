import { Hourglass } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router";

import { Elapsed } from "@/components/node-status";
import { StatusDot } from "@/components/status";
import { Button } from "@/components/ui/button";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { useDevices, useOverview, useServices } from "@/lib/api";
import { activity, type ActivityItem } from "@/lib/operations";
import { runningText } from "@/lib/services";
import { useNow } from "@/lib/use-now";
import { cn } from "@/lib/utils";

const ROW =
  "grid grid-cols-[auto_minmax(0,1fr)] items-start gap-x-2.5 rounded-md px-2 py-1.5 text-sm hover:bg-accent";

function Running({ item, onPick }: { item: ActivityItem; onPick: () => void }) {
  return (
    <li>
      <Link to={`/nodes/${item.nodeId}`} onClick={onPick} className={ROW}>
        <StatusDot tone="warn" pulse className="mt-1.5" />
        <span className="min-w-0">
          <span className="block truncate">
            {runningText(item.action, item.nodeName)}
          </span>
          <span className="block font-mono text-[11px] text-muted-foreground">
            {item.by} · <Elapsed since={item.at} />
            {item.status === "queued" && " · waiting"}
          </span>
        </span>
      </Link>
    </li>
  );
}

export function ActivityMenu() {
  const services = useServices();
  const overview = useOverview();
  const devices = useDevices();
  const [open, setOpen] = useState(false);
  const now = useNow(open ? 5_000 : 30_000);
  const list = activity(
    services.data?.actions ?? [],
    overview.data?.nodes ?? [],
    now,
    devices.data?.devices,
  );
  const running = list.length;
  const close = () => setOpen(false);
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          variant="outline"
          size="sm"
          aria-label={
            running > 0 ? `${running} in progress` : "Nothing in progress"
          }
          className={cn(running > 0 && "border-warning/40")}
        >
          {running > 0 ? (
            <>
              <StatusDot tone="warn" pulse />
              <span className="font-mono text-xs">
                {running}
                <span className="hidden md:inline"> in progress</span>
              </span>
            </>
          ) : (
            <Hourglass aria-hidden="true" />
          )}
        </Button>
      </PopoverTrigger>
      <PopoverContent
        align="end"
        className="max-h-[70dvh] w-[min(22rem,calc(100vw-2rem))] overflow-y-auto p-2"
      >
        <h2 className="px-2 pt-1 pb-1.5 text-[11px] tracking-wider text-muted-foreground uppercase">
          In progress
        </h2>
        {running === 0 ? (
          <p className="px-2 pb-2 text-sm text-muted-foreground">
            Nothing is running.
          </p>
        ) : (
          <ul>
            {list.map((item) => (
              <Running key={item.id} item={item} onPick={close} />
            ))}
          </ul>
        )}
        <Link
          to="/history"
          onClick={close}
          className="mt-1 block border-t px-2 pt-2.5 pb-1 text-sm text-muted-foreground hover:text-foreground"
        >
          View history
        </Link>
      </PopoverContent>
    </Popover>
  );
}
