import { useState } from "react";
import { Link } from "react-router";
import { ChevronDown, Settings } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { EnrollDefaultsDialog } from "@/features/settings/enroll-defaults-dialog";
import { PrivateRangesDialog } from "@/features/settings/private-ranges-dialog";
import { UsageDialog } from "@/features/usage/usage-dialog";
import { useOverview, useUsage } from "@/lib/api";
import { estimateDailyUse } from "@/lib/budget";

type Open = "ranges" | "enroll" | "usage" | null;

export function SettingsMenu() {
  const [open, setOpen] = useState<Open>(null);
  const show = (dialog: Open) => (next: boolean) =>
    setOpen(next ? dialog : null);
  return (
    <>
      <DropdownMenu modal={false}>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" size="sm" aria-label="Settings">
            <Settings aria-hidden="true" />
            <span className="hidden lg:inline">Settings</span>
            <ChevronDown aria-hidden="true" className="hidden lg:block" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuItem asChild>
            <Link to="/settings/cloudflare">Cloudflare</Link>
          </DropdownMenuItem>
          <DropdownMenuItem onSelect={() => setOpen("ranges")}>
            Private addresses…
          </DropdownMenuItem>
          <DropdownMenuItem onSelect={() => setOpen("enroll")}>
            Enroll defaults…
          </DropdownMenuItem>
          <DropdownMenuItem onSelect={() => setOpen("usage")}>
            Usage…
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
      <PrivateRangesDialog
        open={open === "ranges"}
        onOpenChange={show("ranges")}
      />
      <EnrollDefaultsDialog
        open={open === "enroll"}
        onOpenChange={show("enroll")}
      />
      {open === "usage" && <UsageSettings onOpenChange={show("usage")} />}
    </>
  );
}

function UsageSettings({
  onOpenChange,
}: {
  onOpenChange: (open: boolean) => void;
}) {
  const usage = useUsage();
  const nodes = useOverview().data?.nodes ?? [];
  return (
    <UsageDialog
      open
      onOpenChange={onOpenChange}
      usage={usage.data}
      estimate={estimateDailyUse(nodes)}
    />
  );
}
