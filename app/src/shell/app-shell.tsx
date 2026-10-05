import { useEffect, useState } from "react";
import { Link, NavLink, Outlet } from "react-router";
import { ChevronDown, Search, User } from "lucide-react";
import { displayHandle } from "@/lib/format";
import { errorMessage } from "@/lib/http";

import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useSignedAction } from "@/features/deploy/use-signed-action";
import { useDevices, useOverview, useProposals, useServices } from "@/lib/api";
import { timeAgo } from "@/lib/format";
import { accountLinks } from "@/lib/account";
import { useLiveUpdates } from "@/lib/live";
import { useNow } from "@/lib/use-now";
import { cn } from "@/lib/utils";
import { isPending } from "@/lib/services";
import type { Identity, Overview, ServicesResponse, SessionVia } from "@/types";

import { ActivityMenu } from "./activity-menu";
import { CommandPalette } from "./command-palette";
import { SECTIONS } from "./nav";
import { FaultScreen, Mark } from "./screens";

function attention(
  overview: Overview | undefined,
  services: ServicesResponse | undefined,
): Record<string, number> {
  return {
    "/incidents":
      overview?.incidents.filter((incident) => incident.status === "OPEN")
        .length ?? 0,
    "/services": services?.actions.filter(isPending).length ?? 0,
  };
}

function ageOf(updatedAt: number, now: number): string {
  return timeAgo(new Date(updatedAt).toISOString(), now);
}

export function AppShell({
  identity,
  via,
}: {
  identity: Identity;
  via: SessionVia;
}) {
  useLiveUpdates();
  const overview = useOverview();
  const services = useServices();
  const runAction = useSignedAction();
  const [paletteOpen, setPaletteOpen] = useState(false);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setPaletteOpen((open) => !open);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  if (overview.isError && !overview.data) {
    return (
      <FaultScreen
        message={errorMessage(overview.error)}
        onRetry={() => void overview.refetch()}
      />
    );
  }

  const counts = attention(overview.data, services.data);

  return (
    <div className="min-h-dvh pb-16 md:pb-0">
      <header className="sticky top-0 z-30 flex h-12 items-center gap-3 border-b bg-card px-4">
        <Link
          to="/"
          aria-label="Krynodes home"
          className="flex min-h-9 items-center rounded-sm md:min-h-0"
        >
          <Mark />
        </Link>
        <nav
          aria-label="Sections"
          className="ml-4 hidden flex-1 items-center gap-1 md:flex"
        >
          {SECTIONS.map((section) => (
            <NavLink
              key={section.to}
              to={section.to}
              end={section.end}
              className={({ isActive }) =>
                cn(
                  "rounded-md px-2.5 py-1.5 text-sm text-muted-foreground hover:text-foreground",
                  isActive && "bg-accent text-foreground",
                )
              }
            >
              {section.label}
              <Count value={counts[section.to]} />
            </NavLink>
          ))}
        </nav>
        <span className="flex-1 md:hidden" />
        <ActivityMenu />
        <Button
          variant="outline"
          size="sm"
          onClick={() => setPaletteOpen(true)}
          aria-label="Search and commands"
          aria-keyshortcuts="Control+K"
        >
          <Search aria-hidden="true" />
          <span className="hidden md:inline">Search</span>
          <kbd className="hidden font-mono text-[11px] text-muted-foreground md:inline">
            Ctrl K
          </kbd>
        </Button>
        <AccountMenu identity={identity} via={via} />
      </header>
      {overview.isRefetchError && (
        <StaleBanner updatedAt={overview.dataUpdatedAt} />
      )}
      <main className="mx-auto w-full max-w-[1400px] px-4 py-5 md:px-6">
        <Outlet />
      </main>
      <nav
        aria-label="Sections"
        className="fixed inset-x-0 bottom-0 z-30 grid grid-cols-5 border-t bg-card md:hidden"
      >
        {SECTIONS.map((section) => (
          <NavLink
            key={section.to}
            to={section.to}
            end={section.end}
            className={({ isActive }) =>
              cn(
                "relative flex min-h-14 flex-col items-center justify-center gap-0.5 text-[11px] text-muted-foreground",
                isActive && "text-foreground",
              )
            }
          >
            <section.icon aria-hidden="true" className="size-4" />
            {section.label}
            <Count
              value={counts[section.to]}
              className="absolute top-1.5 right-[calc(50%-22px)] ml-0"
            />
          </NavLink>
        ))}
      </nav>
      <CommandPalette
        open={paletteOpen}
        onOpenChange={setPaletteOpen}
        nodes={overview.data?.nodes ?? []}
        services={services.data}
        onRun={(target, action) =>
          runAction.mutate({ action, targets: [target] })
        }
      />
    </div>
  );
}

function Count({
  value,
  className,
}: {
  value: number | undefined;
  className?: string;
}) {
  if (!value) return null;
  return (
    <span
      className={cn(
        "ml-1.5 rounded bg-destructive/15 px-1.5 font-mono text-[10px] text-destructive",
        className,
      )}
    >
      <span className="sr-only">, </span>
      {value}
      <span className="sr-only"> open</span>
    </span>
  );
}

function StaleBanner({ updatedAt }: { updatedAt: number }) {
  const now = useNow();
  return (
    <div
      role="status"
      className="border-b border-warning/40 bg-warning/10 px-4 py-2 text-center text-sm"
    >
      Can't reach Krynodes. Showing data from {ageOf(updatedAt, now)}.
    </div>
  );
}

function AccountMenu({
  identity,
  via,
}: {
  identity: Identity;
  via: SessionVia;
}) {
  const handle = displayHandle(identity.username, identity.email);
  const links = accountLinks(via);
  const proposals = useProposals();
  const devices = useDevices();
  const approvals =
    (proposals.data?.proposals.filter((proposal) => proposal.status === "open")
      .length ?? 0) +
    (devices.data?.devices.filter((device) => !device.core).length ?? 0);
  return (
    <DropdownMenu modal={false}>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          size="sm"
          className="relative"
          aria-label={`Account ${handle}${approvals > 0 ? `, ${approvals} waiting for approval` : ""}`}
        >
          <User aria-hidden="true" className="sm:hidden" />
          <span className="hidden max-w-32 truncate sm:inline">{handle}</span>
          <ChevronDown aria-hidden="true" />
          {approvals > 0 && (
            <span
              aria-hidden="true"
              className="absolute top-1 right-1 size-2 rounded-full bg-warning"
            />
          )}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuLabel className="font-normal text-muted-foreground">
          {identity.email}
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem asChild>
          <Link to="/devices">Trusted devices</Link>
        </DropdownMenuItem>
        <DropdownMenuItem asChild>
          <Link to="/settings/cloudflare">Cloudflare</Link>
        </DropdownMenuItem>
        {approvals > 0 && (
          <DropdownMenuItem asChild>
            <Link to="/devices">Approvals · {approvals}</Link>
          </DropdownMenuItem>
        )}
        {links.length > 0 && <DropdownMenuSeparator />}
        {links.map((link) => (
          <DropdownMenuItem key={link.href} asChild>
            <a href={link.href}>{link.label}</a>
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
