import { useEffect } from "react";
import {
  Link,
  NavLink,
  Outlet,
  useLocation,
  useNavigationType,
} from "react-router";
import { ChevronDown, User } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { displayHandle } from "@/lib/format";
import { useLiveUpdates } from "@/lib/live";
import { cn } from "@/lib/utils";
import type { Identity, SessionVia } from "@/types";

import { SECTIONS } from "./nav";
import { Mark } from "./screens";

export function AppShell({
  identity,
  via,
}: {
  identity: Identity;
  via: SessionVia;
}) {
  const { pathname } = useLocation();
  const navigation = useNavigationType();
  useLiveUpdates();

  useEffect(() => {
    if (navigation !== "POP") window.scrollTo(0, 0);
  }, [pathname, navigation]);

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
                  isActive &&
                    "bg-primary-subtle text-primary-text hover:text-primary-text",
                )
              }
            >
              {section.label}
            </NavLink>
          ))}
        </nav>
        <span className="flex-1 md:hidden" />
        <AccountMenu identity={identity} via={via} />
      </header>
      <main className="mx-auto w-full max-w-[1400px] px-4 py-5 md:px-6">
        <Outlet />
      </main>
      <nav
        aria-label="Sections"
        className="fixed inset-x-0 bottom-0 z-30 grid auto-cols-fr grid-flow-col border-t bg-card md:hidden"
      >
        {SECTIONS.map((section) => (
          <NavLink
            key={section.to}
            to={section.to}
            end={section.end}
            className={({ isActive }) =>
              cn(
                "flex min-h-14 flex-col items-center justify-center gap-0.5 text-[11px] text-muted-foreground",
                isActive && "text-primary-text",
              )
            }
          >
            <section.icon aria-hidden="true" className="size-4" />
            {section.label}
          </NavLink>
        ))}
      </nav>
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
  return (
    <DropdownMenu modal={false}>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="sm" aria-label={`Account ${handle}`}>
          <User aria-hidden="true" className="sm:hidden" />
          <span className="hidden max-w-32 truncate sm:inline">{handle}</span>
          <ChevronDown aria-hidden="true" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuLabel className="font-normal text-muted-foreground">
          {identity.email}
        </DropdownMenuLabel>
        {via === "access" && (
          <>
            <DropdownMenuSeparator />
            <DropdownMenuItem asChild>
              <a href="/cdn-cgi/access/logout">Sign Out</a>
            </DropdownMenuItem>
          </>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
