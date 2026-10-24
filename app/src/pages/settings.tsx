import { NavLink, Outlet } from "react-router";

import { PageHeader } from "@/components/page-header";
import { cn } from "@/lib/utils";

const SECTIONS = [
  { path: "cloudflare", label: "Cloudflare" },
  { path: "private-addresses", label: "Private Addresses" },
  { path: "enroll", label: "Enroll Defaults" },
  { path: "usage", label: "Usage" },
];

export function SettingsPage() {
  return (
    <>
      <PageHeader title="Settings" />
      <div className="grid grid-cols-1 gap-6 md:grid-cols-[13rem_minmax(0,1fr)]">
        <nav
          aria-label="Settings sections"
          className="flex flex-wrap gap-1 md:flex-col md:flex-nowrap"
        >
          {SECTIONS.map((section) => (
            <NavLink
              key={section.path}
              to={section.path}
              className={({ isActive }) =>
                cn(
                  "rounded-md px-2.5 py-1.5 text-sm text-muted-foreground hover:bg-accent/60 hover:text-foreground",
                  isActive && "bg-accent text-foreground",
                )
              }
            >
              {section.label}
            </NavLink>
          ))}
        </nav>
        <div className="max-w-2xl min-w-0">
          <Outlet />
        </div>
      </div>
    </>
  );
}
