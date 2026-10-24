import type { SessionVia } from "../types";

export function accountLinks(
  via: SessionVia,
): { label: string; href: string }[] {
  return via === "access"
    ? [{ label: "Sign Out", href: "/cdn-cgi/access/logout" }]
    : [];
}
