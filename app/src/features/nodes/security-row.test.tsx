import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";

import type { NodeRecord, SecurityReport } from "@/types";

import { SecurityRowHead } from "./security-row";

const SEEN = Date.parse("2026-11-03T10:00:00Z");

const node = (agent = "0.7.35") =>
  ({ id: "n1", name: "server-1", agent_version: agent }) as NodeRecord;

const report: SecurityReport = {
  checkedAt: "2026-11-03T09:58:00Z",
  findings: [{ id: "public-ports", severity: "warning", detail: "8080/tcp" }],
  recipes: [
    "security-updates",
    "reboot-window",
    "ssh-keys-only",
    "no-root-login",
    "fail2ban",
    "firewall",
  ],
  lockdown: false,
  rebootHour: null,
  platform: {
    family: "debian",
    name: "Debian 12",
    id: "debian",
    version: "12",
    endOfLife: null,
  },
  firewall: { closed: true, open: [], other: [] },
};

const head = (props: Partial<Parameters<typeof SecurityRowHead>[0]> = {}) =>
  renderToStaticMarkup(
    <MemoryRouter>
      <SecurityRowHead
        node={node()}
        report={report}
        seen={SEEN}
        open={false}
        checking={false}
        onToggle={() => {}}
        onCheck={() => {}}
        {...props}
      />
    </MemoryRouter>,
  );

const text = (html: string) => html.replace(/<[^>]+>/gu, " ");

describe("a server's row on the Security page", () => {
  it("sums the server up and says how much is left to check", () => {
    const html = head();
    expect(html).toMatch(/aria-expanded="false"[^>]*>server-1</u);
    expect(text(html)).toContain("Debian 12 · Checked 2m ago");
    expect(text(html)).toContain("All 5 On");
    expect(text(html)).toContain("ufw · Closed");
    expect(text(html)).toContain("1 to check");
    expect(text(html)).not.toContain("Check Now");
  });

  it("offers Check Now in place of the count once open", () => {
    const html = head({ open: true });
    expect(html).toMatch(/aria-expanded="true"/u);
    expect(text(html)).toContain("Check Now");
    expect(text(html)).not.toContain("1 to check");
  });

  it("says All clear when nothing is left to check", () => {
    expect(text(head({ report: { ...report, findings: [] } }))).toContain(
      "All clear",
    );
  });

  it("does not open for a server that cannot report, and says why", () => {
    const old = head({ node: node("0.6.0") });
    expect(old).not.toContain("aria-expanded");
    expect(text(old)).toContain("Agent too old to report security");
    const silent = head({ report: undefined });
    expect(silent).not.toContain("aria-expanded");
    expect(text(silent)).toContain("No security report yet");
    expect(text(silent)).toContain("Check Now");
  });
});
