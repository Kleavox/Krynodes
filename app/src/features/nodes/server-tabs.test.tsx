import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { ServerTabs, serverTab } from "./server-tabs";

describe("the server page's tabs", () => {
  it("marks the open tab", () => {
    const html = renderToStaticMarkup(
      <ServerTabs tab="security" onTab={() => {}} />,
    );
    expect(html).toContain('role="tablist"');
    expect(html).toMatch(/aria-selected="false"[^>]*>Overview</u);
    expect(html).toMatch(/aria-selected="true"[^>]*>Security</u);
  });

  it("opens Overview for anything but security", () => {
    expect(serverTab("security")).toBe("security");
    expect(serverTab(null)).toBe("overview");
    expect(serverTab("firewall")).toBe("overview");
  });
});
