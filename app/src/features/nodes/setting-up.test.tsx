import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { SettingUpCard } from "./setting-up";

describe("a server that is setting up", () => {
  it("shows the shape of a server card loading, with no data and nothing to open", () => {
    const html = renderToStaticMarkup(<SettingUpCard name="server-1" />);
    expect(html).toContain("server-1");
    expect(html).toContain("Setting Up");
    expect(html).toContain('aria-busy="true"');
    expect(html).toContain('role="status"');
    expect(html).toContain("Opens when setup is done");
    expect(
      html.match(/data-slot="skeleton"/g)?.length ?? 0,
    ).toBeGreaterThanOrEqual(5);
    expect(html).not.toContain("<button");
    expect(html).not.toContain("<a ");
    expect(html).not.toMatch(/\d%/);
  });
});
