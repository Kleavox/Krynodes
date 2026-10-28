import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { Mark } from "./screens";

describe("Mark", () => {
  it("shows the hub mark and the word Krynodes", () => {
    const html = renderToStaticMarkup(<Mark />);
    expect(html).toContain("</svg>Krynodes</span>");
    expect(html).not.toContain("KRYNODES");
    expect(html).toMatch(/<svg[^>]*aria-hidden="true"/u);
    expect(html.match(/<circle/gu)).toHaveLength(3);
  });
});
