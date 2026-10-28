import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";

import { HeartbeatStrip, ReportStrip } from "./strips";

const START = Date.parse("2026-10-28T09:40:00Z");

describe("strips", () => {
  it("draws a quarantined window grey, since it is not counted, never red like Down", () => {
    const report = renderToStaticMarkup(
      <ReportStrip states={["quarantined"]} starts={[START]} />,
    );
    const uptime = renderToStaticMarkup(
      <MemoryRouter>
        <HeartbeatStrip
          slots={[
            {
              start: START,
              tone: "quarantined",
              sample: null,
              work: undefined,
              incident: undefined,
            },
          ]}
          windowSeconds={300}
        />
      </MemoryRouter>,
    );
    for (const html of [report, uptime]) {
      expect(html).toContain("Quarantined");
      expect(html).not.toContain("bg-destructive");
      expect(html).toContain("bg-muted-foreground/35");
    }
  });
});
