import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { WarningStrip } from "./quarantine-panels";

const none = () => {};

const rows = (
  rows: { confirming?: boolean; cutting?: boolean; error?: string }[],
) =>
  renderToStaticMarkup(
    <>
      {rows.map((row, index) => (
        <WarningStrip
          key={index}
          strip={{
            title: `Warning ${index + 1}`,
            detail: null,
            cutoff: "Cut off in 10 minutes",
          }}
          cutting={row.cutting ?? false}
          confirming={row.confirming ?? false}
          error={row.error ?? null}
          onCut={none}
          onMine={none}
        />
      ))}
    </>,
  )
    .split("<section")
    .slice(1);

describe("It Was Me on each warning", () => {
  it("waits for the Fingerprint on the pressed row only", () => {
    const [first, second, third] = rows([{}, { confirming: true }, {}]);
    expect(second).toContain("Waiting for the Fingerprint…");
    for (const row of [first!, third!]) {
      expect(row).not.toContain("Waiting for the Fingerprint…");
      expect(row).toContain("It Was Me");
      expect(row).not.toContain('disabled=""');
    }
  });

  it("shows an error under its own row", () => {
    const [first, , third] = rows([{}, {}, { error: "The server said no." }]);
    expect(third).toContain("The server said no.");
    expect(first).not.toContain("The server said no.");
  });
});
