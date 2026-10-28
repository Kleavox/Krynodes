import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { FixLine } from "./test-dialog";

const none = () => {};

const line = (props: { fixed?: boolean; pending?: boolean; error?: string }) =>
  renderToStaticMarkup(
    <FixLine
      label="Send the Addresses Again"
      fixed={props.fixed ?? false}
      pending={props.pending ?? false}
      error={props.error ?? null}
      onFix={none}
    />,
  );

describe("Test Link fixes per pair", () => {
  it("marks only the pair that was fixed", () => {
    expect(line({ fixed: true })).toContain(
      "Sent. Test again once the servers have it.",
    );
    const other = line({});
    expect(other).not.toContain("Sent.");
    expect(other).toContain("Send the Addresses Again");
    expect(other).not.toContain('disabled=""');
  });

  it("waits and fails on its own pair", () => {
    expect(line({ pending: true })).toContain("Waiting for your passkey");
    expect(line({ error: "Signing was cancelled." })).toContain(
      "Signing was cancelled.",
    );
  });
});
