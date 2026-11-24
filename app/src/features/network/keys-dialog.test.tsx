import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { KeysBody, type KeysState } from "./keys-dialog";

const none = () => {};

const body = (loaded: boolean, state: KeysState) =>
  renderToStaticMarkup(
    <KeysBody
      name="server-1"
      loaded={loaded}
      state={state}
      onMake={none}
      onUse={none}
      onClose={none}
    />,
  );

describe("new keys", () => {
  it("Make New Keys waits until the current document has loaded", () => {
    expect(body(false, { phase: "confirm" })).toMatch(
      /<button[^>]*disabled=""[^>]*>Make New Keys<\/button>/u,
    );
    expect(body(true, { phase: "confirm" })).toMatch(
      /<button(?![^>]*disabled="")[^>]*>Make New Keys<\/button>/u,
    );
  });

  it("shows the new fingerprint before Use New Keys signs anything", () => {
    const html = body(true, {
      phase: "made",
      shown: {
        fingerprint: "ABCD-EF01-2345-6789",
        line: "Check that server-1 shows the same fingerprint: run sudo kry network fingerprint on it.",
      },
    });
    expect(html).toContain("ABCD-EF01-2345-6789");
    expect(html).toMatch(/<button[^>]*>Use New Keys<\/button>/u);
    expect(html).not.toContain("Make New Keys");
  });

  it("cannot be closed while the server or the passkey is working", () => {
    for (const phase of ["making", "signing"] as const) {
      expect(body(true, { phase })).toMatch(
        /<button[^>]*disabled=""[^>]*>Close<\/button>/u,
      );
    }
  });
});
