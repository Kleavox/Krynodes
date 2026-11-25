import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { KeysBody, type KeysState } from "./keys-dialog";
import { OneTimeCheck } from "./one-time-check";

const none = () => {};

const unchecked = [
  {
    node: "11111111-1111-4111-8111-111111111111",
    name: "server-1",
    fingerprint: "ABCD-EFGH-JKLM-NPQR",
    line: "Check that server-1 shows the same fingerprint: run sudo kry network fingerprint on it.",
  },
];

const body = (loaded: boolean, state: KeysState, checking = false) =>
  renderToStaticMarkup(
    <KeysBody
      name="server-1"
      loaded={loaded}
      state={state}
      checking={checking}
      onMake={none}
      onUse={none}
      onClose={none}
    >
      {checking && <OneTimeCheck members={unchecked} onAnswer={none} />}
    </KeysBody>,
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

  it("shows the fingerprint check, not a wait for the passkey or the server, while a check is open", () => {
    const checking = body(true, { phase: "making" }, true);
    expect(checking).toContain('aria-label="Check Fingerprints"');
    expect(checking).toContain("They Match");
    expect(checking).not.toContain("Waiting for your passkey");
    expect(checking).not.toContain("Waiting for server-1");
    const waiting = body(true, { phase: "making" });
    expect(waiting).toContain("Waiting for your passkey");
    expect(waiting).toContain("Waiting for server-1");
  });

  it("cannot be closed while the server or the passkey is working", () => {
    for (const phase of ["making", "signing"] as const) {
      expect(body(true, { phase })).toMatch(
        /<button[^>]*disabled=""[^>]*>Close<\/button>/u,
      );
    }
  });
});
