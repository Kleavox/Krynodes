import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { ChangeBody, removeChange } from "./change-dialog";
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

const body = (checking: boolean) =>
  renderToStaticMarkup(
    <ChangeBody
      change={removeChange({
        node: "11111111-1111-4111-8111-111111111111",
        name: "server-1",
      })}
      phase="running"
      said={null}
      checking={checking}
      onStart={none}
      onClose={none}
    >
      {checking && <OneTimeCheck members={unchecked} onAnswer={none} />}
    </ChangeBody>,
  );

describe("the change dialog", () => {
  it("shows the fingerprint check, not the wait for the passkey, while a check is open", () => {
    const shown = body(true);
    expect(shown).toContain('aria-label="Check Fingerprints"');
    expect(shown).toContain("They Match");
    expect(shown).not.toContain("Waiting for your passkey");
  });

  it("waits for the passkey once nothing is left to check", () => {
    const shown = body(false);
    expect(shown).not.toContain("Check Fingerprints");
    expect(shown).toContain("Waiting for your passkey");
  });
});
