import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { OneTimeCheck } from "./one-time-check";
import { LaptopCodeSheet, LaptopDnsBody } from "./laptops";

describe("adding a laptop", () => {
  it("downloads the agent of the release the Worker pinned", () => {
    const html = renderToStaticMarkup(
      <LaptopCodeSheet
        code={{
          code: "code-1",
          expiresAt: "2026-11-22T11:00:00Z",
          origin: "https://kry.example.test",
          endpoint: "https://kry.example.test",
          download:
            "https://example.test/releases/download/agent-v0.7.92/krynodes-windows-amd64.exe",
        }}
      />,
    );
    expect(html).toContain(
      'href="https://example.test/releases/download/agent-v0.7.92/krynodes-windows-amd64.exe"',
    );
    expect(html).toContain("install --code code-1");
    expect(html).toContain("Copy Command");
  });
});

const none = () => {};

const dns = (checking: boolean) =>
  renderToStaticMarkup(
    <LaptopDnsBody
      first="1.1.1.1"
      second="9.9.9.9"
      error={null}
      saved={false}
      pending
      checking={checking}
      onFirst={none}
      onSecond={none}
      onSave={none}
    >
      {checking && (
        <OneTimeCheck
          members={[
            {
              node: "11111111-1111-4111-8111-111111111111",
              name: "server-1",
              fingerprint: "ABCD-EFGH-JKLM-NPQR",
              line: "Check that server-1 shows the same fingerprint: run sudo kry network fingerprint on it.",
            },
          ]}
          onAnswer={none}
        />
      )}
    </LaptopDnsBody>,
  );

describe("the laptop DNS form", () => {
  it("shows the fingerprint check, not the wait for the passkey, while a check is open", () => {
    const shown = dns(true);
    expect(shown).toContain('aria-label="Check Fingerprints"');
    expect(shown).toContain("They Match");
    expect(shown).not.toContain("Waiting for your passkey");
  });

  it("waits for the passkey once nothing is left to check", () => {
    const shown = dns(false);
    expect(shown).not.toContain("Check Fingerprints");
    expect(shown).toContain("Waiting for your passkey");
  });
});
