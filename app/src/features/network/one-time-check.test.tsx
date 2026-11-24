import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { OneTimeCheck } from "./one-time-check";

describe("the one-time fingerprint check", () => {
  it("lists each unchecked member with its fingerprint, where to compare it, and asks before anything is signed", () => {
    const html = renderToStaticMarkup(
      <OneTimeCheck
        members={[
          {
            node: "11111111-1111-4111-8111-111111111111",
            name: "server-1",
            fingerprint: "ABCD-EFGH-JKLM-NPQR",
            line: "Check that server-1 shows the same fingerprint: run sudo kry network fingerprint on it.",
          },
          {
            node: "33333333-3333-4333-8333-333333333333",
            name: "laptop-1",
            fingerprint: "STUV-WXYZ-2345-6789",
            line: "Check that laptop-1 shows the same fingerprint: in the tray, Fingerprint.",
          },
        ]}
        onAnswer={() => {}}
      />,
    );
    expect(html).toContain(
      "This browser has not checked these members yet, or their keys changed.",
    );
    for (const text of [
      "server-1",
      "ABCD-EFGH-JKLM-NPQR",
      "run sudo kry network fingerprint on it.",
      "laptop-1",
      "STUV-WXYZ-2345-6789",
      "in the tray, Fingerprint.",
    ]) {
      expect(html).toContain(text);
    }
    expect(html).toMatch(
      /<button[^>]*type="button"[^>]*>They Match<\/button>/u,
    );
    expect(html).not.toContain("changed since");
    const warned = renderToStaticMarkup(
      <OneTimeCheck
        members={[
          {
            node: "22222222-2222-4222-8222-222222222222",
            name: "server-2",
            fingerprint: "ABCD-EFGH-JKLM-NPQR",
            line: "Check that server-2 shows the same fingerprint: run sudo kry network fingerprint on it.",
            warning:
              "server-2's keys changed since this browser last saw them. Check them on server-2 before you go on.",
          },
        ]}
        onAnswer={() => {}}
      />,
    );
    expect(warned).toMatch(
      /<p[^>]*text-destructive[^>]*>server-2&#x27;s keys changed since this browser last saw them\. Check them on server-2 before you go on\.<\/p>/u,
    );
    expect(html).toMatch(/<button[^>]*type="button"[^>]*>Cancel<\/button>/u);
  });
});
