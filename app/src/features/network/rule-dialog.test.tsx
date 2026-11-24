import { isValidElement, type ReactElement, type ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { type RuleForm } from "@/lib/rules";
import { document, L1, L2, S1, S2, S3 } from "@/lib/rules-test-utils";

import { RuleFields } from "./rule-dialog";

const none = () => {};

const props = (
  form: RuleForm,
  extra: { touched?: boolean; disabled?: boolean } = {},
) => ({
  document: document(),
  form,
  touched: true,
  disabled: false,
  onTouch: none,
  onChange: none,
  ...extra,
});

const html = (
  form: RuleForm,
  extra: { touched?: boolean; disabled?: boolean } = {},
) => renderToStaticMarkup(<RuleFields {...props(form, extra)} />);

const specific = (from: string, to: string, text: string): RuleForm => ({
  from,
  to,
  ports: "specific",
  text,
});

const all = (from: string, to: string): RuleForm => ({
  from,
  to,
  ports: "all",
  text: "",
});

function find(
  node: ReactNode,
  id: string,
): ReactElement<{
  options: { value: string; label: string }[];
}> | null {
  if (Array.isArray(node)) {
    for (const child of node) {
      const found = find(child, id);
      if (found) return found;
    }
    return null;
  }
  if (!isValidElement<{ id?: string; children?: ReactNode }>(node)) return null;
  if (node.props.id === id) return node as never;
  return find(node.props.children, id);
}

const offered = (form: RuleForm, id: string) =>
  find(RuleFields(props(form)), id)!.props.options.map((one) => one.value);

describe("the rule dialog", () => {
  it("the From member is not offered as To", () => {
    expect(offered(all(S1, S2), "rule-from")).toContain(S1);
    expect(offered(all(S1, S2), "rule-to")).not.toContain(S1);
    expect(offered(all(S2, S3), "rule-to")).not.toContain(S2);
    expect(offered(all(S2, S3), "rule-to")).toContain(S1);
  });

  it("a laptop is never offered as To", () => {
    for (const from of [L1, L2, "laptops", "servers", S1]) {
      const to = offered(all(from, S2), "rule-to");
      expect(to).toEqual(expect.arrayContaining(["servers"]));
      expect(to).not.toContain(L1);
      expect(to).not.toContain(L2);
    }
  });

  it("All Ports from a server shows the warning", () => {
    expect(html(all(S1, S2))).toContain(
      "server-1 can open any connection to server-2.",
    );
    expect(html(all("servers", S2))).toContain(
      "All Servers can open any connection to server-2.",
    );
    expect(html(all(L1, S2))).not.toContain("can open any connection");
    expect(html(specific(S1, S2, "22/tcp"))).not.toContain(
      "can open any connection",
    );
  });

  it("says the rule as a sentence before anything is saved", () => {
    expect(html(specific(S1, S2, "22/tcp, 80,443/tcp"))).toContain(
      "server-1 can connect to server-2 on 22/tcp, 80/tcp, 443/tcp.",
    );
    expect(html(all("laptops", "servers"))).toContain(
      "All Laptops can connect to All Servers on all ports.",
    );
  });

  it("shows the port error under the field and no sentence", () => {
    const shown = html(specific(S1, S2, "0/tcp"));
    expect(shown).toContain("0/tcp is not a valid port.");
    expect(shown).toMatch(/id="rule-ports"[^>]*aria-invalid="true"/u);
    expect(shown).not.toContain("can connect to");
  });

  it("shows no port error before the field was touched", () => {
    const quiet = html(specific(S1, S2, ""), { touched: false });
    expect(quiet).not.toContain("Enter at least one port");
    expect(quiet).toContain("Each port needs /tcp or /udp.");
    expect(quiet).toMatch(/id="rule-ports"[^>]*aria-invalid="false"/u);
    const touched = html(specific(S1, S2, ""), { touched: true });
    expect(touched).toContain("Enter at least one port, like 22/tcp.");
    expect(touched).toMatch(/id="rule-ports"[^>]*aria-invalid="true"/u);
  });

  it("locks From, To, Ports and the port list while a change is signed", () => {
    const tag = (shown: string, id: string) =>
      new RegExp(
        String.raw`<(?:button|input)\b[^>]*\bid="${id}"[^>]*>`,
        "u",
      ).exec(shown)![0];
    const idle = html(specific(S1, S2, "22/tcp"));
    const locked = html(specific(S1, S2, "22/tcp"), { disabled: true });
    for (const id of ["rule-from", "rule-to", "rule-port-mode", "rule-ports"]) {
      expect(tag(idle, id)).not.toContain('disabled=""');
      expect(tag(locked, id)).toContain('disabled=""');
    }
  });

  it("takes the port field only for Specific Ports", () => {
    expect(html(specific(S1, S2, ""))).toContain('id="rule-ports"');
    expect(html(all(S1, S2))).not.toContain('id="rule-ports"');
  });
});
