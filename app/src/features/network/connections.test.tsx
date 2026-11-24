import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import { changeNetwork } from "@/lib/approve";
import { namesOf, OPEN_CONNECTIONS_LINE } from "@/lib/rules";
import {
  ALL_LAPTOPS_TO_ALL_SERVERS,
  document,
  L1,
  network,
  S3,
  SERVER_1_TO_SERVER_2,
} from "@/lib/rules-test-utils";

import { deleteRuleChange } from "./change-dialog";
import { Connections } from "./connections";

const none = () => {};

const html = (shown = document()) =>
  renderToStaticMarkup(
    <Connections document={shown} onAdd={none} onEdit={none} onDelete={none} />,
  );

describe("the connections", () => {
  it("the list says each rule in one sentence", () => {
    const shown = html();
    expect(shown).toContain(
      "All Laptops can connect to All Servers on all ports.",
    );
    expect(shown).toContain("server-1 can connect to server-2 on 22/tcp.");
    expect(shown).toContain('aria-label="Actions for rule 1"');
    expect(shown).toContain('aria-label="Actions for rule 2"');
    expect(shown).toContain("Add Rule");
  });

  it("a member with no rule says No rules", () => {
    const shown = html(network([SERVER_1_TO_SERVER_2]));
    expect(shown).toMatch(/Who can reach server-1<\/h3><p[^>]*>No rules<\/p>/u);
    expect(shown).toMatch(/Who can reach server-3<\/h3><p[^>]*>No rules<\/p>/u);
    expect(shown).toMatch(
      /Who can reach server-2<\/h3><ul[^>]*><li[^>]*>.*server-1.*22\/tcp/u,
    );
    expect(shown).not.toMatch(/Who can reach laptop/u);
    expect(html()).not.toContain("No rules");
  });

  it("the open-connections line is shown", () => {
    expect(html()).toContain(OPEN_CONNECTIONS_LINE);
    expect(html(network([]))).toContain(OPEN_CONNECTIONS_LINE);
  });

  it("with no rule at all, it says nothing can connect", () => {
    expect(html(network([]))).toContain("There are no rules yet.");
  });
});

describe("deleting a rule", () => {
  const other = network([ALL_LAPTOPS_TO_ALL_SERVERS, SERVER_1_TO_SERVER_2]);

  it("a Delete whose index now holds another rule signs nothing", async () => {
    const shown = {
      from: { node: L1 },
      to: { node: S3 },
      ports: ["443/tcp" as const],
    };
    const change = deleteRuleChange(1, shown, namesOf(other));
    const sign = {
      openSession: vi.fn(),
      buildCommand: vi.fn(),
      signCommand: vi.fn(),
      signDocument: vi.fn(),
    };
    const postDocument = vi.fn();
    await expect(
      changeNetwork(change.edit, change.change, {
        sign,
        api: {
          current: async () => ({ document: other, hash: "q".repeat(43) }),
          nodes: async () => [],
          postDocument,
        },
      }),
    ).rejects.toThrow("The rules changed; open the list again.");
    expect(sign.openSession).not.toHaveBeenCalled();
    expect(sign.signDocument).not.toHaveBeenCalled();
    expect(postDocument).not.toHaveBeenCalled();
  });

  it("says the rule and that an open connection keeps running", () => {
    const change = deleteRuleChange(1, SERVER_1_TO_SERVER_2, namesOf(other));
    expect(change.body).toContain(
      "server-1 can connect to server-2 on 22/tcp.",
    );
    expect(change.body).toContain(
      "new connections of that kind are refused unless another rule allows them.",
    );
    expect(change.body).toContain(
      "A connection already open keeps running until it closes.",
    );
    expect(change.change).toBe(
      "Delete rule: server-1 can connect to server-2 on 22/tcp.",
    );
    expect(change.destructive).toBe(true);
    expect(change.edit(other).allow).toEqual([ALL_LAPTOPS_TO_ALL_SERVERS]);
  });
});
