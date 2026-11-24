import { networkDocumentSchema, type NetworkRule } from "@krynodes/protocol";
import { describe, expect, it } from "vitest";

import type { changeNetwork } from "./approve";
import { nextOf, withoutMember } from "./network";
import {
  applyLines,
  blankForm,
  canSave,
  changeFrom,
  describeRule,
  dropRule,
  failuresOf,
  formOf,
  fromOptions,
  namesOf,
  OPEN_CONNECTIONS_LINE,
  openWarning,
  parsePorts,
  portsError,
  type PortRange,
  reachOf,
  ruleChange,
  ruleDeleteText,
  ruleOf,
  sameRule,
  saveRule,
  serversOf,
  targetsOf,
  toOptions,
  withoutRule,
  withRule,
} from "./rules";
import {
  ALL_LAPTOPS_TO_ALL_SERVERS,
  document,
  L1,
  L2,
  network,
  S1,
  S2,
  S3,
  SERVER_1_TO_SERVER_2,
} from "./rules-test-utils";

const ruleSchema = networkDocumentSchema.shape.allow.element;

const names = namesOf(document());

describe("typing ports", () => {
  it("80,443/tcp becomes two entries", () => {
    expect(parsePorts("80,443/tcp")).toEqual(["80/tcp", "443/tcp"]);
    expect(parsePorts("22/tcp, 80,443/tcp, 8000-8100/tcp, 53/udp")).toEqual([
      "22/tcp",
      "80/tcp",
      "443/tcp",
      "8000-8100/tcp",
      "53/udp",
    ]);
    expect(parsePorts("8000-8100,9000/udp")).toEqual([
      "8000-8100/udp",
      "9000/udp",
    ]);
  });

  it("all means every port", () => {
    expect(parsePorts(" All ")).toBe("all");
  });

  it("0/tcp and 90-80/tcp are refused with the bad part named", () => {
    expect(parsePorts("0/tcp")).toEqual({
      error: expect.stringMatching(/^0\/tcp is not a valid port\./u),
    });
    expect(parsePorts("22/tcp, 90-80/tcp")).toEqual({
      error: expect.stringMatching(/^90-80\/tcp is not a valid port\./u),
    });
    expect(parsePorts("080/tcp")).toEqual({
      error: expect.stringMatching(/^080\/tcp is not a valid port\./u),
    });
    expect(parsePorts("80,65536/udp")).toEqual({
      error: expect.stringMatching(/^65536\/udp is not a valid port\./u),
    });
    expect(parsePorts("5000-5000/tcp")).toEqual({
      error: expect.stringMatching(/^5000-5000\/tcp is not a valid port\./u),
    });
  });

  it("a port without tcp or udp, or not a port, is refused with the part named", () => {
    expect(parsePorts("22/tcp, 80")).toEqual({
      error: "80 needs /tcp or /udp.",
    });
    expect(parsePorts("80,443")).toEqual({ error: "80 needs /tcp or /udp." });
    expect(parsePorts("ssh/tcp")).toEqual({
      error: expect.stringMatching(/^ssh\/tcp is not a port\./u),
    });
    expect(parsePorts("80/icmp")).toEqual({
      error: expect.stringMatching(/^80\/icmp is not a port\./u),
    });
    expect(parsePorts("22/tcp,")).toEqual({ error: "Remove the extra comma." });
    expect(parsePorts("  ")).toEqual({
      error: "Enter at least one port, like 22/tcp.",
    });
  });

  it("a port that overlaps another one names both", () => {
    expect(parsePorts("8000-8100/tcp, 8050/tcp")).toEqual({
      error: "8050/tcp overlaps 8000-8100/tcp.",
    });
    expect(parsePorts("22/tcp,22/tcp")).toEqual({
      error: "22/tcp overlaps 22/tcp.",
    });
    expect(parsePorts("53/tcp, 53/udp")).toEqual(["53/tcp", "53/udp"]);
  });

  it("a rule takes only so many ports", () => {
    const nine = Array.from({ length: 9 }, (_, i) => `${i + 1}/tcp`).join(",");
    expect(parsePorts(nine)).toEqual({
      error: "That is too many ports for one rule. Use ranges to cover more.",
    });
    expect(parsePorts(nine.replace(",9/tcp", ""))).toHaveLength(8);
  });

  it("a parsed result is accepted by the protocol schema", () => {
    for (const text of [
      "22/tcp",
      "80,443/tcp",
      "22/tcp, 80,443/tcp, 8000-8100/tcp, 53/udp",
      "all",
    ]) {
      const ports = parsePorts(text);
      expect(ports).not.toHaveProperty("error");
      expect(
        ruleSchema.safeParse({ ...SERVER_1_TO_SERVER_2, ports }).success,
      ).toBe(true);
    }
  });
});

describe("saying a rule", () => {
  it("says a rule in one sentence", () => {
    expect(describeRule(ALL_LAPTOPS_TO_ALL_SERVERS, names)).toBe(
      "All Laptops can connect to All Servers on all ports.",
    );
    expect(
      describeRule(
        { from: { node: L1 }, to: { node: S2 }, ports: ["22/tcp"] },
        names,
      ),
    ).toBe("laptop-1 can connect to server-2 on 22/tcp.");
    expect(
      describeRule(
        {
          from: { group: "servers" },
          to: { node: S3 },
          ports: ["80/tcp", "8000-8100/tcp"],
        },
        names,
      ),
    ).toBe("All Servers can connect to server-3 on 80/tcp, 8000-8100/tcp.");
  });

  it("warns when a server may open any connection", () => {
    const base = document();
    expect(
      openWarning({ from: { node: S1 }, to: { node: S2 }, ports: "all" }, base),
    ).toBe("server-1 can open any connection to server-2.");
    expect(
      openWarning(
        { from: { group: "servers" }, to: { node: S2 }, ports: "all" },
        base,
      ),
    ).toBe("All Servers can open any connection to server-2.");
    expect(
      openWarning(
        { from: { node: S1 }, to: { node: S2 }, ports: ["22/tcp"] },
        base,
      ),
    ).toBeNull();
    expect(
      openWarning({ from: { node: L1 }, to: { node: S2 }, ports: "all" }, base),
    ).toBeNull();
    expect(openWarning(ALL_LAPTOPS_TO_ALL_SERVERS, base)).toBeNull();
  });

  it("says that open connections keep running", () => {
    expect(OPEN_CONNECTIONS_LINE).toBe(
      "Rules apply to new connections. A connection already open keeps running until it closes.",
    );
  });
});

describe("who can reach a server", () => {
  it("who can reach expands groups but never the server itself", () => {
    const base = network([
      ALL_LAPTOPS_TO_ALL_SERVERS,
      SERVER_1_TO_SERVER_2,
      { from: { group: "servers" }, to: { node: S2 }, ports: ["53/udp"] },
      { from: { node: L1 }, to: { node: S2 }, ports: ["22/tcp"] },
    ]);
    expect(reachOf(S2, base)).toEqual([
      { from: "laptop-1", ports: "All Ports" },
      { from: "laptop-2", ports: "All Ports" },
      { from: "server-1", ports: "22/tcp, 53/udp" },
      { from: "server-3", ports: "53/udp" },
    ]);
    expect(reachOf(S2, base).map((one) => one.from)).not.toContain("server-2");
  });

  it("a server nobody was let in on is reached by the default rule only", () => {
    expect(reachOf(S3, document())).toEqual([
      { from: "laptop-1", ports: "All Ports" },
      { from: "laptop-2", ports: "All Ports" },
    ]);
    expect(reachOf(S3, network([]))).toEqual([]);
  });

  it("a laptop or a stranger is reached by no one", () => {
    expect(reachOf(L1, document())).toEqual([]);
    expect(reachOf("nobody", document())).toEqual([]);
  });
});

describe("changing the rules", () => {
  it("adds a rule to the next document and leaves the given one alone", () => {
    const base = document();
    const rule: NetworkRule = {
      from: { node: L1 },
      to: { node: S3 },
      ports: ["443/tcp"],
    };
    const next = withRule(base, rule);
    expect(next.allow).toEqual([...base.allow, rule]);
    expect(base.allow).toHaveLength(2);
    expect(networkDocumentSchema.safeParse(next).success).toBe(true);
    expect({ ...next, allow: base.allow }).toEqual(base);
  });

  it("refuses a rule the protocol would not accept", () => {
    const bad: PortRange[] = ["0/tcp"];
    expect(() =>
      withRule(document(), {
        from: { node: S1 },
        to: { node: S2 },
        ports: bad,
      }),
    ).toThrow("That rule is not valid.");
  });

  it("a laptop is never a target", () => {
    const base = document();
    expect(() =>
      withRule(base, { from: { node: S1 }, to: { node: L1 }, ports: "all" }),
    ).toThrow(
      "laptop-1 is a laptop. A rule can only let someone connect to a server.",
    );
  });

  it("refuses a rule a machine cannot follow, in plain text", () => {
    const base = document();
    expect(() =>
      withRule(base, { from: { node: S1 }, to: { node: S1 }, ports: "all" }),
    ).toThrow("server-1 cannot connect to itself.");
    expect(() =>
      withRule(base, {
        from: { node: S1 },
        to: { node: "66666666-6666-4666-8666-666666666666" },
        ports: "all",
      }),
    ).toThrow("That machine is not in the private network.");
    expect(() =>
      withRule(base, {
        from: { node: "66666666-6666-4666-8666-666666666666" },
        to: { node: S1 },
        ports: "all",
      }),
    ).toThrow("That machine is not in the private network.");
  });

  it("refuses a rule that is already there, whatever the order of its ports", () => {
    const base = network([
      { from: { node: S1 }, to: { node: S2 }, ports: ["80/tcp", "22/tcp"] },
    ]);
    expect(() =>
      withRule(base, {
        from: { node: S1 },
        to: { node: S2 },
        ports: ["22/tcp", "80/tcp"],
      }),
    ).toThrow("That rule is already in the private network.");
    expect(() => withRule(document(), ALL_LAPTOPS_TO_ALL_SERVERS)).toThrow(
      "That rule is already in the private network.",
    );
  });

  it("says so when the network cannot hold another rule", () => {
    let base = network([]);
    const add = () => {
      base = withRule(base, {
        from: { group: "laptops" },
        to: { group: "servers" },
        ports: [`${base.allow.length + 1}/tcp`],
      });
    };
    expect(() => {
      for (let i = 0; i < 100; i++) add();
    }).toThrow(
      "The private network cannot hold another rule. Delete one first.",
    );
    expect(base.allow.length).toBeGreaterThan(8);
  });

  it("deletes a rule by its place in the list", () => {
    const base = document();
    const next = withoutRule(base, 0);
    expect(next.allow).toEqual([SERVER_1_TO_SERVER_2]);
    expect(base.allow).toHaveLength(2);
    expect(withoutRule(base, 1).allow).toEqual([ALL_LAPTOPS_TO_ALL_SERVERS]);
    expect(withoutRule(withoutRule(base, 1), 0).allow).toEqual([]);
  });

  it("refuses to delete a rule that is no longer there", () => {
    for (const index of [2, -1, 0.5, Number.NaN]) {
      expect(() => withoutRule(document(), index)).toThrow(
        "That rule is no longer in the private network.",
      );
    }
  });

  it("removing a member removes its rules", () => {
    const base = network([
      ALL_LAPTOPS_TO_ALL_SERVERS,
      SERVER_1_TO_SERVER_2,
      { from: { node: L1 }, to: { node: S3 }, ports: ["443/tcp"] },
      { from: { node: S3 }, to: { node: S1 }, ports: ["22/tcp"] },
    ]);
    expect(withoutMember(base, S1).allow).toEqual([
      ALL_LAPTOPS_TO_ALL_SERVERS,
      { from: { node: L1 }, to: { node: S3 }, ports: ["443/tcp"] },
    ]);
    expect(withoutMember(base, L1).allow).toEqual([
      ALL_LAPTOPS_TO_ALL_SERVERS,
      SERVER_1_TO_SERVER_2,
      { from: { node: S3 }, to: { node: S1 }, ports: ["22/tcp"] },
    ]);
  });

  it("fits changeNetwork as the edit of a change", () => {
    const base = { document: document(), hash: "q".repeat(43) };
    const rule: NetworkRule = {
      from: { node: L2 },
      to: { node: S1 },
      ports: ["22/tcp"],
    };
    const edit: Parameters<typeof changeNetwork>[0] = (next) =>
      withRule(next, rule);
    const next = edit(nextOf(base));
    expect(next).toMatchObject({ version: 5, parent: base.hash });
    expect(next.allow).toEqual([...base.document.allow, rule]);
    const after = withoutRule(nextOf(base), 1);
    expect(after).toMatchObject({ version: 5, parent: base.hash });
    expect(after.allow).toEqual([ALL_LAPTOPS_TO_ALL_SERVERS]);
  });
});

describe("the rule form", () => {
  it("offers the groups and every member as From", () => {
    expect(fromOptions(document())).toEqual([
      { value: "laptops", label: "All Laptops" },
      { value: "servers", label: "All Servers" },
      { value: S1, label: "server-1" },
      { value: S2, label: "server-2" },
      { value: S3, label: "server-3" },
      { value: L1, label: "laptop-1" },
      { value: L2, label: "laptop-2" },
    ]);
  });

  it("offers All Servers and the servers other than From as To, never a laptop", () => {
    expect(toOptions(document(), S1)).toEqual([
      { value: "servers", label: "All Servers" },
      { value: S2, label: "server-2" },
      { value: S3, label: "server-3" },
    ]);
    expect(toOptions(document(), L1).map((one) => one.value)).toEqual([
      "servers",
      S1,
      S2,
      S3,
    ]);
    for (const from of ["laptops", "servers", S1, L1, L2]) {
      const offered = toOptions(document(), from).map((one) => one.value);
      expect(offered).not.toContain(L1);
      expect(offered).not.toContain(L2);
      expect(offered).not.toContain("laptops");
    }
    expect(toOptions(document(), S2).map((one) => one.value)).not.toContain(S2);
  });

  it("lists the servers of a document", () => {
    expect(serversOf(document()).map((one) => one.name)).toEqual([
      "server-1",
      "server-2",
      "server-3",
    ]);
  });

  it("starts from a server, All Servers and no ports", () => {
    expect(blankForm(document())).toEqual({
      from: S1,
      to: "servers",
      ports: "specific",
      text: "",
    });
    expect(blankForm(network([])).to).toBe("servers");
  });

  it("changing From moves To off the same member", () => {
    const form = { from: S1, to: S2, ports: "all" as const, text: "" };
    expect(changeFrom(document(), form, S2)).toEqual({
      ...form,
      from: S2,
      to: "servers",
    });
    expect(changeFrom(document(), form, L1)).toEqual({ ...form, from: L1 });
    expect(changeFrom(document(), form, "servers")).toEqual({
      ...form,
      from: "servers",
    });
  });

  it("builds the rule of a form", () => {
    expect(
      ruleOf({
        from: S1,
        to: S2,
        ports: "specific",
        text: "22/tcp, 80,443/tcp",
      }),
    ).toEqual({
      rule: {
        from: { node: S1 },
        to: { node: S2 },
        ports: ["22/tcp", "80/tcp", "443/tcp"],
      },
    });
    expect(
      ruleOf({ from: "laptops", to: "servers", ports: "all", text: "ignored" }),
    ).toEqual({ rule: ALL_LAPTOPS_TO_ALL_SERVERS });
    expect(
      ruleOf({ from: "servers", to: S3, ports: "specific", text: "all" }),
    ).toEqual({
      rule: { from: { group: "servers" }, to: { node: S3 }, ports: "all" },
    });
  });

  it("says what is wrong with a form in plain text", () => {
    expect(
      ruleOf({ from: S1, to: S2, ports: "specific", text: "0/tcp" }),
    ).toEqual({
      error: expect.stringMatching(/^0\/tcp is not a valid port\./u),
    });
    expect(ruleOf({ from: S1, to: S2, ports: "specific", text: "" })).toEqual({
      error: "Enter at least one port, like 22/tcp.",
    });
    expect(ruleOf({ from: "", to: S2, ports: "all", text: "" })).toEqual({
      error: "Choose who can connect.",
    });
    expect(ruleOf({ from: S1, to: "", ports: "all", text: "" })).toEqual({
      error: "Choose the server they connect to.",
    });
  });

  it("names the port error of a form, and only that one", () => {
    expect(
      portsError({ from: "", to: "", ports: "specific", text: "90-80/tcp" }),
    ).toMatch(/^90-80\/tcp is not a valid port\./u);
    expect(
      portsError({ from: S1, to: S2, ports: "all", text: "0/tcp" }),
    ).toBeNull();
    expect(
      portsError({ from: S1, to: S2, ports: "specific", text: "22/tcp" }),
    ).toBeNull();
  });

  it("fills the form again from a rule, ports as text", () => {
    for (const rule of [
      ALL_LAPTOPS_TO_ALL_SERVERS,
      SERVER_1_TO_SERVER_2,
      {
        from: { group: "servers" as const },
        to: { node: S3 },
        ports: ["80/tcp", "8000-8100/udp"],
      },
    ]) {
      expect(ruleOf(formOf(rule))).toEqual({ rule });
    }
    expect(formOf(SERVER_1_TO_SERVER_2)).toEqual({
      from: S1,
      to: S2,
      ports: "specific",
      text: "22/tcp",
    });
    expect(formOf(ALL_LAPTOPS_TO_ALL_SERVERS)).toMatchObject({
      from: "laptops",
      to: "servers",
      ports: "all",
    });
  });
});

describe("editing and deleting the rule that was shown", () => {
  const OTHER: NetworkRule = {
    from: { node: L1 },
    to: { node: S3 },
    ports: ["443/tcp"],
  };

  it("deletes the rule at that place when it is still the one shown", () => {
    const next = dropRule(document(), 1, SERVER_1_TO_SERVER_2);
    expect(next.allow).toEqual([ALL_LAPTOPS_TO_ALL_SERVERS]);
  });

  it("stops in plain text when that place holds another rule now", () => {
    expect(() =>
      dropRule(network([OTHER, SERVER_1_TO_SERVER_2]), 0, SERVER_1_TO_SERVER_2),
    ).toThrow("The rules changed; open the list again.");
    expect(() => dropRule(network([OTHER]), 1, SERVER_1_TO_SERVER_2)).toThrow(
      "The rules changed; open the list again.",
    );
  });

  it("recognises the rule whatever the order of its ports", () => {
    const shown: NetworkRule = {
      from: { node: S1 },
      to: { node: S2 },
      ports: ["80/tcp", "22/tcp"],
    };
    const now: NetworkRule = { ...shown, ports: ["22/tcp", "80/tcp"] };
    expect(dropRule(network([now]), 0, shown).allow).toEqual([]);
  });

  it("adds a new rule as a rule", () => {
    expect(saveRule(document(), OTHER, null).allow).toEqual([
      ...document().allow,
      OTHER,
    ]);
  });

  it("edits a rule by removing the old and adding the new in one document", () => {
    const next = saveRule(document(), OTHER, {
      index: 1,
      rule: SERVER_1_TO_SERVER_2,
    });
    expect(next.allow).toEqual([ALL_LAPTOPS_TO_ALL_SERVERS, OTHER]);
    const same = saveRule(document(), SERVER_1_TO_SERVER_2, {
      index: 1,
      rule: SERVER_1_TO_SERVER_2,
    });
    expect(same.allow).toEqual(document().allow);
  });

  it("refuses an edit whose rule changed meanwhile, and one that repeats another rule", () => {
    expect(() =>
      saveRule(network([OTHER, SERVER_1_TO_SERVER_2]), OTHER, {
        index: 0,
        rule: SERVER_1_TO_SERVER_2,
      }),
    ).toThrow("The rules changed; open the list again.");
    expect(() =>
      saveRule(document(), ALL_LAPTOPS_TO_ALL_SERVERS, {
        index: 1,
        rule: SERVER_1_TO_SERVER_2,
      }),
    ).toThrow("That rule is already in the private network.");
  });

  it("plugs into changeNetwork like withRule does", () => {
    const base = { document: document(), hash: "q".repeat(43) };
    const edit: Parameters<typeof changeNetwork>[0] = (next) =>
      saveRule(next, OTHER, { index: 1, rule: SERVER_1_TO_SERVER_2 });
    expect(edit(nextOf(base))).toMatchObject({ version: 5, parent: base.hash });
  });
});

describe("where a rule applies", () => {
  it("a rule applies on the servers it lets someone reach", () => {
    expect(targetsOf(document(), [SERVER_1_TO_SERVER_2])).toEqual([S2]);
    expect(targetsOf(document(), [ALL_LAPTOPS_TO_ALL_SERVERS])).toEqual([
      S1,
      S2,
      S3,
    ]);
    expect(
      targetsOf(document(), [
        SERVER_1_TO_SERVER_2,
        { from: { node: L1 }, to: { node: S2 }, ports: "all" },
        { from: { node: L1 }, to: { node: S3 }, ports: "all" },
      ]),
    ).toEqual([S2, S3]);
  });

  it("says Applying on a server until it has the version", () => {
    const members = (applied: number, failure: string | null = null) => [
      { node: S1, name: "server-1", applied: 5, failure: null },
      { node: S2, name: "server-2", applied, failure },
      { node: L1, name: "laptop-1", applied: 1, failure: null },
    ];
    expect(applyLines({ members: members(4) }, [S2], 5)).toEqual([
      "Applying on server-2…",
    ]);
    expect(applyLines({ members: members(5) }, [S2], 5)).toEqual([
      "Applied on server-2.",
    ]);
    expect(
      applyLines(
        { members: members(4, "The tunnel did not come up.") },
        [S1, S2],
        5,
      ),
    ).toEqual([
      "Applied on server-1.",
      "server-2: The tunnel did not come up.",
    ]);
    expect(applyLines({ members: members(5) }, ["nobody"], 5)).toEqual([]);
  });
});

describe("a failure belongs to the send that shows it", () => {
  const members = (applied: number, failure: string | null) => [
    { node: S2, name: "server-2", applied, failure },
  ];

  it("a server that has the version is applied, whatever failure it still carries", () => {
    expect(
      applyLines(
        { members: members(5, "The tunnel did not come up.") },
        [S2],
        5,
      ),
    ).toEqual(["Applied on server-2."]);
  });

  it("remembers the failures every server carries", () => {
    expect(
      failuresOf({
        members: [
          { node: S1, failure: null },
          { node: S2, failure: "The tunnel did not come up." },
        ],
      }),
    ).toEqual({ [S1]: null, [S2]: "The tunnel did not come up." });
  });

  it("a failure that was there before the send is not the send's own", () => {
    const before = { [S2]: "The tunnel did not come up." };
    expect(
      applyLines(
        { members: members(4, "The tunnel did not come up.") },
        [S2],
        5,
        before,
      ),
    ).toEqual(["Applying on server-2…"]);
    expect(
      applyLines(
        { members: members(4, "The firewall refused the change.") },
        [S2],
        5,
        before,
      ),
    ).toEqual(["server-2: The firewall refused the change."]);
    expect(applyLines({ members: members(4, null) }, [S2], 5, before)).toEqual([
      "Applying on server-2…",
    ]);
  });
});

describe("saving a rule", () => {
  it("an edit that changes nothing cannot be saved", () => {
    const edit = { index: 1, rule: SERVER_1_TO_SERVER_2 };
    const form = formOf(SERVER_1_TO_SERVER_2);
    expect(canSave(form, edit)).toBe(false);
    expect(canSave({ ...form, text: "22/tcp, 80/tcp" }, edit)).toBe(true);
    expect(canSave({ ...form, to: S3 }, edit)).toBe(true);
    expect(canSave({ ...form, ports: "all" }, edit)).toBe(true);
  });

  it("an edit whose ports only change order cannot be saved either", () => {
    const rule: NetworkRule = {
      from: { node: S1 },
      to: { node: S2 },
      ports: ["80/tcp", "22/tcp"],
    };
    expect(
      canSave({ ...formOf(rule), text: "22/tcp, 80/tcp" }, { index: 0, rule }),
    ).toBe(false);
  });

  it("an added rule can be saved once it is valid", () => {
    expect(canSave(formOf(SERVER_1_TO_SERVER_2), null)).toBe(true);
    expect(canSave(blankForm(document()), null)).toBe(false);
    expect(canSave({ ...blankForm(document()), text: "0/tcp" }, null)).toBe(
      false,
    );
  });

  it("says whether two rules are the same", () => {
    expect(sameRule(SERVER_1_TO_SERVER_2, { ...SERVER_1_TO_SERVER_2 })).toBe(
      true,
    );
    expect(sameRule(SERVER_1_TO_SERVER_2, ALL_LAPTOPS_TO_ALL_SERVERS)).toBe(
      false,
    );
  });
});

describe("what a rule change says in History", () => {
  const wide = Array.from(
    { length: 8 },
    (_, i) => `${1000 + i}-${2000 + i}/tcp`,
  );
  const names = new Map([
    [S1, "a".repeat(100)],
    [S2, "b".repeat(100)],
  ]);
  const rule: NetworkRule = {
    from: { node: S1 },
    to: { node: S2 },
    ports: wide,
  };

  it("an added rule is said in a sentence with no detail", () => {
    expect(ruleChange(SERVER_1_TO_SERVER_2, null, namesOf(document()))).toEqual(
      {
        change: "Add rule: server-1 can connect to server-2 on 22/tcp.",
        detail: null,
      },
    );
  });

  it("an edit says the new rule and carries the old one as its detail", () => {
    expect(
      ruleChange(
        { ...SERVER_1_TO_SERVER_2, ports: ["80/tcp"] },
        { index: 1, rule: SERVER_1_TO_SERVER_2 },
        namesOf(document()),
      ),
    ).toEqual({
      change: "Change rule: server-1 can connect to server-2 on 80/tcp.",
      detail: "Was: server-1 can connect to server-2 on 22/tcp.",
    });
  });

  it("a long sentence is cut to the 300 characters the Worker takes", () => {
    expect(describeRule(rule, names).length).toBeGreaterThan(300);
    for (const text of [
      ruleChange(rule, null, names).change,
      ruleChange(rule, { index: 0, rule }, names).change,
      ruleDeleteText(rule, names),
    ]) {
      expect(text).toHaveLength(300);
      expect(text.endsWith("…")).toBe(true);
    }
    expect(ruleDeleteText(SERVER_1_TO_SERVER_2, namesOf(document()))).toBe(
      "Delete rule: server-1 can connect to server-2 on 22/tcp.",
    );
  });
});
