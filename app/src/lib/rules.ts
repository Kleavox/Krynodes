import {
  networkDocumentSchema,
  type NetworkDocument,
  type NetworkRule,
} from "@krynodes/protocol";

import type { NetworkView } from "../types";

export type PortRange = Exclude<NetworkRule["ports"], "all">[number];

type Side = NetworkRule["from"] | NetworkRule["to"];

export const OPEN_CONNECTIONS_LINE =
  "Rules apply to new connections. A connection already open keeps running until it closes.";

const ruleSchema = networkDocumentSchema.shape.allow.element;

const PORT_TOKEN = /^(\d+(?:-\d+)?)(?:\/(tcp|udp))?$/u;

const allowed = (ports: PortRange[]) =>
  ruleSchema.shape.ports.safeParse(ports).success;

export function parsePorts(
  text: string,
): PortRange[] | "all" | { error: string } {
  const typed = text.trim();
  if (typed.toLowerCase() === "all") return "all";
  if (typed === "") return { error: "Enter at least one port, like 22/tcp." };
  const ports: PortRange[] = [];
  let waiting: string[] = [];
  for (const part of typed.split(",").map((one) => one.trim())) {
    if (part === "") return { error: "Remove the extra comma." };
    const found = PORT_TOKEN.exec(part);
    if (!found) {
      return {
        error: `${part} is not a port. Write ports like 22/tcp, 80,443/tcp or 8000-8100/udp.`,
      };
    }
    waiting.push(found[1]!);
    if (found[2] === undefined) continue;
    for (const one of waiting) {
      const entry = `${one}/${found[2]}`;
      if (!allowed([entry])) {
        return {
          error: `${entry} is not a valid port. Ports run from 1 to 65535 without leading zeros, and a range goes from low to high.`,
        };
      }
      ports.push(entry);
    }
    waiting = [];
  }
  if (waiting.length > 0) return { error: `${waiting[0]} needs /tcp or /udp.` };
  for (const [index, entry] of ports.entries()) {
    const clash = ports
      .slice(0, index)
      .find((earlier) => !allowed([earlier, entry]));
    if (clash !== undefined) return { error: `${entry} overlaps ${clash}.` };
  }
  return allowed(ports)
    ? ports
    : {
        error: "That is too many ports for one rule. Use ranges to cover more.",
      };
}

export const namesOf = (document: NetworkDocument) =>
  new Map(document.members.map((one) => [one.node, one.name]));

const sideName = (side: Side, names: ReadonlyMap<string, string>) =>
  "node" in side
    ? (names.get(side.node) ?? "Unknown machine")
    : side.group === "laptops"
      ? "All Laptops"
      : "All Servers";

export const describeRule = (
  rule: NetworkRule,
  names: ReadonlyMap<string, string>,
) =>
  `${sideName(rule.from, names)} can connect to ${sideName(rule.to, names)} on ${
    rule.ports === "all" ? "all ports" : rule.ports.join(", ")
  }.`;

export function openWarning(
  rule: NetworkRule,
  document: NetworkDocument,
): string | null {
  const { from } = rule;
  const server =
    "group" in from
      ? from.group === "servers"
      : document.members.some(
          (one) => one.node === from.node && one.kind !== "laptop",
        );
  if (rule.ports !== "all" || !server) return null;
  const names = namesOf(document);
  return `${sideName(from, names)} can open any connection to ${sideName(rule.to, names)}.`;
}

const merged = (
  had: "all" | PortRange[] | undefined,
  ports: NetworkRule["ports"],
) =>
  had === "all" || ports === "all"
    ? ("all" as const)
    : [...new Set([...(had ?? []), ...ports])];

export function reachOf(
  server: string,
  document: NetworkDocument,
): { from: string; ports: string }[] {
  const target = document.members.find((one) => one.node === server);
  if (!target || target.kind === "laptop") return [];
  const reached = new Map<string, "all" | PortRange[]>();
  for (const { from, to, ports } of document.allow) {
    if ("node" in to && to.node !== server) continue;
    for (const one of document.members) {
      const fits =
        "node" in from
          ? one.node === from.node
          : (one.kind === "laptop") === (from.group === "laptops");
      if (fits && one.node !== server) {
        reached.set(one.node, merged(reached.get(one.node), ports));
      }
    }
  }
  const names = namesOf(document);
  return [...reached].map(([node, ports]) => ({
    from: names.get(node)!,
    ports: ports === "all" ? "All Ports" : ports.join(", "),
  }));
}

const keyOf = (rule: NetworkRule) =>
  JSON.stringify([
    rule.from,
    rule.to,
    rule.ports === "all" ? "all" : [...rule.ports].sort(),
  ]);

export const sameRule = (a: NetworkRule, b: NetworkRule) =>
  keyOf(a) === keyOf(b);

const unknownMachine = () =>
  new Error("That machine is not in the private network.");

export function withRule(
  document: NetworkDocument,
  rule: NetworkRule,
): NetworkDocument {
  if (!ruleSchema.safeParse(rule).success) {
    throw new Error("That rule is not valid.");
  }
  const find = (side: Side) =>
    "node" in side
      ? document.members.find((one) => one.node === side.node)
      : undefined;
  const source = find(rule.from);
  const target = find(rule.to);
  if (("node" in rule.from && !source) || ("node" in rule.to && !target)) {
    throw unknownMachine();
  }
  if (target?.kind === "laptop") {
    throw new Error(
      `${target.name} is a laptop. A rule can only let someone connect to a server.`,
    );
  }
  if (source && source === target) {
    throw new Error(`${source.name} cannot connect to itself.`);
  }
  if (document.allow.some((one) => keyOf(one) === keyOf(rule))) {
    throw new Error("That rule is already in the private network.");
  }
  const next = structuredClone(document);
  next.allow.push(rule);
  const checked = networkDocumentSchema.safeParse(next);
  if (!checked.success) {
    throw new Error(
      "The private network cannot hold another rule. Delete one first.",
    );
  }
  return checked.data;
}

export function withoutRule(
  document: NetworkDocument,
  index: number,
): NetworkDocument {
  if (document.allow[index] === undefined) {
    throw new Error("That rule is no longer in the private network.");
  }
  const next = structuredClone(document);
  next.allow.splice(index, 1);
  return networkDocumentSchema.parse(next);
}

export interface RuleOption {
  value: string;
  label: string;
}

export interface RuleForm {
  from: string;
  to: string;
  ports: "all" | "specific";
  text: string;
}

export const serversOf = (document: NetworkDocument) =>
  document.members.filter((one) => one.kind !== "laptop");

export const fromOptions = (document: NetworkDocument): RuleOption[] => [
  { value: "laptops", label: "All Laptops" },
  { value: "servers", label: "All Servers" },
  ...document.members.map((one) => ({ value: one.node, label: one.name })),
];

export const toOptions = (
  document: NetworkDocument,
  from: string,
): RuleOption[] => [
  { value: "servers", label: "All Servers" },
  ...serversOf(document)
    .filter((one) => one.node !== from)
    .map((one) => ({ value: one.node, label: one.name })),
];

export const blankForm = (document: NetworkDocument): RuleForm => {
  const from = serversOf(document)[0]?.node ?? "servers";
  return {
    from,
    to: toOptions(document, from)[0]!.value,
    ports: "specific",
    text: "",
  };
};

export const changeFrom = (
  document: NetworkDocument,
  form: RuleForm,
  from: string,
): RuleForm => {
  const offered = toOptions(document, from);
  return {
    ...form,
    from,
    to: offered.some((one) => one.value === form.to)
      ? form.to
      : offered[0]!.value,
  };
};

const valueOf = (side: Side) => ("node" in side ? side.node : side.group);

export const formOf = (rule: NetworkRule): RuleForm => ({
  from: valueOf(rule.from),
  to: valueOf(rule.to),
  ports: rule.ports === "all" ? "all" : "specific",
  text: rule.ports === "all" ? "" : rule.ports.join(", "),
});

const portsOf = (form: RuleForm) =>
  form.ports === "all" ? "all" : parsePorts(form.text);

export function portsError(form: RuleForm): string | null {
  const ports = portsOf(form);
  return typeof ports === "object" && "error" in ports ? ports.error : null;
}

export function ruleOf(
  form: RuleForm,
): { rule: NetworkRule } | { error: string } {
  if (form.from === "") return { error: "Choose who can connect." };
  if (form.to === "") return { error: "Choose the server they connect to." };
  const ports = portsOf(form);
  if (typeof ports === "object" && "error" in ports) return ports;
  return {
    rule: {
      from:
        form.from === "laptops" || form.from === "servers"
          ? { group: form.from }
          : { node: form.from },
      to: form.to === "servers" ? { group: "servers" } : { node: form.to },
      ports,
    },
  };
}

export const canSave = (
  form: RuleForm,
  editing: { index: number; rule: NetworkRule } | null,
) => {
  const built = ruleOf(form);
  return "rule" in built && !(editing && sameRule(editing.rule, built.rule));
};

const clip = (text: string, max: number) =>
  text.length <= max ? text : `${text.slice(0, max - 1)}…`;

export const ruleChange = (
  rule: NetworkRule,
  editing: { index: number; rule: NetworkRule } | null,
  names: ReadonlyMap<string, string>,
) => ({
  change: clip(
    `${editing ? "Change" : "Add"} rule: ${describeRule(rule, names)}`,
    300,
  ),
  detail: editing
    ? clip(`Was: ${describeRule(editing.rule, names)}`, 2000)
    : null,
});

export const ruleDeleteText = (
  rule: NetworkRule,
  names: ReadonlyMap<string, string>,
) => clip(`Delete rule: ${describeRule(rule, names)}`, 300);

const changedMeanwhile = () =>
  new Error("The rules changed; open the list again.");

function confirmShown(
  document: NetworkDocument,
  index: number,
  shown: NetworkRule,
) {
  const now = document.allow[index];
  if (now === undefined || keyOf(now) !== keyOf(shown)) {
    throw changedMeanwhile();
  }
}

export function dropRule(
  document: NetworkDocument,
  index: number,
  shown: NetworkRule,
): NetworkDocument {
  confirmShown(document, index, shown);
  return withoutRule(document, index);
}

export function saveRule(
  document: NetworkDocument,
  rule: NetworkRule,
  editing: { index: number; rule: NetworkRule } | null,
): NetworkDocument {
  if (!editing) return withRule(document, rule);
  confirmShown(document, editing.index, editing.rule);
  return withRule(withoutRule(document, editing.index), rule);
}

export const targetsOf = (document: NetworkDocument, rules: NetworkRule[]) => {
  const servers = serversOf(document).map((one) => one.node);
  return [
    ...new Set(rules.flatMap(({ to }) => ("node" in to ? [to.node] : servers))),
  ];
};

export const failuresOf = (view: {
  members: Pick<NetworkView["members"][number], "node" | "failure">[];
}) => Object.fromEntries(view.members.map((one) => [one.node, one.failure]));

export const applyLines = (
  view: {
    members: Pick<
      NetworkView["members"][number],
      "node" | "name" | "applied" | "failure"
    >[];
  },
  nodes: string[],
  version: number,
  before: Readonly<Record<string, string | null>> = {},
) =>
  view.members
    .filter((one) => nodes.includes(one.node))
    .map((one) =>
      one.applied >= version
        ? `Applied on ${one.name}.`
        : one.failure && one.failure !== (before[one.node] ?? null)
          ? `${one.name}: ${one.failure}`
          : `Applying on ${one.name}…`,
    );
