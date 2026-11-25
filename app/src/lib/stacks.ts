import {
  isValidTarget,
  stackArgsValid,
  stackTitleValid,
  type NetworkDocument,
  type StackEntry,
} from "@krynodes/protocol";
import { parse } from "yaml";

import type { CheckView, FleetNode } from "../types";
import { currentDocument } from "./api";
import {
  browserStore,
  checkAnchor,
  remember,
  type PinStore,
  type Unchecked,
} from "./pins";
import { seal } from "./seal";

export type Access = "contained" | "full";

export interface StackForm {
  compose: string;
  access: Access;
  network: number[];
  title: string;
  env: string;
}

export interface SealDeps {
  current?: () => Promise<{ document: NetworkDocument; hash: string } | null>;
  store?: PinStore | null;
  check?: (members: Unchecked[]) => Promise<boolean>;
}

export const ACCESS_LINES: Record<Access, string> = {
  contained:
    "The stack keeps to its own folder and network. Host paths, privileged mode and host namespaces are refused.",
  full: "The stack can reach the server itself: host folders, devices and its network.",
};

export const CONNECTIONS_LINE =
  "Nothing reaches this port until a rule in Connections allows it.";

const MAX_PORTS = 32;
const MAX_COMPOSE = 32768;
const MAX_ENV = 16384;

const bytes = (text: string) => new TextEncoder().encode(text).length;

export const stackNameValid = (name: string) => isValidTarget("stack", name);

async function sealKeyFor(node: FleetNode, deps: SealDeps): Promise<string> {
  const current = await (deps.current ?? currentDocument)();
  const member = current?.document.members.find((one) => one.node === node.id);
  if (!current || !member) {
    throw new Error(
      `${node.name} is not in the private network, so its .env cannot be sealed.`,
    );
  }
  const store = deps.store === undefined ? browserStore() : deps.store;
  const unchecked = (await checkAnchor(current, store)).filter(
    (one) => one.node === node.id,
  );
  if (unchecked.length > 0) {
    const check = deps.check ?? (async () => false);
    if (!(await check(unchecked))) {
      throw new Error(
        "The fingerprint was not confirmed. Nothing was sealed or signed.",
      );
    }
    remember(store, unchecked);
  }
  return member.sealKey;
}

export async function buildStackArgs(
  form: StackForm,
  node: FleetNode,
  deps: SealDeps = {},
): Promise<Record<string, string>> {
  if (form.compose.trim() === "") throw new Error("Paste a compose file.");
  if (bytes(form.compose) > MAX_COMPOSE) {
    throw new Error("The compose file must be at most 32 KB.");
  }
  if (bytes(form.env) > MAX_ENV) {
    throw new Error("The .env must be at most 16 KB.");
  }
  const args: Record<string, string> = {
    compose: form.compose,
    access: form.access,
    network: [...new Set(form.network)].join(","),
  };
  const title = form.title.trim();
  if (title !== "") args.title = title;
  if (form.env.trim() !== "") {
    args.env = await seal(await sealKeyFor(node, deps), form.env);
  }
  if (title !== "" && !stackTitleValid(title)) {
    throw new Error("A title is at most 64 characters on one line.");
  }
  if (!stackArgsValid("stack", "create", args)) {
    throw new Error(
      args.env
        ? "The .env is too long once sealed. Shorten it."
        : "The server would refuse these settings.",
    );
  }
  return args;
}

function hostPorts(spec: string): number[] {
  const [mapping = ""] = spec.split("/");
  const cut = mapping.lastIndexOf(":");
  if (cut < 0) return [];
  const host = mapping.slice(0, cut);
  return portRange(host.slice(host.lastIndexOf(":") + 1));
}

function portRange(text: string): number[] {
  const found = /^(\d{1,5})(?:-(\d{1,5}))?$/u.exec(text);
  if (!found) return [];
  const low = Number(found[1]);
  const high = Number(found[2] ?? found[1]);
  if (low < 1 || high > 65535 || high < low || high - low >= MAX_PORTS) {
    return [];
  }
  return Array.from({ length: high - low + 1 }, (_, index) => low + index);
}

export function publishedPorts(compose: string): number[] {
  let config: unknown;
  try {
    config = parse(compose, { merge: true });
  } catch {
    return [];
  }
  const services = (config as { services?: unknown } | null)?.services;
  if (typeof services !== "object" || services === null) return [];
  const found = new Set<number>();
  for (const service of Object.values(services)) {
    const ports = (service as { ports?: unknown } | null)?.ports;
    if (!Array.isArray(ports)) continue;
    for (const port of ports) {
      const numbers =
        typeof port === "string"
          ? hostPorts(port)
          : typeof port === "object" && port !== null
            ? portRange(String((port as { published?: unknown }).published))
            : [];
      for (const number of numbers) found.add(number);
    }
  }
  return [...found].sort((a, b) => a - b).slice(0, MAX_PORTS);
}

const covers = (range: string, port: number) => {
  const [span = ""] = range.split("/");
  const [low, high = low] = span.split("-").map(Number);
  return low !== undefined && low <= port && port <= high!;
};

export function portAllowed(
  document: NetworkDocument | undefined,
  node: string,
  port: number,
): boolean {
  if (!document) return false;
  const server = document.members.some(
    (one) => one.node === node && one.kind !== "laptop",
  );
  return document.allow.some(
    ({ to, ports }) =>
      ("node" in to ? to.node === node : server) &&
      (ports === "all" || ports.some((range) => covers(range, port))),
  );
}

export function checkLabel(
  check: Pick<CheckView, "state" | "cause">,
): "Up" | "Down" | "Paused" | "--" {
  if (check.state === "up") return "Up";
  if (check.state === "down")
    return check.cause === "owner" ? "Paused" : "Down";
  return "--";
}

export const stackLine = (stack: Pick<StackEntry, "running" | "total">) =>
  `${stack.running} of ${stack.total} running`;

export interface ReadStack {
  compose: string;
  access: Access;
  title: string;
  network: number[];
  env: string[];
}

export function readStack(output: string | null | undefined): ReadStack {
  let parsed: Partial<ReadStack> | null = null;
  try {
    parsed = JSON.parse(output ?? "") as Partial<ReadStack> | null;
  } catch {
    parsed = null;
  }
  if (typeof parsed?.compose !== "string") {
    throw new Error("The server's answer did not hold the compose file.");
  }
  return {
    compose: parsed.compose,
    access: parsed.access === "full" ? "full" : "contained",
    title: typeof parsed.title === "string" ? parsed.title : "",
    network: Array.isArray(parsed.network) ? parsed.network : [],
    env: Array.isArray(parsed.env) ? parsed.env : [],
  };
}
