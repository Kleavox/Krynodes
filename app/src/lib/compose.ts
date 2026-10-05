import { isMap, isScalar, isSeq, parseDocument, type YAMLMap } from "yaml";

type Service = Record<string, unknown>;

interface Loaded {
  services: Record<string, Service> | null;
  error: string | null;
}

export interface ComposeSummary {
  services: string[];
  internet: string[];
  folders: string[];
  hostNetwork: string[];
  devices: string[];
  privileged: string[];
  builds: string[];
  error: string | null;
}

const LOOPBACK = /^(127\.|::1$|localhost$|\[::1\]$)/u;

function load(text: string): Loaded {
  const doc = parseDocument(text);
  if (doc.errors.length > 0) {
    return {
      services: null,
      error: doc.errors[0]!.message.split("\n")[0]!.replace(/:$/u, ""),
    };
  }
  const value = doc.toJS() as { services?: unknown } | null;
  if (
    !value ||
    typeof value !== "object" ||
    !value.services ||
    typeof value.services !== "object" ||
    Array.isArray(value.services)
  ) {
    return {
      services: null,
      error: "A compose file needs a services section.",
    };
  }
  return { services: value.services as Record<string, Service>, error: null };
}

const list = (value: unknown): unknown[] => (Array.isArray(value) ? value : []);

function shortPort(entry: string) {
  const [mapping = "", protocol = "tcp"] = entry.split("/");
  const parts = mapping.split(":");
  const container = parts.at(-1) ?? "";
  const host = parts.length >= 2 ? parts.at(-2) : undefined;
  const ip = parts.length >= 3 ? parts.slice(0, -2).join(":") : undefined;
  return { container, host, ip, protocol };
}

export function summarize(text: string): ComposeSummary {
  const loaded = load(text);
  const summary: ComposeSummary = {
    services: [],
    internet: [],
    folders: [],
    hostNetwork: [],
    devices: [],
    privileged: [],
    builds: [],
    error: loaded.error,
  };
  if (!loaded.services) return summary;
  const add = (items: string[], item: string) => {
    if (!items.includes(item)) items.push(item);
  };
  for (const [name, service] of Object.entries(loaded.services)) {
    summary.services.push(name);
    if (!service || typeof service !== "object") continue;
    for (const port of list(service.ports)) {
      if (typeof port === "string" || typeof port === "number") {
        const parsed = shortPort(String(port));
        if (!parsed.ip || !LOOPBACK.test(parsed.ip)) {
          add(
            summary.internet,
            `${parsed.host ?? parsed.container}/${parsed.protocol}`,
          );
        }
      } else if (port && typeof port === "object") {
        const long = port as Record<string, unknown>;
        const ip = typeof long.host_ip === "string" ? long.host_ip : "";
        if (long.published !== undefined && !LOOPBACK.test(ip)) {
          add(
            summary.internet,
            `${String(long.published)}/${typeof long.protocol === "string" ? long.protocol : "tcp"}`,
          );
        }
      }
    }
    for (const volume of list(service.volumes)) {
      const source =
        typeof volume === "string"
          ? volume.split(":")[0]
          : volume &&
              typeof volume === "object" &&
              (volume as Record<string, unknown>).type === "bind"
            ? String((volume as Record<string, unknown>).source ?? "")
            : "";
      if (source && (source.startsWith("/") || source.startsWith("~"))) {
        add(summary.folders, source);
      }
    }
    if (service.network_mode === "host") summary.hostNetwork.push(name);
    if (list(service.devices).length > 0 || service.gpus)
      summary.devices.push(name);
    if (service.privileged === true) summary.privileged.push(name);
    if (service.build !== undefined) summary.builds.push(name);
  }
  return summary;
}

export function servicesOf(text: string): string[] {
  return Object.keys(load(text).services ?? {});
}

export function portsOf(text: string, name: string): number[] {
  const service = load(text).services?.[name];
  if (!service || typeof service !== "object") return [];
  const ports: number[] = [];
  const add = (value: unknown) => {
    const port = Number(value);
    if (
      Number.isInteger(port) &&
      port > 0 &&
      port < 65536 &&
      !ports.includes(port)
    ) {
      ports.push(port);
    }
  };
  for (const port of list(service.ports)) {
    if (typeof port === "string" || typeof port === "number") {
      add(shortPort(String(port)).container);
    } else if (port && typeof port === "object") {
      add((port as Record<string, unknown>).target);
    }
  }
  for (const port of list(service.expose)) add(String(port).split("/")[0]);
  return ports;
}

function names(value: string, removed: string[]): string | undefined {
  return removed.find((name) =>
    new RegExp(
      `(^|[^A-Za-z0-9_-])${name.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")}([^A-Za-z0-9_-]|$)`,
      "u",
    ).test(value),
  );
}

export function moveCompose(
  text: string,
  keep: string[],
  pins: Record<string, string>,
): { text: string; flagged: string[] } {
  const doc = parseDocument(text);
  const services = doc.get("services") as YAMLMap | undefined;
  if (!isMap(services)) return { text, flagged: [] };
  const all = services.items.map((item) =>
    String(isScalar(item.key) ? item.key.value : item.key),
  );
  const removed = all.filter((name) => !keep.includes(name));
  for (const name of removed) services.delete(name);
  const flagged: string[] = [];
  for (const name of keep) {
    const service = services.get(name) as YAMLMap | undefined;
    if (!isMap(service)) continue;
    const depends = service.get("depends_on");
    if (isSeq(depends)) {
      depends.items = depends.items.filter(
        (item) => !removed.includes(String(isScalar(item) ? item.value : item)),
      );
      if (depends.items.length === 0) service.delete("depends_on");
    } else if (isMap(depends)) {
      for (const gone of removed) depends.delete(gone);
      if (depends.items.length === 0) service.delete("depends_on");
    }
    if (pins[name]) service.set("image", pins[name]);
    const environment = service.get("environment");
    if (isMap(environment)) {
      for (const item of environment.items) {
        const key = String(isScalar(item.key) ? item.key.value : item.key);
        const value = String(isScalar(item.value) ? item.value.value : "");
        const found = names(value, removed);
        if (found) flagged.push(`${name}: ${key} still names ${found}`);
      }
    } else if (isSeq(environment)) {
      for (const item of environment.items) {
        const entry = String(isScalar(item) ? item.value : "");
        const [key = "", ...rest] = entry.split("=");
        const found = names(rest.join("="), removed);
        if (found) flagged.push(`${name}: ${key} still names ${found}`);
      }
    }
  }
  return { text: doc.toString(), flagged };
}
