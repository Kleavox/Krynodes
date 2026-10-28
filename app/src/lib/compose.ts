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
  docker: string[];
  private: string[];
  error: string | null;
}

const LOOPBACK = /^(127\.|::1$|localhost$|\[::1\]$)/u;
const PRIVATE_IP = /^\$\{?KRY_PRIVATE_IP\}?$/u;

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
    docker: [],
    private: [],
    error: loaded.error,
  };
  if (!loaded.services) return summary;
  const add = (items: string[], item: string) => {
    if (!items.includes(item)) items.push(item);
  };
  const opens = (ip: string, port: string) => {
    if (PRIVATE_IP.test(ip)) add(summary.private, port);
    else if (!LOOPBACK.test(ip)) add(summary.internet, port);
  };
  for (const [name, service] of Object.entries(loaded.services)) {
    summary.services.push(name);
    if (!service || typeof service !== "object") continue;
    for (const port of list(service.ports)) {
      if (typeof port === "string" || typeof port === "number") {
        const parsed = shortPort(String(port));
        opens(
          parsed.ip ?? "",
          `${parsed.host ?? parsed.container}/${parsed.protocol}`,
        );
      } else if (port && typeof port === "object") {
        const long = port as Record<string, unknown>;
        if (long.published !== undefined) {
          opens(
            typeof long.host_ip === "string" ? long.host_ip : "",
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
      if (source?.endsWith("docker.sock")) add(summary.docker, name);
    }
    if (service.use_api_socket === true) add(summary.docker, name);
    if (service.network_mode === "host") summary.hostNetwork.push(name);
    if (list(service.devices).length > 0 || service.gpus)
      summary.devices.push(name);
    if (service.privileged === true) summary.privileged.push(name);
    if (service.build !== undefined) summary.builds.push(name);
  }
  return summary;
}

function published(
  text: string,
  shape: RegExp,
): { port: string; service: string }[] {
  const found: { port: string; service: string }[] = [];
  for (const [service, value] of Object.entries(load(text).services ?? {})) {
    if (!value || typeof value !== "object") continue;
    for (const port of list(value.ports)) {
      let host: unknown;
      let protocol: unknown = "tcp";
      if (typeof port === "string" || typeof port === "number") {
        ({ host, protocol } = shortPort(String(port)));
      } else if (port && typeof port === "object") {
        const long = port as Record<string, unknown>;
        host = long.published;
        protocol = long.protocol ?? "tcp";
      }
      const name = `${String(host)}/${String(protocol)}`;
      if (shape.test(name) && !found.some((entry) => entry.port === name)) {
        found.push({ port: name, service });
      }
    }
  }
  return found;
}

export const publishedPorts = (text: string) =>
  published(text, /^\d{1,5}\/(tcp|udp)$/u);

export const publishedRanges = (text: string) =>
  published(text, /^\d{1,5}-\d{1,5}\/(tcp|udp)$/u);

export const usesPrivateIp = (text: string) =>
  /\$\{?KRY_PRIVATE_IP\b/u.test(text);

export function usePrivateAddress(text: string): string {
  const doc = parseDocument(text);
  const services = doc.get("services");
  if (doc.errors.length > 0 || !isMap(services)) return text;
  let changed = false;
  for (const item of services.items) {
    const ports = isMap(item.value) ? item.value.get("ports") : null;
    if (!isSeq(ports)) continue;
    for (const port of ports.items) {
      if (!isScalar(port)) continue;
      const value = String(port.value);
      const parsed = shortPort(value);
      if (parsed.host !== undefined && parsed.ip === undefined) {
        port.value = `\${KRY_PRIVATE_IP}:${value}`;
        changed = true;
      }
    }
  }
  return changed ? doc.toString() : text;
}

const record = (value: unknown): Record<string, unknown> =>
  value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};

export function sharedNetworksOf(
  text: string,
): { key: string; name: string; services: string[] }[] {
  const doc = parseDocument(text);
  if (doc.errors.length > 0) return [];
  const value = record(doc.toJS());
  const services = record(value.services);
  return Object.entries(record(value.networks)).flatMap(([key, network]) => {
    const entry = record(network);
    if (entry.external !== true) return [];
    return [
      {
        key,
        name: typeof entry.name === "string" ? entry.name : key,
        services: Object.keys(services).filter((name) => {
          const networks = record(services[name]).networks;
          return Array.isArray(networks)
            ? networks.includes(key)
            : key in record(networks);
        }),
      },
    ];
  });
}

export function serviceShape(text: string, name: string) {
  const service = record(load(text).services?.[name]);
  const copies = Number(record(service.deploy).replicas ?? service.scale ?? 1);
  return {
    privileged: service.privileged === true,
    caps: list(service.cap_add).map((cap) =>
      String(cap).toUpperCase().replace(/^CAP_/u, ""),
    ),
    networkMode: service.network_mode !== undefined,
    copies: Number.isFinite(copies) ? copies : 1,
  };
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
