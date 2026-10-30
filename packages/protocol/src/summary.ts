export interface ChangeSummary {
  title: string;
  admitted: string[];
  removed: string[];
  access: { nodeId: string; added: string[]; removed: string[] }[];
}

const plural = (count: number, word: string) =>
  `${count} ${word}${count === 1 ? "" : "s"}`;

const listed = (items: string[], word: string) =>
  items.length > 3
    ? plural(items.length, word)
    : items.length === 1
      ? items[0]!
      : `${items.slice(0, -1).join(", ")} and ${items.at(-1)}`;

type Pair = { device: string; server: string };

function phrase(
  pairs: Pair[],
  say: (devices: string, servers: string) => string,
): string | null {
  if (pairs.length === 0) return "";
  const devices = [...new Set(pairs.map((pair) => pair.device))];
  const servers = [...new Set(pairs.map((pair) => pair.server))];
  if (devices.length === 1) return say(devices[0]!, listed(servers, "server"));
  if (servers.length === 1) return say(listed(devices, "device"), servers[0]!);
  return null;
}

export function summarizeChange(input: {
  names: Record<string, string>;
  servers: Record<string, string>;
  currentCore: string[];
  currentAccess: Record<string, string[]>;
  change: {
    core: string[] | null;
    access: Record<string, string[]>;
  };
}): ChangeSummary {
  const { change } = input;
  const core = change.core ?? input.currentCore;
  const admitted = core.filter((id) => !input.currentCore.includes(id));
  const removed = input.currentCore.filter((id) => !core.includes(id));
  const access = Object.entries(change.access)
    .map(([nodeId, list]) => {
      const before = input.currentAccess[nodeId] ?? [];
      return {
        nodeId,
        added: list.filter((id) => !before.includes(id)),
        removed: before.filter((id) => !list.includes(id)),
      };
    })
    .filter((entry) => entry.added.length > 0 || entry.removed.length > 0);
  const name = (id: string) => input.names[id] ?? "an unknown passkey";
  const parts = [
    ...admitted.map((id) => `Admit ${name(id)}`),
    ...removed.map((id) => `Remove ${name(id)}`),
  ];
  const server = (id: string) => input.servers[id] ?? "an unknown server";
  const given: Pair[] = [];
  const taken: Pair[] = [];
  for (const entry of access) {
    for (const id of entry.added.filter((id) => !admitted.includes(id))) {
      given.push({ device: name(id), server: server(entry.nodeId) });
    }
    for (const id of entry.removed.filter((id) => !removed.includes(id))) {
      taken.push({ device: name(id), server: server(entry.nodeId) });
    }
  }
  const named = [
    phrase(given, (who, where) => `Give ${who} access to ${where}`),
    phrase(taken, (who, where) => `Take ${where} from ${who}`),
  ];
  if (named.includes(null)) {
    const count = new Set([...given, ...taken].map((pair) => pair.server)).size;
    parts.push(`Change access on ${plural(count, "server")}`);
  } else {
    parts.push(...named.filter((part): part is string => Boolean(part)));
  }
  return {
    title: parts.length > 0 ? parts.join(" · ") : "Refresh servers",
    admitted,
    removed,
    access,
  };
}
