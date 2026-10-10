interface Address {
  bits: bigint;
  size: 32 | 128;
}

export interface Listener {
  address: string;
  port: number;
  protocol: "tcp" | "udp";
  process: string;
}

export interface Finding {
  id: string;
  severity: "serious" | "warning" | "note";
  detail: string;
}

const PUBLIC_PORTS = "Listening on public addresses outside Krynodes: ";

function ipv4(text: string): bigint | null {
  const parts = text.split(".");
  if (parts.length !== 4) return null;
  let bits = 0n;
  for (const part of parts) {
    if (!/^\d{1,3}$/u.test(part) || Number(part) > 255) return null;
    bits = (bits << 8n) | BigInt(part);
  }
  return bits;
}

function ipv6(text: string): bigint | null {
  let rest = text.toLowerCase();
  const tail: number[] = [];
  const dotted = /:(\d+\.\d+\.\d+\.\d+)$/u.exec(rest);
  if (dotted) {
    const v4 = ipv4(dotted[1]!);
    if (v4 === null) return null;
    tail.push(Number(v4 >> 16n), Number(v4 & 0xffffn));
    rest = rest.slice(0, -dotted[1]!.length);
    if (!rest.endsWith("::")) rest = rest.slice(0, -1);
  }
  const halves = rest.split("::");
  if (halves.length > 2) return null;
  const group = (part: string) => (part === "" ? [] : part.split(":"));
  const head = group(halves[0]!);
  const back = halves.length === 2 ? group(halves[1]!) : [];
  const words = [...head, ...back];
  if (!words.every((word) => /^[0-9a-f]{1,4}$/u.test(word))) return null;
  const fill = 8 - words.length - tail.length;
  if (halves.length === 2 ? fill < 1 : fill !== 0) return null;
  const all = [
    ...head.map((word) => parseInt(word, 16)),
    ...Array<number>(halves.length === 2 ? fill : 0).fill(0),
    ...back.map((word) => parseInt(word, 16)),
    ...tail,
  ];
  return all.reduce((bits, word) => (bits << 16n) | BigInt(word), 0n);
}

function parseAddress(text: string): Address | null {
  if (text.includes(":")) {
    const bits = ipv6(text);
    return bits === null ? null : { bits, size: 128 };
  }
  const bits = ipv4(text);
  return bits === null ? null : { bits, size: 32 };
}

function formatAddress({ bits, size }: Address): string {
  if (size === 32) {
    return [24n, 16n, 8n, 0n].map((shift) => (bits >> shift) & 0xffn).join(".");
  }
  const words = Array.from({ length: 8 }, (_, index) =>
    Number((bits >> BigInt((7 - index) * 16)) & 0xffffn),
  );
  let best = { start: -1, length: 0 };
  for (let start = 0; start < 8; start++) {
    let length = 0;
    while (start + length < 8 && words[start + length] === 0) length++;
    if (length > best.length && length > 1) best = { start, length };
  }
  const hex = words.map((word) => word.toString(16));
  if (best.start < 0) return hex.join(":");
  return `${hex.slice(0, best.start).join(":")}::${hex.slice(best.start + best.length).join(":")}`;
}

const mask = (size: number, length: number) =>
  ((1n << BigInt(size)) - 1n) ^ ((1n << BigInt(size - length)) - 1n);

export function parseRange(text: string): string | null {
  const [base, prefix, extra] = text.trim().split("/");
  if (extra !== undefined || !base) return null;
  const address = parseAddress(base);
  if (!address) return null;
  if (prefix !== undefined && !/^\d{1,3}$/u.test(prefix)) return null;
  const length = prefix === undefined ? address.size : Number(prefix);
  if (length > address.size) return null;
  const masked = {
    ...address,
    bits: address.bits & mask(address.size, length),
  };
  return `${formatAddress(masked)}/${length}`;
}

function unmapped(address: Address): Address {
  return address.size === 128 && address.bits >> 32n === 0xffffn
    ? { bits: address.bits & 0xffffffffn, size: 32 }
    : address;
}

export function inRanges(text: string, ranges: string[]): boolean {
  const parsed = parseAddress(text);
  if (!parsed) return false;
  const address = unmapped(parsed);
  return ranges.some((range) => {
    const [base, prefix] = range.split("/");
    const network = parseAddress(base ?? "");
    if (!network || network.size !== address.size) return false;
    const bitsMask = mask(network.size, Number(prefix));
    return (address.bits & bitsMask) === network.bits;
  });
}

export function filterListeners<
  T extends { findings: Finding[]; listeners?: Listener[] },
>(report: T, ranges: string[]): T {
  if (ranges.length === 0 || !report.listeners) return report;
  const entries = [
    ...new Set(
      report.listeners
        .filter((listener) => !inRanges(listener.address, ranges))
        .map(
          (listener) =>
            `${listener.port}/${listener.protocol}${listener.process ? ` (${listener.process})` : ""}`,
        ),
    ),
  ];
  const findings = report.findings.flatMap((finding) =>
    finding.id !== "public-ports"
      ? [finding]
      : entries.length === 0
        ? []
        : [{ ...finding, detail: PUBLIC_PORTS + entries.join(", ") }],
  );
  return { ...report, findings };
}
