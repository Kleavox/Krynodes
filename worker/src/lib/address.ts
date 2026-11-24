const QUAD =
  /^(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})$/u;

export function publicIpv4(value: string | null | undefined): string | null {
  const octets = QUAD.exec(value ?? "")
    ?.slice(1)
    .map(Number);
  if (!octets || octets.some((octet) => octet > 255)) return null;
  const [a, b] = octets as [number, number];
  const shared =
    a === 0 ||
    a === 10 ||
    a === 127 ||
    a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168);
  return shared ? null : octets.join(".");
}
