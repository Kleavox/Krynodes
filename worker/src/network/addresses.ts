export interface AddressRow {
  address: string;
  state: "used" | "held" | "freed";
  freed_at: string | null;
}

export function nextAddresses(
  range: string,
  rows: AddressRow[],
  count: number,
): string[] {
  const prefix = range.slice(0, -4);
  const known = new Set(rows.map((row) => row.address));
  const fresh = Array.from(
    { length: 254 },
    (_, index) => `${prefix}${index + 1}`,
  ).filter((address) => !known.has(address));
  const freed = rows
    .filter((row) => row.state === "freed")
    .sort((a, b) => (a.freed_at ?? "").localeCompare(b.freed_at ?? ""))
    .map((row) => row.address);
  const open = [...fresh, ...freed];
  if (open.length < count) throw new Error(`No address left in ${range}.`);
  return open.slice(0, count);
}
