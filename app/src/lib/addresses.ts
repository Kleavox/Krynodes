export function addressCount(count: number): string {
  return count === 1 ? "1 address" : `${count} addresses`;
}

export const STAND_IN = { label: "IPv4", address: "000.000.000.00" } as const;
