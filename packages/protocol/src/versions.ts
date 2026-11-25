export const MIN_AGENT = "0.7.93";

const RELEASE = /^\d+\.\d+\.\d+$/u;

export function compareVersions(a: string, b: string): number {
  const left = a.split(".").map(Number);
  const right = b.split(".").map(Number);
  for (let index = 0; index < 3; index += 1) {
    const difference = (left[index] ?? 0) - (right[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return 0;
}

export const agentSupported = (version: string | null | undefined) =>
  Boolean(version) &&
  (!RELEASE.test(version!) || compareVersions(version!, MIN_AGENT) >= 0);
