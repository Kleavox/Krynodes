export const MIN_AGENT_VERSION = "0.6.0";
export const UPDATABLE_FROM = "0.5.0";

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

const reaches = (version: string | null | undefined, floor: string) =>
  Boolean(version) &&
  (!RELEASE.test(version!) || compareVersions(version!, floor) >= 0);

export const agentSupported = (version: string | null | undefined) =>
  reaches(version, MIN_AGENT_VERSION);

export const agentUpdatable = (version: string | null | undefined) =>
  reaches(version, UPDATABLE_FROM);
