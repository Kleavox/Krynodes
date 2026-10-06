export const MIN_AGENT_VERSION = "0.5.0";

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

export function agentSupported(version: string | null | undefined): boolean {
  if (!version) return false;
  return (
    !RELEASE.test(version) || compareVersions(version, MIN_AGENT_VERSION) >= 0
  );
}
