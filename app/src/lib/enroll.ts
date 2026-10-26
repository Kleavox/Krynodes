import type { EnrollDefaults } from "./api";
import { toUtcHour } from "./security";

export interface EnrollSetup {
  recommended: boolean;
  docker: boolean;
  rebootHour: number | null;
  network?: true;
}

export const enrollSetup = (
  choice: EnrollDefaults,
  offset: number,
): EnrollSetup => ({
  recommended: choice.recommended,
  docker: choice.docker,
  rebootHour: choice.recommended
    ? Math.floor(toUtcHour(choice.hour, offset))
    : null,
  ...(choice.network ? { network: true as const } : {}),
});
