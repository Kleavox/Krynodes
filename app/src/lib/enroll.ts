import type { SetupChoice } from "./api";
import { toUtcHour } from "./security";

export interface EnrollSetup {
  recommended: boolean;
  docker: boolean;
  rebootHour: number | null;
  network?: true;
  adminUser?: true;
  adminName?: string;
}

export const enrollSetup = (
  choice: SetupChoice,
  offset: number,
): EnrollSetup => ({
  recommended: choice.recommended,
  docker: choice.docker,
  rebootHour: choice.recommended
    ? Math.floor(toUtcHour(choice.hour, offset))
    : null,
  ...(choice.network ? { network: true as const } : {}),
  ...(choice.adminUser
    ? { adminUser: true as const, adminName: (choice.adminName ?? "").trim() }
    : {}),
});
