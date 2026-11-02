import type { SetupChoice } from "./api";
import { toUtcHour } from "./security";

export interface EnrollSetup {
  docker: boolean;
  rebootHour: number;
  network?: true;
  adminName: string;
}

export const enrollSetup = (
  choice: SetupChoice,
  offset: number,
): EnrollSetup => ({
  docker: choice.docker,
  rebootHour: Math.floor(toUtcHour(choice.hour, offset)),
  ...(choice.network ? { network: true as const } : {}),
  adminName: (choice.adminName ?? "").trim(),
});
