import type { EnrollmentStatus } from "../types";

export type EnrollmentStep = "start" | "waiting" | "connected" | "expired";

export function enrollmentStep(
  created: boolean,
  status: EnrollmentStatus | undefined,
): EnrollmentStep {
  if (!created) return "start";
  if (status?.status === "used") return "connected";
  if (status?.status === "expired") return "expired";
  return "waiting";
}

export function pollEnrollment(
  status: EnrollmentStatus | undefined,
): number | false {
  return !status || status.status === "pending" ? 3_000 : false;
}
