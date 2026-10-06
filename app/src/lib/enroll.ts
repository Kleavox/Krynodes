import { toUtcHour } from "./security";

export function setupFlags(choice: {
  recommended: boolean;
  docker: boolean;
  hour: number;
  offset: number;
}): string {
  const steps = [
    ...(choice.recommended ? ["recommended"] : []),
    ...(choice.docker ? ["docker"] : []),
  ];
  if (steps.length === 0) return "";
  const hour = choice.recommended
    ? ` --reboot-hour ${Math.floor(toUtcHour(choice.hour, choice.offset))}`
    : "";
  return ` --setup ${steps.join(",")}${hour}`;
}
