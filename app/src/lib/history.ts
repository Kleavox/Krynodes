import type { ActionRecord } from "../types";
import { shortDate } from "./format";
import { displayName, objectOf, verb } from "./services";

const dayOf = (at: number, offset = 0) => {
  const date = new Date(at);
  return new Date(
    date.getFullYear(),
    date.getMonth(),
    date.getDate() + offset,
  ).getTime();
};

export function byDay(
  actions: ActionRecord[],
  now: number,
): { label: string; actions: ActionRecord[] }[] {
  const today = dayOf(now);
  const yesterday = dayOf(now, -1);
  const groups: { label: string; actions: ActionRecord[] }[] = [];
  for (const action of actions) {
    const day = dayOf(Date.parse(action.requestedAt));
    const label =
      day === today
        ? "Today"
        : day === yesterday
          ? "Yesterday"
          : shortDate(day);
    const last = groups.at(-1);
    if (last?.label === label) last.actions.push(action);
    else groups.push({ label, actions: [action] });
  }
  return groups;
}

export function historyText(action: ActionRecord): string {
  const name = displayName(action.kind, action.name);
  if (action.action === "uninstall") return "Remove Krynodes from the server";
  return action.action === "logs"
    ? `Read logs of ${name}`
    : `${verb(action.action)} ${objectOf(action)}`;
}
