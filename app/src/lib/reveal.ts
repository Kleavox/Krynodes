import { useSyncExternalStore } from "react";

const KEY = "kry-addresses";
const listeners = new Set<() => void>();
let shown = read();

function read(): boolean {
  try {
    return sessionStorage.getItem(KEY) === "shown";
  } catch {
    return false;
  }
}

function remember(next: boolean): boolean {
  try {
    if (next) sessionStorage.setItem(KEY, "shown");
    else sessionStorage.removeItem(KEY);
    return true;
  } catch {
    return false;
  }
}

export function setAddressesShown(next: boolean) {
  shown = next;
  remember(next);
  for (const listener of listeners) listener();
}

const subscribe = (listener: () => void) => {
  listeners.add(listener);
  return () => listeners.delete(listener);
};

export const useAddressesShown = () =>
  useSyncExternalStore(
    subscribe,
    () => shown,
    () => false,
  );
