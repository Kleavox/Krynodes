import { z } from "zod";

import {
  CONTAINER_NAME,
  PROJECT_NAME,
  parseStackNames,
  SERVICE_NAME,
  stackTitleValid,
  TARGET_NAME,
} from "./targets";

export const STACK_ACTIONS = {
  stack: [
    "create",
    "deploy",
    "edit",
    "read",
    "rollback",
    "start",
    "stop",
    "restart",
    "remove",
    "restore",
    "purge",
    "adopt",
    "logs",
  ],
  container: ["start", "stop", "restart", "logs"],
  unit: ["start", "stop", "restart"],
  docker: ["install"],
} as const;

const MAX_COMPOSE_BYTES = 32768;
const SEALED_ENV = /^[A-Za-z0-9_-]{1,24576}$/u;
const MAX_PORTS = 32;
const MAX_LINES = 500;

type Check = (value: string) => boolean;

interface Shape {
  need: Record<string, Check>;
  may: Record<string, Check>;
}

const compose: Check = (text) => {
  const size = new TextEncoder().encode(text).length;
  return size >= 1 && size <= MAX_COMPOSE_BYTES;
};

const ports: Check = (text) => {
  if (text === "") return true;
  const list = text.split(",");
  return (
    list.length <= MAX_PORTS &&
    new Set(list).size === list.length &&
    list.every((port) => /^[1-9]\d{0,4}$/u.test(port) && Number(port) <= 65535)
  );
};

const access: Check = (text) => text === "contained" || text === "full";

const SAVE: Shape = {
  need: {
    compose,
    access,
    network: ports,
  },
  may: {
    env: (text) => SEALED_ENV.test(text),
    title: stackTitleValid,
    names: (text) => parseStackNames(text) !== null,
  },
};

const lines: Check = (text) =>
  /^[1-9]\d{0,2}$/u.test(text) && Number(text) <= MAX_LINES;

const STACK_LOGS: Shape = {
  need: { lines },
  may: { service: (text) => SERVICE_NAME.test(text) },
};

const CONTAINER_LOGS: Shape = { need: { lines }, may: {} };

const ADOPT: Shape = { need: { access }, may: {} };

const NONE: Shape = { need: {}, may: {} };

export type StackKind = keyof typeof STACK_ACTIONS;

function shapeOf(kind: StackKind, action: string): Shape {
  if (kind === "stack" && (action === "create" || action === "edit")) {
    return SAVE;
  }
  if (kind === "stack" && action === "adopt") return ADOPT;
  if (action === "logs") return kind === "stack" ? STACK_LOGS : CONTAINER_LOGS;
  return NONE;
}

const isPlain = (value: unknown): value is Record<string, unknown> => {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
};

const rule = (shape: Shape, key: string): Check | undefined =>
  Object.hasOwn(shape.need, key)
    ? shape.need[key]
    : Object.hasOwn(shape.may, key)
      ? shape.may[key]
      : undefined;

export function stackArgsValid(
  kind: StackKind,
  action: string,
  args: unknown,
): boolean {
  if (!isPlain(args) || !Object.hasOwn(STACK_ACTIONS, kind)) return false;
  if (!(STACK_ACTIONS[kind] as readonly string[]).includes(action)) {
    return false;
  }
  const shape = shapeOf(kind, action);
  return (
    Object.keys(shape.need).every((key) => Object.hasOwn(args, key)) &&
    Object.entries(args).every(
      ([key, value]) =>
        typeof value === "string" && rule(shape, key)?.(value) === true,
    )
  );
}

const count = z.number().int().nonnegative();
const iso = z.iso.datetime();
const named = (pattern: RegExp) => z.string().regex(pattern);

export const stackEntrySchema = z.strictObject({
  project: named(PROJECT_NAME),
  title: z.string().refine(stackTitleValid).nullable(),
  directory: z.string().max(4096),
  own: z.boolean(),
  access: z.enum(["contained", "full"]).nullable(),
  running: count,
  total: count,
  rollback: z.boolean(),
  network: z.array(z.number().int().min(1).max(65535)).max(MAX_PORTS),
  services: z
    .array(
      z.strictObject({
        service: named(SERVICE_NAME),
        container: named(CONTAINER_NAME),
      }),
    )
    .max(64),
});

export const containerEntrySchema = z.strictObject({
  name: named(CONTAINER_NAME),
  project: named(PROJECT_NAME).nullable(),
  service: named(SERVICE_NAME).nullable(),
  image: z.string().max(512),
  state: z.enum(["running", "stopped", "restarting", "paused"]),
  health: z.enum(["healthy", "unhealthy", "starting"]).nullable(),
  ports: z.array(z.string().max(128)).max(MAX_PORTS),
});

export const unitEntrySchema = z.strictObject({
  name: named(TARGET_NAME),
  state: z.enum(["running", "stopped", "failed"]),
  protected: z.boolean(),
});

export const removedEntrySchema = z.strictObject({
  project: named(PROJECT_NAME),
  removedAt: iso,
});

export const inventorySchema = z.strictObject({
  type: z.literal("inventory"),
  hash: z.string().regex(/^[0-9a-f]{64}$/u),
  docker: z.enum(["missing", "stopped", "ready"]),
  compose: z.string().max(64).nullable(),
  stacks: z.array(stackEntrySchema).max(64),
  containers: z.array(containerEntrySchema).max(256),
  units: z.array(unitEntrySchema).max(256),
  removed: z.array(removedEntrySchema).max(64),
});

export const checkSchema = z.strictObject({
  type: z.literal("check"),
  name: named(CONTAINER_NAME),
  state: z.enum(["up", "down", "gone"]),
  cause: z.literal("owner").nullable(),
  at: iso,
  detail: z.string().max(200),
});

export const checksSchema = z.strictObject({
  type: z.literal("checks"),
  names: z.array(named(CONTAINER_NAME)).max(64),
});

export type StackEntry = z.infer<typeof stackEntrySchema>;
export type ContainerEntry = z.infer<typeof containerEntrySchema>;
export type UnitEntry = z.infer<typeof unitEntrySchema>;
export type RemovedEntry = z.infer<typeof removedEntrySchema>;
export type Inventory = z.infer<typeof inventorySchema>;
export type ContainerCheck = z.infer<typeof checkSchema>;
