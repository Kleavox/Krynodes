import type { Env } from "../env";
import { FleetHub } from "../fleet/hub";

export class FakeSocket {
  attachment: unknown = null;
  sent: string[] = [];
  closed: { code: number; reason: string } | null = null;
  get readyState() {
    return this.closed ? 3 : 1;
  }
  serializeAttachment(value: unknown) {
    this.attachment = structuredClone(value);
  }
  deserializeAttachment() {
    return structuredClone(this.attachment);
  }
  send(message: string) {
    if (this.closed) {
      throw new TypeError("Can't call WebSocket send() after close().");
    }
    this.sent.push(message);
  }
  close(code: number, reason: string) {
    this.closed = { code, reason };
  }
  replies() {
    return this.sent.map((text) => JSON.parse(text) as Record<string, unknown>);
  }
}

class AutoResponse {
  request: string;
  response: string;
  constructor(request: string, response: string) {
    this.request = request;
    this.response = response;
  }
}

export function hubHarness(db: D1Database, extra: Partial<Env> = {}) {
  if (!("WebSocketRequestResponsePair" in globalThis)) {
    Object.assign(globalThis, { WebSocketRequestResponsePair: AutoResponse });
  }
  const accepted: { ws: FakeSocket; tags: string[] }[] = [];
  const autoResponses: AutoResponse[] = [];
  const pings = new Map<FakeSocket, number>();
  const joins: Promise<void>[] = [];
  let alarm: number | null = null;
  const kept = new Map<string, unknown>();
  let gate: Promise<unknown> = Promise.resolve();
  let resets = 0;
  const ctx = {
    blockConcurrencyWhile<T>(work: () => Promise<T>): Promise<T> {
      const run = gate.then(work);
      gate = run.catch(() => {
        resets += 1;
      });
      return run;
    },
    acceptWebSocket(ws: FakeSocket, tags: string[] = []) {
      accepted.push({ ws, tags });
    },
    getWebSockets(tag?: string) {
      return accepted
        .filter((entry) => !tag || entry.tags.includes(tag))
        .map((entry) => entry.ws);
    },
    setWebSocketAutoResponse(pair: AutoResponse) {
      autoResponses.push(pair);
    },
    getWebSocketAutoResponseTimestamp(ws: FakeSocket) {
      const at = pings.get(ws);
      return at === undefined ? null : new Date(at);
    },
    storage: {
      async getAlarm() {
        return alarm;
      },
      async setAlarm(at: number) {
        alarm = at;
      },
      async get(key: string) {
        return structuredClone(kept.get(key));
      },
      async put(key: string, value: unknown) {
        kept.set(key, structuredClone(value));
      },
      async delete(key: string) {
        return kept.delete(key);
      },
    },
  };
  const env = { DB: db, ...extra } as unknown as Env;
  const fresh = () => new FleetHub(ctx as unknown as DurableObjectState, env);
  let hub = fresh();
  const connect = (nodeId: string, version: string | null = "0.7.94") => {
    const ws = new FakeSocket();
    joins.push(hub.join(ws as unknown as WebSocket, nodeId, version));
    return ws;
  };
  const watch = () => {
    const ws = new FakeSocket();
    hub.watch(ws as unknown as WebSocket);
    return ws;
  };
  const say = async (
    ws: FakeSocket,
    message: Record<string, unknown> | string,
  ) => {
    await gate;
    return hub.webSocketMessage(
      ws as unknown as WebSocket,
      typeof message === "string" ? message : JSON.stringify(message),
    );
  };
  return {
    get hub() {
      return hub;
    },
    forget() {
      hub = fresh();
    },
    alarmAt: () => alarm,
    resets: () => resets,
    stored: (key: string) => structuredClone(kept.get(key)),
    async settled() {
      await Promise.all(joins.splice(0));
    },
    async fire() {
      alarm = null;
      await hub.alarm();
    },
    ping(ws: FakeSocket) {
      pings.set(ws, Date.now());
    },
    autoResponses,
    connect,
    watch,
    say,
  };
}
