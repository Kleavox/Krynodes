import type { Env } from "../env";
import { FleetHub } from "../fleet/hub";

export class FakeSocket {
  attachment: unknown = null;
  sent: string[] = [];
  closed: { code: number; reason: string } | null = null;
  lingers = false;
  pinged: number | null = null;
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

export class FakeStorage {
  values = new Map<string, unknown>();
  alarm: number | null = null;
  async get(key: string) {
    return structuredClone(this.values.get(key));
  }
  async put(key: string, value: unknown) {
    this.values.set(key, structuredClone(value));
  }
  async delete(key: string) {
    return this.values.delete(key);
  }
  async setAlarm(at: number) {
    this.alarm = at;
  }
  async deleteAlarm() {
    this.alarm = null;
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

export function hubHarness(env: Partial<Env>) {
  if (!("WebSocketRequestResponsePair" in globalThis)) {
    Object.assign(globalThis, { WebSocketRequestResponsePair: AutoResponse });
  }
  const accepted: { ws: FakeSocket; tags: string[] }[] = [];
  const ctx = {
    acceptWebSocket(ws: FakeSocket, tags: string[]) {
      accepted.push({ ws, tags });
    },
    getWebSockets(tag?: string) {
      return accepted
        .filter(
          (entry) =>
            (!entry.ws.closed || entry.ws.lingers) &&
            (!tag || entry.tags.includes(tag)),
        )
        .map((entry) => entry.ws);
    },
    getWebSocketAutoResponseTimestamp(ws: FakeSocket) {
      return ws.pinged === null ? null : new Date(ws.pinged);
    },
    setWebSocketAutoResponse() {},
    storage: new FakeStorage(),
  };
  const hub = new FleetHub(
    ctx as unknown as DurableObjectState,
    env as unknown as Env,
  );
  let requests = 0;
  const connect = async (
    nodeId: string,
    ownerId = "standalone",
    interval = 60,
  ) => {
    const ws = new FakeSocket();
    await hub.accept(ws as unknown as WebSocket, nodeId, ownerId, interval);
    return ws;
  };
  const request = async (
    ws: FakeSocket,
    type: string,
    fields: Record<string, unknown> = {},
  ) => {
    requests += 1;
    const id = requests;
    await hub.webSocketMessage(
      ws as unknown as WebSocket,
      JSON.stringify({ id, type, ...fields }),
    );
    return ws.replies().find((reply) => reply.id === id) ?? null;
  };
  return { hub, accepted, connect, request };
}
