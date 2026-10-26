import { describe, expect, it, vi } from "vitest";

import type { Env } from "../env";
import { sendServerEmail, sendTokenEmail } from "./mail";

function mailEnv(extra: Partial<Env> = {}) {
  const send = vi.fn(async () => ({ messageId: "m-1" }));
  const env = {
    EMAIL: { send },
    ALERT_EMAIL: "operator@example.test",
    FROM_EMAIL: "kry@example.test",
    PUBLIC_ORIGIN: "https://kry.example.test",
    ...extra,
  } as unknown as Env;
  const sent = () =>
    (send.mock.calls[0] as unknown as [Record<string, string>])[0];
  return { env, send, sent };
}

const at = "2026-09-28T08:05:09.123Z";
const down = (checkName: string | null, summary = `${checkName} is down`) => ({
  checkName,
  summary,
  occurredAt: at,
});

describe("incident email", () => {
  it("goes to the operator through the Cloudflare binding, one mail per server", async () => {
    const { env, sent } = mailEnv();
    await sendServerEmail(env, {
      nodeId: "n1",
      nodeName: "pivox",
      down: [
        down("API <health>", "API <health> is down: timeout"),
        down("Web"),
      ],
    });
    const message = sent();
    expect(message.to).toBe("operator@example.test");
    expect(message.from).toEqual({
      name: "Krynodes",
      email: "kry@example.test",
    });
    expect(message.subject).toBe(
      "[Krynodes] pivox: 2 checks down — API <health>, Web",
    );
    expect(message.html).toContain("API &lt;health&gt;");
    expect(message.html).not.toContain("<health>");
    expect(message.html).toContain("2026-09-28 08:05 UTC");
    expect(message.html).toContain(
      'href="https://kry.example.test/checks?status=down"',
    );
    expect(message.html).toContain("Open Checks");
    expect(message.html).not.toMatch(/Pulse|Kleavox/u);
    expect(message.text).toContain("timeout");
    expect(message.text).toContain(
      "https://kry.example.test/checks?status=down",
    );
  });

  it("says plainly when a server stops reporting", async () => {
    const { env, sent } = mailEnv();
    await sendServerEmail(env, {
      nodeId: "n1",
      nodeName: "pivox",
      down: [down(null, "pivox stopped reporting")],
    });
    expect(sent().subject).toBe("[Krynodes] pivox: offline");
    expect(sent().text).toContain("Last report: 2026-09-28 08:05 UTC");
    expect(sent().text).toContain("https://kry.example.test/nodes/n1");
  });

  it("writes row labels as they are, without uppercase", async () => {
    const { env, sent } = mailEnv();
    await sendTokenEmail(env, { expiresAt: "2026-11-20T00:00:00.000Z" });
    expect(sent().html).toContain(">Expires</td>");
    expect(sent().html).not.toContain("text-transform:uppercase");
    expect(sent().html).not.toContain("letter-spacing:0.06em");
  });

  it("sends nothing when no operator address or binding is configured", async () => {
    for (const extra of [{ ALERT_EMAIL: undefined }, { EMAIL: undefined }]) {
      const { env, send } = mailEnv(extra);
      await sendServerEmail(env, {
        nodeId: "n1",
        nodeName: "pivox",
        down: [down("API")],
      });
      expect(send).not.toHaveBeenCalled();
    }
  });
});
