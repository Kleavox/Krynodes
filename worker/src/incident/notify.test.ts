import { describe, expect, it } from "vitest";

import { emptyBox, loadBox, receive, type IncidentNotice } from "./notify";

const T = Date.parse("2026-10-02T10:00:00.000Z");
const MINUTE = 60_000;

const notice = (
  nodeId: string,
  checkName: string | null,
  kind: "opened" | "resolved" = "opened",
): IncidentNotice => ({
  nodeId,
  checkId: checkName === null ? null : `${nodeId}-${checkName}`,
  checkName,
  kind,
  summary: `${checkName ?? nodeId} is down`,
  occurredAt: new Date(T).toISOString(),
});

function run(steps: [number, IncidentNotice[]][]) {
  let box = emptyBox();
  const mails: { at: number; nodeId: string; down: string[] }[] = [];
  for (const [at, notices] of steps) {
    const result = receive(box, notices, at);
    box = result.box;
    for (const server of result.send) {
      mails.push({
        at,
        nodeId: server.nodeId,
        down: server.down.map((entry) => entry.checkName ?? "server"),
      });
    }
  }
  return mails;
}

describe("incident mail", () => {
  it("mails a failure at once, one mail per server per report", () => {
    expect(
      run([
        [
          T,
          [
            notice("server-1", "Health"),
            notice("server-1", "API"),
            notice("vps", null),
          ],
        ],
      ]),
    ).toEqual([
      { at: T, nodeId: "server-1", down: ["Health", "API"] },
      { at: T, nodeId: "vps", down: ["server"] },
    ]);
  });

  it("never mails a recovery", () => {
    expect(
      run([
        [T, [notice("server-1", "Health")]],
        [T + 5 * MINUTE, [notice("server-1", "Health", "resolved")]],
        [T + 6 * MINUTE, [notice("server-1", null, "resolved")]],
      ]),
    ).toHaveLength(1);
  });

  it("mails a check's first failure in an hour, not the ones after it", () => {
    const mails = run([
      [T, [notice("server-1", "Health")]],
      [T + 10 * MINUTE, [notice("server-1", "Health")]],
      [
        T + 20 * MINUTE,
        [notice("server-1", "API"), notice("server-1", "Health")],
      ],
      [T + 61 * MINUTE, [notice("server-1", "Health")]],
    ]);
    expect(mails.map((mail) => [mail.at, mail.down])).toEqual([
      [T, ["Health"]],
      [T + 20 * MINUTE, ["API"]],
      [T + 61 * MINUTE, ["Health"]],
    ]);
  });

  it("starts empty when the stored box has an older shape", () => {
    expect(loadBox({ queue: [], held: 2 } as never)).toEqual(emptyBox());
    expect(loadBox(undefined)).toEqual(emptyBox());
  });
});
