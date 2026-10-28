import { afterEach, describe, expect, it, vi } from "vitest";

const openSession = vi.fn();
const signIntent = vi.fn();

vi.mock("./deploy-session", () => ({ openSession }));
vi.mock("./passkeys", () => ({ signIntent }));

const { failure, guardedFetch } = await import("./proof");

const NEEDED = {
  code: "PROOF_NEEDED",
  message: "Confirm with the passkey of a trusted device.",
  op: "node.delete",
  target: "n1",
  core: ["phone"],
};

function replies(...answers: [number, unknown][]) {
  const calls: RequestInit[] = [];
  vi.stubGlobal("window", { location: { origin: "https://kry.example.test" } });
  vi.stubGlobal("fetch", (_path: string, init: RequestInit) => {
    calls.push(init);
    const [status, body] = answers[calls.length - 1]!;
    return Promise.resolve(
      status === 204
        ? new Response(null, { status })
        : new Response(JSON.stringify(body), { status }),
    );
  });
  return calls;
}

afterEach(() => {
  vi.unstubAllGlobals();
  openSession.mockReset();
  signIntent.mockReset();
});

describe("guardedFetch", () => {
  it("asks for the passkey only when the Worker says so, then sends the proof", async () => {
    const calls = replies([403, NEEDED], [204, null]);
    openSession.mockResolvedValue({ grant: {} });
    signIntent.mockResolvedValue("signed-intent");
    await guardedFetch("/api/nodes/n1", { method: "DELETE" });
    expect(openSession).toHaveBeenCalledWith(["phone"]);
    expect(signIntent).toHaveBeenCalledWith(
      { grant: {} },
      "node.delete",
      "n1",
      "https://kry.example.test",
    );
    expect(calls).toHaveLength(2);
    expect((calls[1]!.headers as Record<string, string>)["x-kry-proof"]).toBe(
      "signed-intent",
    );
  });

  it("refuses to sign what the dashboard did not ask to confirm", async () => {
    const calls = replies([
      403,
      { ...NEEDED, op: "enroll.admin", target: "aa".repeat(32) },
    ]);
    await expect(
      guardedFetch(
        "/api/settings/enroll-defaults",
        { method: "PUT" },
        { op: "enroll.admin", target: "bb".repeat(32) },
      ),
    ).rejects.toThrow(
      "Krynodes asked to confirm something else. Nothing was saved.",
    );
    expect(openSession).not.toHaveBeenCalled();
    expect(calls).toHaveLength(1);
  });

  it("signs what the dashboard expects", async () => {
    const target = "aa".repeat(32);
    const calls = replies(
      [403, { ...NEEDED, op: "enroll.admin", target }],
      [200, {}],
    );
    openSession.mockResolvedValue({ grant: {} });
    signIntent.mockResolvedValue("signed-intent");
    await guardedFetch(
      "/api/settings/enroll-defaults",
      { method: "PUT" },
      { op: "enroll.admin", target },
    );
    expect(calls).toHaveLength(2);
  });

  it("passes other refusals through without a prompt", async () => {
    const calls = replies([403, { code: "NOT_CORE", message: "No." }]);
    await expect(
      guardedFetch("/api/nodes/n1", { method: "DELETE" }),
    ).rejects.toThrow("No.");
    expect(openSession).not.toHaveBeenCalled();
    expect(calls).toHaveLength(1);
  });

  it("explains a cancelled fingerprint", async () => {
    replies([403, NEEDED]);
    openSession.mockRejectedValue(
      new DOMException("cancelled", "NotAllowedError"),
    );
    await expect(
      guardedFetch("/api/nodes/n1", { method: "DELETE" }),
    ).rejects.toThrow(/No fingerprint was confirmed/u);
  });
});

describe("failure", () => {
  it("says a passkey this browser already holds is registered", () => {
    expect(
      failure(new DOMException("previously registered", "InvalidStateError")),
    ).toBe("This device is already registered.");
  });

  it("points a cancelled or failed fingerprint to another way", () => {
    expect(failure(new DOMException("cancelled", "NotAllowedError"))).toMatch(
      /^No fingerprint was confirmed/u,
    );
  });
});
