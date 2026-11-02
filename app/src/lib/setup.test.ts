import { describe, expect, it } from "vitest";

import type { NodeRecord } from "../types";
import { opensServer, setupView } from "./setup";

const NOW = Date.parse("2026-11-02T10:00:00Z");
const ago = (minutes: number) => new Date(NOW - minutes * 60_000).toISOString();

const server = (extra: Partial<NodeRecord> = {}) =>
  ({
    enrolled_at: ago(30),
    last_seen_at: ago(0),
    setup: null,
    warnings: [],
    ...extra,
  }) as NodeRecord;

describe("setupView", () => {
  it("names each step and counts it", () => {
    const labels = {
      admin: "Adding Admin User",
      upgrade: "Updating Packages",
      protections: "Turning On Protections",
      selinux: "Turning On SELinux",
      apparmor: "Turning On AppArmor",
      docker: "Installing Docker",
      network: "Preparing Private Network",
      restart: "Restarting",
    } as const;
    for (const [phase, label] of Object.entries(labels)) {
      expect(
        setupView(
          server({
            setup: { phase: phase as keyof typeof labels, step: 2, of: 6 },
          }),
          NOW,
        ),
      ).toEqual({ label, step: 2, of: 6, stopped: false });
    }
  });

  it("says where a setup stopped", () => {
    expect(
      setupView(
        server({ setup: { phase: "upgrade", step: 2, of: 6, stopped: true } }),
        NOW,
      ),
    ).toEqual({ label: "Updating Packages", step: 2, of: 6, stopped: true });
  });

  it("shows a server that enrolled but has not reported yet as starting, for ten minutes", () => {
    const fresh = server({ enrolled_at: ago(2), last_seen_at: null });
    expect(setupView(fresh, NOW)).toEqual({
      label: "Starting",
      step: null,
      of: null,
      stopped: false,
    });
    expect(
      setupView(server({ enrolled_at: ago(11), last_seen_at: null }), NOW),
    ).toBeNull();
    expect(setupView(server(), NOW)).toBeNull();
  });
});

describe("opensServer", () => {
  it("keeps a server that is setting up closed, unless a warning waits on it", () => {
    const running = { phase: "upgrade" as const, step: 2, of: 6 };
    expect(opensServer(server(), NOW)).toBe(true);
    expect(opensServer(server({ setup: running }), NOW)).toBe(false);
    expect(
      opensServer(server({ enrolled_at: ago(1), last_seen_at: null }), NOW),
    ).toBe(false);
    expect(
      opensServer(server({ setup: { ...running, stopped: true } }), NOW),
    ).toBe(true);
    expect(
      opensServer(
        server({
          setup: running,
          warnings: [
            { id: "w1", kind: "sudo", detail: {}, at: ago(1), cutAt: null },
          ],
        }),
        NOW,
      ),
    ).toBe(true);
  });
});
