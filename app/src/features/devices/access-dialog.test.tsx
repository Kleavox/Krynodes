import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { DeviceRecord } from "@/types";

import { DeviceFacts, Ticks } from "./access-dialog";

const none = () => {};

const phone: DeviceRecord = {
  id: "phone",
  name: "Phone",
  alg: -7,
  publicKey: "phone-key",
  createdAt: "2026-10-02T09:12:00.000Z",
  lastUsedAt: null,
  verifies: true,
  synced: false,
  fingerprint: "a1c9e04b7d2f3386",
  core: true,
  owner: "owner@example.test",
  mine: true,
};

describe("ticking servers or passkeys", () => {
  const ticks = [
    { key: "io", label: "io", checked: true, was: true },
    { key: "calisto", label: "calisto", checked: true, was: false },
    { key: "pivox", label: "pivox", checked: false, was: true },
  ];

  it("uses checkboxes, never switches", () => {
    const html = renderToStaticMarkup(<Ticks ticks={ticks} onTick={none} />);
    expect(html.match(/type="checkbox"/g)).toHaveLength(3);
    expect(html).not.toContain('role="switch"');
  });

  it("says what a changed row does", () => {
    const html = renderToStaticMarkup(<Ticks ticks={ticks} onTick={none} />);
    expect(html.match(/>Adds</g)).toHaveLength(1);
    expect(html.match(/>Removes</g)).toHaveLength(1);
    expect(html).not.toContain("Changed");
  });

  it("ticks All Servers only when every row is ticked", () => {
    const some = renderToStaticMarkup(
      <Ticks ticks={ticks} all="All Servers" onTick={none} onAll={none} />,
    );
    expect(some).toContain("All Servers");
    expect(some.match(/checked=""/g)).toHaveLength(2);
    const every = renderToStaticMarkup(
      <Ticks
        ticks={ticks.map((tick) => ({ ...tick, checked: true }))}
        all="All Servers"
        onTick={none}
        onAll={none}
      />,
    );
    expect(every.match(/checked=""/g)).toHaveLength(4);
  });
});

describe("a passkey's facts", () => {
  it("shows the fingerprint, where it is saved, and when it was used", () => {
    const html = renderToStaticMarkup(<DeviceFacts device={phone} />);
    expect(html).toContain("A1C9 E04B 7D2F 3386");
    expect(html).toContain("This Device Only");
    expect(html).toContain("Never Used");
    expect(html).not.toContain("Owner");
    expect(html).not.toContain("Can Sign");
  });

  it("names the owner of someone else's passkey", () => {
    const html = renderToStaticMarkup(
      <DeviceFacts device={{ ...phone, mine: false }} />,
    );
    expect(html).toContain("Owner");
    expect(html).toContain(">owner<");
    expect(
      renderToStaticMarkup(
        <DeviceFacts device={{ ...phone, mine: false, owner: null }} />,
      ),
    ).toContain("Not Claimed Yet");
  });
});
