import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { LaptopCodeSheet } from "./laptops";

describe("adding a laptop", () => {
  it("downloads the agent of the release the Worker pinned", () => {
    const html = renderToStaticMarkup(
      <LaptopCodeSheet
        code={{
          code: "code-1",
          expiresAt: "2026-11-22T11:00:00Z",
          origin: "https://kry.example.test",
          endpoint: "https://kry.example.test",
          download:
            "https://example.test/releases/download/agent-v0.7.92/krynodes-windows-amd64.exe",
        }}
      />,
    );
    expect(html).toContain(
      'href="https://example.test/releases/download/agent-v0.7.92/krynodes-windows-amd64.exe"',
    );
    expect(html).toContain("install --code code-1");
    expect(html).toContain("Copy Command");
  });
});
