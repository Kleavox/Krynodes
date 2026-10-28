import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { Busy, Waiting } from "./busy";

describe("busy text", () => {
  it("shows the word with three moving dots that screen readers skip", () => {
    const html = renderToStaticMarkup(<Busy>Saving</Busy>);
    expect(html).toContain("Saving");
    expect(html).not.toContain("…");
    expect(html.match(/animate-busy-\d/gu)).toEqual([
      "animate-busy-1",
      "animate-busy-2",
      "animate-busy-3",
    ]);
    expect(html).toMatch(
      /<span aria-hidden="true"[^>]*><span class="animate-busy-1">/u,
    );
  });

  it("says Waiting and reads it out as waiting for your passkey", () => {
    const html = renderToStaticMarkup(<Waiting />);
    expect(html).toContain('<span aria-hidden="true">Waiting</span>');
    expect(html).toContain(
      '<span class="sr-only">Waiting for your passkey</span>',
    );
  });

  it("ends a text that runs on with the moving dots", () => {
    const html = renderToStaticMarkup(<Busy>{"Restarting…"}</Busy>);
    expect(html).toContain("Restarting<");
    expect(html).not.toContain("…");
  });
});
