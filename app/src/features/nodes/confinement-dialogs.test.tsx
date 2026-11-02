import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { BooleanFields } from "./confinement-dialogs";

const none = () => {};

const text = (html: string) =>
  html
    .replace(/<[^>]+>/gu, " ")
    .replace(/\s+/gu, " ")
    .trim();

describe("Change Boolean", () => {
  it("takes the boolean's name and On or Off", () => {
    const html = renderToStaticMarkup(
      <BooleanFields
        name="httpd_can_network_connect"
        on
        onName={none}
        onOn={none}
      />,
    );
    expect(text(html)).toBe("Boolean Set To On Off");
    expect(html).toContain('value="httpd_can_network_connect"');
    expect(html.match(/type="radio"/gu)).toHaveLength(2);
    expect(html).toContain('checked=""/>On');
    expect(
      renderToStaticMarkup(
        <BooleanFields name="" on={false} onName={none} onOn={none} />,
      ),
    ).toContain('checked=""/>Off');
  });

  it("says what a boolean's name may hold", () => {
    const html = renderToStaticMarkup(
      <BooleanFields name="Bad;name" on onName={none} onOn={none} />,
    );
    expect(text(html)).toContain(
      "A boolean is lowercase letters, digits and _, like httpd_can_network_connect.",
    );
  });
});
