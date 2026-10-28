import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { ContainerNames, namesState, renameNote } from "./container-names";

const one = "services:\n  adguard:\n    image: adguard/adguardhome\n";
const three =
  "services:\n  broker:\n    image: redis:7\n  db:\n    image: postgres:17\n  webserver:\n    image: paperless\n";

const draw = (
  text: string,
  project: string,
  typed: Record<string, string> = {},
  taken: string[] = [],
) =>
  renderToStaticMarkup(
    <ContainerNames
      names={{
        ...namesState({ text, project, typed, taken, server: "io" }),
        type: () => {},
      }}
    />,
  );

describe("Container Names under a stack's name", () => {
  it("is not there until the compose file has a service", () => {
    expect(draw("", "uptime-kuma")).toBe("");
  });

  it("stays closed and shows the one name, or how many", () => {
    const single = draw(one, "adguard-home");
    expect(single).toContain("<details");
    expect(single).not.toMatch(/<details[^>]*\sopen/u);
    expect(single).toContain("Container Names");
    expect(single).toContain('value="adguard-home"');
    expect(draw(three, "paperless")).toContain("3 containers");
  });

  it("says which name to fix and why", () => {
    const markup = draw(three, "paperless", { db: "cloudflared" }, [
      "cloudflared",
    ]);
    expect(markup).toContain("1 to fix");
    expect(markup).toContain("io already runs a container named cloudflared.");
    expect(markup).toContain('aria-invalid="true"');
  });

  it("tells which containers a save renames and what they run as now", () => {
    const names = namesState({
      text: three,
      project: "paperless",
      saved: { db: "postgres" },
      typed: {},
      taken: [],
      server: "io",
      running: ["paperless-broker-1", "postgres", "paperless_webserver_1"],
    });
    expect(names.renamed).toBe(2);
    const words = renderToStaticMarkup(
      <ContainerNames names={{ ...names, type: () => {} }} />,
    )
      .replace(/<[^>]+>/gu, " ")
      .replace(/\s+/gu, " ");
    expect(words).toContain("2 to rename");
    expect(words).toContain("Now running as paperless-broker-1");
    expect(words).toContain("Now running as paperless_webserver_1");
    expect(words).not.toContain("Now running as postgres");
    expect(renameNote(names.renamed)).toBe(
      "Saving renames 2 containers; they restart.",
    );
    expect(renameNote(1)).toBe("Saving renames 1 container; it restarts.");
    expect(renameNote(0)).toBeNull();
  });

  it("renames nothing on a stack that runs nothing yet", () => {
    expect(
      namesState({
        text: three,
        project: "paperless",
        typed: {},
        taken: [],
        server: "io",
      }).renamed,
    ).toBe(0);
    expect(draw(three, "paperless")).not.toContain("running as");
  });

  it("sends every container's name to the server", () => {
    expect(
      namesState({
        text: three,
        project: "paperless",
        typed: { webserver: "paperless" },
        taken: [],
        server: "io",
      }).arg,
    ).toBe("broker=paperless-broker,db=paperless-db,webserver=paperless");
  });
});
