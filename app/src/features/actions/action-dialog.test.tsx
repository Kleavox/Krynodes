import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { ActionRow } from "@/types";

import { ActionBody, type RunState } from "./action-dialog";

const row = (patch: Partial<ActionRow>): ActionRow => ({
  id: "a1",
  nodeId: "node-1",
  kind: "agent",
  name: "server-1",
  action: "update",
  title: "Update Agent to 0.8.1",
  status: "done",
  message: null,
  output: null,
  createdAt: "2026-11-22T10:00:00.000Z",
  finishedAt: null,
  ...patch,
});

const text = (state: RunState) =>
  renderToStaticMarkup(<ActionBody state={state} name="server-1" />).replace(
    /<[^>]+>/gu,
    " ",
  );

describe("the action dialog", () => {
  it("shows the progress lines in the order they came", () => {
    const shown = text({
      phase: "sending",
      lines: ["Downloading 0.8.1", "Verifying", "Restarting the agent"],
    });
    expect(shown).toMatch(
      /Downloading 0\.8\.1.*Verifying.*Restarting the agent/su,
    );
    expect(shown).toContain("Waiting for server-1");
  });

  it("shows the node's failure text as it came", () => {
    const shown = text({
      phase: "result",
      lines: [],
      row: row({
        status: "failed",
        message: "this server already runs 0.8.1",
      }),
    });
    expect(shown).toContain("this server already runs 0.8.1");
  });

  it("shows the node's answer when it is done", () => {
    expect(
      text({
        phase: "result",
        lines: [],
        row: row({ message: "Updated to 0.8.1." }),
      }),
    ).toContain("Updated to 0.8.1.");
  });

  it("shows a refusal from before the server was reached", () => {
    expect(
      text({ phase: "result", lines: [], error: "server-1 is offline." }),
    ).toContain("server-1 is offline.");
  });
});
