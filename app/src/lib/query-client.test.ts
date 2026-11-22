import { ApiError } from "./http";
import { describe, expect, it } from "vitest";

import { createQueryClient, queryKeys } from "./query-client";

describe("createQueryClient", () => {
  it("rechecks the session when a query is refused", async () => {
    const client = createQueryClient();
    client.setQueryData(queryKeys.session, { authenticated: true });
    await client
      .fetchQuery({
        queryKey: ["overview"],
        queryFn: () => Promise.reject(new ApiError("signed out", 401)),
        retry: false,
      })
      .catch(() => undefined);
    expect(client.getQueryState(queryKeys.session)?.isInvalidated).toBe(true);
  });

  it("leaves the session alone on other failures", async () => {
    const client = createQueryClient();
    client.setQueryData(queryKeys.session, { authenticated: true });
    await client
      .fetchQuery({
        queryKey: ["overview"],
        queryFn: () => Promise.reject(new ApiError("broken", 500)),
        retry: false,
      })
      .catch(() => undefined);
    expect(client.getQueryState(queryKeys.session)?.isInvalidated).toBe(false);
  });
});
