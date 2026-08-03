import { describe, expect, it } from "vitest";
import type { TrpcContext } from "./_core/context";
import { appRouter } from "./routers";

describe("checks router access control", () => {
  it("rejects unauthenticated access before reading protected data", async () => {
    const ctx: TrpcContext = {
      user: null,
      req: { protocol: "https", headers: {} } as TrpcContext["req"],
      res: {} as TrpcContext["res"],
    };
    const caller = appRouter.createCaller(ctx);
    await expect(caller.checks.sessions()).rejects.toMatchObject({ code: "UNAUTHORIZED" });
  });
});

