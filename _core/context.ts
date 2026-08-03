import type { CreateExpressContextOptions } from "@trpc/server/adapters/express";
import type { User } from "../../drizzle/schema";
import { getLocalDevelopmentUser, isLocalDevelopmentRequest } from "../localAuth";
import { sdk } from "./sdk";

export type TrpcContext = {
  req: CreateExpressContextOptions["req"];
  res: CreateExpressContextOptions["res"];
  user: User | null;
};

export async function createContext(
  opts: CreateExpressContextOptions
): Promise<TrpcContext> {
  let user: User | null = null;

  if (isLocalDevelopmentRequest(opts.req)) {
    try {
      user = await getLocalDevelopmentUser();
    } catch (error) {
      console.error("[Local Auth] Unable to create the local development user:", error);
    }

    return {
      req: opts.req,
      res: opts.res,
      user,
    };
  }

  try {
    user = await sdk.authenticateRequest(opts.req);
  } catch (error) {
    // Authentication is optional for public procedures.
    user = null;
  }

  return {
    req: opts.req,
    res: opts.res,
    user,
  };
}
