import type { Request } from "express";
import type { User } from "../drizzle/schema";
import { getUserByOpenId, upsertUser } from "./db";

export const LOCAL_DEVELOPMENT_OPEN_ID = "local-development-user";

type LocalRequest = Pick<Request, "headers" | "socket">;

function hostnameFromHeader(hostHeader: string) {
  const value = hostHeader.split(",", 1)[0]!.trim().toLowerCase();
  if (value.startsWith("[")) {
    const closingBracket = value.indexOf("]");
    return closingBracket > 0 ? value.slice(1, closingBracket) : value;
  }
  return value.split(":", 1)[0] || "";
}

export function isLoopbackHostname(hostname: string) {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1";
}

export function isLoopbackAddress(address: string | undefined) {
  return address === "127.0.0.1" || address === "::1" || address === "::ffff:127.0.0.1";
}

export function isLocalDevelopmentRequest(
  request: LocalRequest,
  nodeEnv = process.env.NODE_ENV,
) {
  if (nodeEnv !== "development") return false;

  const hostHeader = request.headers.host;
  if (!hostHeader || Array.isArray(hostHeader)) return false;

  return (
    isLoopbackHostname(hostnameFromHeader(hostHeader)) &&
    isLoopbackAddress(request.socket.remoteAddress)
  );
}

let localUserPromise: Promise<User | null> | null = null;

export function getLocalDevelopmentUser() {
  if (!localUserPromise) {
    localUserPromise = (async () => {
      await upsertUser({
        openId: LOCAL_DEVELOPMENT_OPEN_ID,
        name: "Développeur local",
        email: "local@localhost",
        loginMethod: "local-development",
        role: "admin",
        lastSignedIn: new Date(),
      });
      return (await getUserByOpenId(LOCAL_DEVELOPMENT_OPEN_ID)) ?? null;
    })().catch(error => {
      localUserPromise = null;
      throw error;
    });
  }
  return localUserPromise;
}
