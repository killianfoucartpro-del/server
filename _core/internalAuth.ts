import type { Request } from "express";

export function getInternalTokenFromReq(req: Request): string | null {
  const header = req.headers["x-internal-token"];
  if (!header) return null;
  return Array.isArray(header) ? header[0] : String(header);
}

export function isValidInternalToken(token: string | null): boolean {
  if (!token) return false;
  return token === process.env.INTERNAL_TOKEN;
}
