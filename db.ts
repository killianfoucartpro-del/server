import { and, count, desc, eq, gte, inArray, like, or, sql } from "drizzle-orm";
import { drizzle } from "drizzle-orm/mysql2";
import {
  checkResults,
  checkSessions,
  InsertUser,
  sessionProxies,
  testSendLogs,
  users,
} from "../drizzle/schema";
import { ENV } from './_core/env';
import type { EncryptedSecret } from "./sendgrid/crypto";

let _db: ReturnType<typeof drizzle> | null = null;

// Lazily create the drizzle instance so local tooling can run without a DB.
export async function getDb() {
  if (!_db && process.env.DATABASE_URL) {
    try {
      _db = drizzle(process.env.DATABASE_URL);
    } catch (error) {
      console.warn("[Database] Failed to connect:", error);
      _db = null;
    }
  }
  return _db;
}

export async function upsertUser(user: InsertUser): Promise<void> {
  if (!user.openId) {
    throw new Error("User openId is required for upsert");
  }

  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot upsert user: database not available");
    return;
  }

  try {
    const values: InsertUser = {
      openId: user.openId,
    };
    const updateSet: Record<string, unknown> = {};

    const textFields = ["name", "email", "loginMethod"] as const;
    type TextField = (typeof textFields)[number];

    const assignNullable = (field: TextField) => {
      const value = user[field];
      if (value === undefined) return;
      const normalized = value ?? null;
      values[field] = normalized;
      updateSet[field] = normalized;
    };

    textFields.forEach(assignNullable);

    if (user.lastSignedIn !== undefined) {
      values.lastSignedIn = user.lastSignedIn;
      updateSet.lastSignedIn = user.lastSignedIn;
    }
    if (user.role !== undefined) {
      values.role = user.role;
      updateSet.role = user.role;
    } else if (user.openId === ENV.ownerOpenId) {
      values.role = 'admin';
      updateSet.role = 'admin';
    }

    if (!values.lastSignedIn) {
      values.lastSignedIn = new Date();
    }

    if (Object.keys(updateSet).length === 0) {
      updateSet.lastSignedIn = new Date();
    }

    await db.insert(users).values(values).onDuplicateKeyUpdate({
      set: updateSet,
    });
  } catch (error) {
    console.error("[Database] Failed to upsert user:", error);
    throw error;
  }
}

export async function getUserByOpenId(openId: string) {
  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot get user: database not available");
    return undefined;
  }

  const result = await db.select().from(users).where(eq(users.openId, openId)).limit(1);

  return result.length > 0 ? result[0] : undefined;
}

export type NewEncryptedResult = EncryptedSecret & { maskedKey: string };
export type NewEncryptedProxy = EncryptedSecret & { maskedProxy: string };

export async function createCheckSession(input: {
  userId: number;
  name: string;
  concurrency: number;
  rateLimitPerMinute: number;
  useProxies: boolean;
  keys: NewEncryptedResult[];
  proxies: NewEncryptedProxy[];
}) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  const now = Date.now();

  return db.transaction(async tx => {
    const inserted = await tx
      .insert(checkSessions)
      .values({
        userId: input.userId,
        name: input.name,
        totalKeys: input.keys.length,
        concurrency: input.concurrency,
        rateLimitPerMinute: input.rateLimitPerMinute,
        useProxies: input.useProxies && input.proxies.length > 0,
        proxyCount: input.proxies.length,
        createdAt: now,
      })
      .$returningId();
    const sessionId = inserted[0]!.id;

    for (let index = 0; index < input.keys.length; index += 500) {
      await tx.insert(checkResults).values(
        input.keys.slice(index, index + 500).map(key => ({
          sessionId,
          userId: input.userId,
          apiKeyCipher: key.cipher,
          apiKeyIv: key.iv,
          apiKeyTag: key.tag,
          maskedKey: key.maskedKey,
          createdAt: now,
        })),
      );
    }

    if (input.proxies.length) {
      await tx.insert(sessionProxies).values(
        input.proxies.map(proxy => ({
          sessionId,
          userId: input.userId,
          proxyCipher: proxy.cipher,
          proxyIv: proxy.iv,
          proxyTag: proxy.tag,
          maskedProxy: proxy.maskedProxy,
          createdAt: now,
        })),
      );
    }

    return sessionId;
  });
}

export async function listCheckSessions(userId: number) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return db.select().from(checkSessions).where(eq(checkSessions.userId, userId)).orderBy(desc(checkSessions.createdAt)).limit(50);
}

export async function getOwnedSession(userId: number, sessionId: number) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return (await db.select().from(checkSessions).where(and(eq(checkSessions.id, sessionId), eq(checkSessions.userId, userId))).limit(1))[0];
}

export async function listSessionResults(input: {
  userId: number;
  sessionId: number;
  page: number;
  pageSize: number;
  filter?: "all" | "valid" | "invalid" | "free" | "errors";
  search?: string;
}) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  const conditions = [eq(checkResults.userId, input.userId), eq(checkResults.sessionId, input.sessionId)];
  if (input.filter === "valid") conditions.push(eq(checkResults.status, "valid"));
  if (input.filter === "invalid") conditions.push(eq(checkResults.status, "invalid"));
  if (input.filter === "free") conditions.push(eq(checkResults.status, "free"));
  if (input.filter === "errors") conditions.push(inArray(checkResults.status, ["network_error", "failed"]));
  if (input.search) conditions.push(like(checkResults.maskedKey, `%${input.search}%`));
  const where = and(...conditions);
  const rows = await db
    .select({
      id: checkResults.id,
      maskedKey: checkResults.maskedKey,
      status: checkResults.status,
      creditLimit: checkResults.creditLimit,
      usedCredits: checkResults.usedCredits,
      resetFrequency: checkResults.resetFrequency,
      fromEmail: checkResults.fromEmail,
      proxyMasked: checkResults.proxyMasked,
      errorMessage: checkResults.errorMessage,
      checkedAt: checkResults.checkedAt,
    })
    .from(checkResults)
    .where(where)
    .orderBy(checkResults.id)
    .limit(input.pageSize)
    .offset((input.page - 1) * input.pageSize);
  const total = (await db.select({ value: count() }).from(checkResults).where(where))[0]?.value || 0;
  return { rows, total };
}

export async function getPendingResults(userId: number, sessionId: number, limit: number) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return db
    .select()
    .from(checkResults)
    .where(and(eq(checkResults.userId, userId), eq(checkResults.sessionId, sessionId), eq(checkResults.status, "pending")))
    .orderBy(checkResults.id)
    .limit(limit);
}

export async function getSessionProxies(userId: number, sessionId: number) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return db
    .select()
    .from(sessionProxies)
    .where(and(eq(sessionProxies.userId, userId), eq(sessionProxies.sessionId, sessionId), eq(sessionProxies.active, true)));
}

export async function markSessionProcessing(userId: number, sessionId: number) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  await db
    .update(checkSessions)
    .set({ status: "processing", startedAt: Date.now() })
    .where(and(eq(checkSessions.id, sessionId), eq(checkSessions.userId, userId), eq(checkSessions.status, "pending")));
}

export async function updateCheckResult(resultId: number, userId: number, data: {
  status: "valid" | "invalid" | "free" | "network_error" | "failed";
  creditLimit: number | null;
  usedCredits: number | null;
  resetFrequency: string | null;
  fromEmail: string | null;
  domainsJson: string;
  proxyMasked: string | null;
  providerStatus: number | null;
  errorMessage: string | null;
}) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  await db.update(checkResults).set({ ...data, checkedAt: Date.now() }).where(and(eq(checkResults.id, resultId), eq(checkResults.userId, userId)));
}

export async function refreshSessionCounters(userId: number, sessionId: number) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  const summary = (await db
    .select({
      processed: sql<number>`SUM(CASE WHEN ${checkResults.status} <> 'pending' THEN 1 ELSE 0 END)`,
      valid: sql<number>`SUM(CASE WHEN ${checkResults.status} = 'valid' THEN 1 ELSE 0 END)`,
      invalid: sql<number>`SUM(CASE WHEN ${checkResults.status} = 'invalid' THEN 1 ELSE 0 END)`,
      free: sql<number>`SUM(CASE WHEN ${checkResults.status} = 'free' THEN 1 ELSE 0 END)`,
      errors: sql<number>`SUM(CASE WHEN ${checkResults.status} IN ('network_error','failed') THEN 1 ELSE 0 END)`,
      pending: sql<number>`SUM(CASE WHEN ${checkResults.status} = 'pending' THEN 1 ELSE 0 END)`,
    })
    .from(checkResults)
    .where(and(eq(checkResults.userId, userId), eq(checkResults.sessionId, sessionId))))[0];
  const pending = Number(summary?.pending || 0);
  await db
    .update(checkSessions)
    .set({
      processedKeys: Number(summary?.processed || 0),
      validKeys: Number(summary?.valid || 0),
      invalidKeys: Number(summary?.invalid || 0),
      freeKeys: Number(summary?.free || 0),
      errorKeys: Number(summary?.errors || 0),
      ...(pending === 0 ? { status: "completed" as const, completedAt: Date.now() } : {}),
    })
    .where(and(eq(checkSessions.id, sessionId), eq(checkSessions.userId, userId)));
  return getOwnedSession(userId, sessionId);
}

export async function getDashboardStats(userId: number) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  const sessions = (await db
    .select({
      sessions: count(),
      total: sql<number>`COALESCE(SUM(${checkSessions.totalKeys}), 0)`,
      processed: sql<number>`COALESCE(SUM(${checkSessions.processedKeys}), 0)`,
      valid: sql<number>`COALESCE(SUM(${checkSessions.validKeys}), 0)`,
      free: sql<number>`COALESCE(SUM(${checkSessions.freeKeys}), 0)`,
    })
    .from(checkSessions)
    .where(eq(checkSessions.userId, userId)))[0];
  const credits = (await db
    .select({ available: sql<number>`COALESCE(SUM(GREATEST(COALESCE(${checkResults.creditLimit},0) - COALESCE(${checkResults.usedCredits},0), 0)), 0)` })
    .from(checkResults)
    .where(and(eq(checkResults.userId, userId), inArray(checkResults.status, ["valid", "free"]))))[0];
  const processed = Number(sessions?.processed || 0);
  const successful = Number(sessions?.valid || 0) + Number(sessions?.free || 0);
  return {
    sessionCount: Number(sessions?.sessions || 0),
    totalKeys: Number(sessions?.total || 0),
    processedKeys: processed,
    successRate: processed ? (successful / processed) * 100 : 0,
    availableCredits: Number(credits?.available || 0),
  };
}

export async function getValidResultsForExport(userId: number, sessionId: number) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return db
    .select()
    .from(checkResults)
    .where(and(eq(checkResults.userId, userId), eq(checkResults.sessionId, sessionId), inArray(checkResults.status, ["valid", "free"])))
    .orderBy(checkResults.id);
}

export async function listValidSendOptions(userId: number) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return db
    .select({
      id: checkResults.id,
      maskedKey: checkResults.maskedKey,
      fromEmail: checkResults.fromEmail,
      status: checkResults.status,
      sessionName: checkSessions.name,
    })
    .from(checkResults)
    .innerJoin(checkSessions, eq(checkResults.sessionId, checkSessions.id))
    .where(and(eq(checkResults.userId, userId), inArray(checkResults.status, ["valid", "free"])))
    .orderBy(desc(checkResults.checkedAt))
    .limit(250);
}

export async function getOwnedResult(userId: number, resultId: number) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return (await db
    .select({ result: checkResults, session: checkSessions })
    .from(checkResults)
    .innerJoin(checkSessions, eq(checkResults.sessionId, checkSessions.id))
    .where(and(eq(checkResults.userId, userId), eq(checkResults.id, resultId)))
    .limit(1))[0];
}

export async function countRecentTestSends(userId: number, since: number) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return Number((await db.select({ value: count() }).from(testSendLogs).where(and(eq(testSendLogs.userId, userId), gte(testSendLogs.createdAt, since))))[0]?.value || 0);
}

export async function createTestSendLog(input: {
  userId: number;
  resultId: number;
  recipient: string;
  subject: string;
  status: "sent" | "failed";
  providerStatus: number | null;
  errorMessage: string | null;
}) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  await db.insert(testSendLogs).values({ ...input, createdAt: Date.now() });
}
