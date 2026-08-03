import { TRPCError } from "@trpc/server";
import { z } from "zod";
import * as db from "../db";
import { protectedProcedure, router } from "../_core/trpc";
import { checkSendGridKey, sendTestEmail } from "../sendgrid/client";
import { decryptSecret, encryptSecret, maskApiKey, maskProxy } from "../sendgrid/crypto";
import { clampExecutionSettings, parseApiKeys, parseProxies } from "../sendgrid/parsers";

const MAX_KEYS_PER_SESSION = 5_000;
const sleep = (milliseconds: number) => new Promise(resolve => setTimeout(resolve, milliseconds));

const sessionIdInput = z.object({ sessionId: z.number().int().positive() });

async function requireOwnedSession(userId: number, sessionId: number) {
  const session = await db.getOwnedSession(userId, sessionId);
  if (!session) throw new TRPCError({ code: "NOT_FOUND", message: "Session introuvable" });
  return session;
}

export const checksRouter = router({
  dashboard: protectedProcedure.query(({ ctx }) => db.getDashboardStats(ctx.user.id)),

  sessions: protectedProcedure.query(({ ctx }) => db.listCheckSessions(ctx.user.id)),

  create: protectedProcedure
    .input(z.object({
      name: z.string().trim().min(1).max(120),
      keyContent: z.string().min(1).max(2_000_000),
      proxyContent: z.string().max(1_000_000).default(""),
      concurrency: z.number().int(),
      rateLimitPerMinute: z.number().int(),
      useProxies: z.boolean(),
    }))
    .mutation(async ({ ctx, input }) => {
      const parsedKeys = parseApiKeys(input.keyContent);
      if (!parsedKeys.values.length) {
        throw new TRPCError({ code: "BAD_REQUEST", message: "Aucune clé au format exploitable" });
      }
      if (parsedKeys.values.length > MAX_KEYS_PER_SESSION) {
        throw new TRPCError({ code: "BAD_REQUEST", message: `Maximum ${MAX_KEYS_PER_SESSION} clés par session` });
      }

      const parsedProxies = parseProxies(input.proxyContent);
      if (input.useProxies && !parsedProxies.values.length) {
        throw new TRPCError({ code: "BAD_REQUEST", message: "Activez les proxys uniquement après avoir importé au moins un proxy valide" });
      }
      const settings = clampExecutionSettings(input.concurrency, input.rateLimitPerMinute);
      const sessionId = await db.createCheckSession({
        userId: ctx.user.id,
        name: input.name,
        ...settings,
        useProxies: input.useProxies,
        keys: parsedKeys.values.map(value => ({ ...encryptSecret(value), maskedKey: maskApiKey(value) })),
        proxies: parsedProxies.values.map(value => ({ ...encryptSecret(value), maskedProxy: maskProxy(value) })),
      });

      return {
        sessionId,
        importedKeys: parsedKeys.values.length,
        duplicateKeys: parsedKeys.duplicates,
        rejectedKeys: parsedKeys.rejected,
        importedProxies: parsedProxies.values.length,
        duplicateProxies: parsedProxies.duplicates,
        rejectedProxies: parsedProxies.rejected,
      };
    }),

  progress: protectedProcedure.input(sessionIdInput).query(async ({ ctx, input }) => {
    return requireOwnedSession(ctx.user.id, input.sessionId);
  }),

  results: protectedProcedure
    .input(z.object({
      sessionId: z.number().int().positive(),
      page: z.number().int().min(1).default(1),
      pageSize: z.number().int().min(25).max(200).default(100),
      filter: z.enum(["all", "valid", "invalid", "free", "errors"]).default("all"),
      search: z.string().trim().max(80).default(""),
    }))
    .query(async ({ ctx, input }) => {
      await requireOwnedSession(ctx.user.id, input.sessionId);
      return db.listSessionResults({ userId: ctx.user.id, ...input });
    }),

  processChunk: protectedProcedure.input(sessionIdInput).mutation(async ({ ctx, input }) => {
    const session = await requireOwnedSession(ctx.user.id, input.sessionId);
    if (["completed", "cancelled", "failed"].includes(session.status)) return session;
    await db.markSessionProcessing(ctx.user.id, input.sessionId);
    const pending = await db.getPendingResults(ctx.user.id, input.sessionId, session.concurrency);
    if (!pending.length) return db.refreshSessionCounters(ctx.user.id, input.sessionId);
    const proxies = session.useProxies ? await db.getSessionProxies(ctx.user.id, input.sessionId) : [];
    const spacing = Math.ceil(60_000 / session.rateLimitPerMinute);

    await Promise.all(pending.map(async (row, index) => {
      if (index > 0) await sleep(index * spacing);
      const proxyRow = proxies.length ? proxies[Math.floor(Math.random() * proxies.length)] : null;
      let proxy: string | null = null;
      try {
        const apiKey = decryptSecret({ cipher: row.apiKeyCipher, iv: row.apiKeyIv, tag: row.apiKeyTag });
        if (proxyRow) {
          proxy = decryptSecret({ cipher: proxyRow.proxyCipher, iv: proxyRow.proxyIv, tag: proxyRow.proxyTag });
        }
        const result = await checkSendGridKey(apiKey, proxy);
        await db.updateCheckResult(row.id, ctx.user.id, {
          ...result,
          domainsJson: JSON.stringify(result.domains),
          proxyMasked: proxyRow?.maskedProxy || null,
        });
        await db.refreshSessionCounters(ctx.user.id, input.sessionId);
      } catch {
        await db.updateCheckResult(row.id, ctx.user.id, {
          status: "failed",
          creditLimit: null,
          usedCredits: null,
          resetFrequency: null,
          fromEmail: null,
          domainsJson: "[]",
          proxyMasked: proxyRow?.maskedProxy || null,
          providerStatus: null,
          errorMessage: "Échec interne sécurisé pendant la vérification",
        });
        await db.refreshSessionCounters(ctx.user.id, input.sessionId);
      }
    }));

    await sleep(spacing);
    return db.refreshSessionCounters(ctx.user.id, input.sessionId);
  }),

  exportValid: protectedProcedure.input(sessionIdInput).mutation(async ({ ctx, input }) => {
    await requireOwnedSession(ctx.user.id, input.sessionId);
    const results = await db.getValidResultsForExport(ctx.user.id, input.sessionId);
    const content = results.map(row => {
      const key = decryptSecret({ cipher: row.apiKeyCipher, iv: row.apiKeyIv, tag: row.apiKeyTag });
      return [
        `APIKEY: ${key}`,
        `Limit: ${row.creditLimit ?? 0}`,
        `Used: ${row.usedCredits ?? 0}`,
        `Reset: ${row.resetFrequency || "N/A"}`,
        `From: ${row.fromEmail || "None"}`,
        `Status: ${row.status === "free" ? "Free Plan" : "Valid"}`,
      ].join("\n");
    }).join("\n\n");
    return { content, count: results.length };
  }),

  sendOptions: protectedProcedure.query(({ ctx }) => db.listValidSendOptions(ctx.user.id)),

  sendTest: protectedProcedure
    .input(z.object({
      resultId: z.number().int().positive(),
      recipient: z.string().email().max(320),
      subject: z.string().trim().min(1).max(200),
      body: z.string().trim().min(1).max(20_000),
      confirmAuthorizedRecipient: z.literal(true),
    }))
    .mutation(async ({ ctx, input }) => {
      const recent = await db.countRecentTestSends(ctx.user.id, Date.now() - 60 * 60 * 1000);
      if (recent >= 10) throw new TRPCError({ code: "TOO_MANY_REQUESTS", message: "Limite de 10 envois de test par heure atteinte" });
      const owned = await db.getOwnedResult(ctx.user.id, input.resultId);
      if (!owned || !["valid", "free"].includes(owned.result.status)) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Clé valide introuvable" });
      }
      if (!owned.result.fromEmail || !owned.result.fromEmail.includes("@") || owned.result.fromEmail.startsWith("@")) {
        throw new TRPCError({ code: "BAD_REQUEST", message: "Aucun alias expéditeur complet n’est disponible pour cette clé" });
      }
      const apiKey = decryptSecret({ cipher: owned.result.apiKeyCipher, iv: owned.result.apiKeyIv, tag: owned.result.apiKeyTag });
      const proxies = owned.session.useProxies ? await db.getSessionProxies(ctx.user.id, owned.session.id) : [];
      const proxyRow = proxies.length ? proxies[Math.floor(Math.random() * proxies.length)] : null;
      const proxy = proxyRow ? decryptSecret({ cipher: proxyRow.proxyCipher, iv: proxyRow.proxyIv, tag: proxyRow.proxyTag }) : null;
      const result = await sendTestEmail({ apiKey, from: owned.result.fromEmail, to: input.recipient, subject: input.subject, body: input.body, proxy });
      await db.createTestSendLog({
        userId: ctx.user.id,
        resultId: input.resultId,
        recipient: input.recipient,
        subject: input.subject,
        status: result.success ? "sent" : "failed",
        providerStatus: result.providerStatus,
        errorMessage: result.errorMessage,
      });
      if (!result.success) throw new TRPCError({ code: "BAD_REQUEST", message: result.errorMessage || "Envoi refusé par SendGrid" });
      return { success: true, providerStatus: result.providerStatus };
    }),
});
