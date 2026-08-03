import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { TrpcContext } from "./_core/context";
import { encryptSecret } from "./sendgrid/crypto";

const dbMocks = vi.hoisted(() => ({
  getDashboardStats: vi.fn(),
  listCheckSessions: vi.fn(),
  createCheckSession: vi.fn(),
  getOwnedSession: vi.fn(),
  listSessionResults: vi.fn(),
  markSessionProcessing: vi.fn(),
  getPendingResults: vi.fn(),
  getSessionProxies: vi.fn(),
  refreshSessionCounters: vi.fn(),
  updateCheckResult: vi.fn(),
  getValidResultsForExport: vi.fn(),
  listValidSendOptions: vi.fn(),
  countRecentTestSends: vi.fn(),
  getOwnedResult: vi.fn(),
  createTestSendLog: vi.fn(),
}));

const clientMocks = vi.hoisted(() => ({
  checkSendGridKey: vi.fn(),
  sendTestEmail: vi.fn(),
}));

vi.mock("./db", () => dbMocks);
vi.mock("./sendgrid/client", () => clientMocks);

import { appRouter } from "./routers";

const user = {
  id: 7,
  openId: "owner-open-id",
  email: "owner@example.com",
  name: "Owner",
  loginMethod: "manus",
  role: "admin" as const,
  createdAt: new Date(),
  updatedAt: new Date(),
  lastSignedIn: new Date(),
};

function caller() {
  const ctx: TrpcContext = {
    user,
    req: { protocol: "https", headers: {} } as TrpcContext["req"],
    res: {} as TrpcContext["res"],
  };
  return appRouter.createCaller(ctx);
}

const ownedSession = {
  id: 42,
  userId: user.id,
  name: "Audit contrôlé",
  status: "pending" as const,
  totalKeys: 1,
  processedKeys: 0,
  validKeys: 0,
  invalidKeys: 0,
  freeKeys: 0,
  errorKeys: 0,
  concurrency: 4,
  rateLimitPerMinute: 60,
  useProxies: false,
  proxyCount: 0,
  createdAt: Date.now(),
  startedAt: null,
  completedAt: null,
};

describe("checks business procedures", () => {
  beforeAll(() => {
    process.env.JWT_SECRET = "procedure-test-secret-that-never-leaves-vitest";
  });

  beforeEach(() => {
    vi.clearAllMocks();
    dbMocks.getOwnedSession.mockResolvedValue(ownedSession);
    dbMocks.createCheckSession.mockResolvedValue(42);
    dbMocks.countRecentTestSends.mockResolvedValue(0);
    dbMocks.createTestSendLog.mockResolvedValue(undefined);
  });

  it("creates an owned encrypted session from deduplicated input", async () => {
    const key = "SG.procedure_test_payload_1234567890.second_part_1234567890";
    const result = await caller().checks.create({
      name: "Audit contrôlé",
      keyContent: `${key}\n${key}`,
      proxyContent: "",
      concurrency: 4,
      rateLimitPerMinute: 60,
      useProxies: false,
    });

    expect(result).toMatchObject({ sessionId: 42, importedKeys: 1, duplicateKeys: 1 });
    expect(dbMocks.createCheckSession).toHaveBeenCalledWith(expect.objectContaining({
      userId: user.id,
      name: "Audit contrôlé",
      keys: [expect.objectContaining({ maskedKey: expect.stringContaining("••") })],
    }));
    const persistedKey = dbMocks.createCheckSession.mock.calls[0][0].keys[0];
    expect(persistedKey.cipher).not.toContain(key);
  });

  it("returns progress only after ownership verification", async () => {
    const result = await caller().checks.progress({ sessionId: 42 });
    expect(result.id).toBe(42);
    expect(dbMocks.getOwnedSession).toHaveBeenCalledWith(user.id, 42);
  });

  it("exports valid credentials only for an owned session", async () => {
    const key = "SG.export_test_payload_1234567890.second_part_1234567890";
    const encrypted = encryptSecret(key);
    dbMocks.getValidResultsForExport.mockResolvedValue([{
      id: 1,
      sessionId: 42,
      userId: user.id,
      apiKeyCipher: encrypted.cipher,
      apiKeyIv: encrypted.iv,
      apiKeyTag: encrypted.tag,
      maskedKey: "SG.expo••••7890",
      status: "valid",
      creditLimit: 1000,
      usedCredits: 12,
      resetFrequency: "monthly",
      fromEmail: "ops@example.com",
      domainsJson: "[]",
      proxyMasked: null,
      providerStatus: 200,
      errorMessage: null,
      checkedAt: Date.now(),
      createdAt: Date.now(),
    }]);

    const result = await caller().checks.exportValid({ sessionId: 42 });
    expect(result.count).toBe(1);
    expect(result.content).toContain(`APIKEY: ${key}`);
    expect(result.content).toContain("Status: Valid");
  });

  it("enforces the hourly test-send limit", async () => {
    dbMocks.countRecentTestSends.mockResolvedValue(10);
    await expect(caller().checks.sendTest({
      resultId: 1,
      recipient: "recipient@example.com",
      subject: "Test",
      body: "Authorized test",
      confirmAuthorizedRecipient: true,
    })).rejects.toMatchObject({ code: "TOO_MANY_REQUESTS" });
    expect(clientMocks.sendTestEmail).not.toHaveBeenCalled();
  });

  it("requires a complete sender alias before sending", async () => {
    dbMocks.getOwnedResult.mockResolvedValue({
      result: { status: "valid", fromEmail: "@example.com" },
      session: ownedSession,
    });
    await expect(caller().checks.sendTest({
      resultId: 1,
      recipient: "recipient@example.com",
      subject: "Test",
      body: "Authorized test",
      confirmAuthorizedRecipient: true,
    })).rejects.toMatchObject({ code: "BAD_REQUEST" });
    expect(clientMocks.sendTestEmail).not.toHaveBeenCalled();
  });

  it("logs an accepted controlled test send", async () => {
    const encrypted = encryptSecret("SG.mail_test_payload_1234567890.second_part_1234567890");
    dbMocks.getOwnedResult.mockResolvedValue({
      result: {
        id: 9,
        status: "valid",
        fromEmail: "ops@example.com",
        apiKeyCipher: encrypted.cipher,
        apiKeyIv: encrypted.iv,
        apiKeyTag: encrypted.tag,
      },
      session: { ...ownedSession, id: 42, useProxies: false },
    });
    clientMocks.sendTestEmail.mockResolvedValue({ success: true, providerStatus: 202, errorMessage: null });

    const result = await caller().checks.sendTest({
      resultId: 9,
      recipient: "recipient@example.com",
      subject: "Test",
      body: "Authorized test",
      confirmAuthorizedRecipient: true,
    });
    expect(result).toEqual({ success: true, providerStatus: 202 });
    expect(dbMocks.createTestSendLog).toHaveBeenCalledWith(expect.objectContaining({
      userId: user.id,
      resultId: 9,
      status: "sent",
      providerStatus: 202,
    }));
  });
});
