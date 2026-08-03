import { beforeEach, describe, expect, it, vi } from "vitest";

const sdkMocks = vi.hoisted(() => ({ authenticateRequest: vi.fn() }));
const localMocks = vi.hoisted(() => ({
  isLocalDevelopmentRequest: vi.fn(),
  getLocalDevelopmentUser: vi.fn(),
}));

vi.mock("./_core/sdk", () => ({ sdk: sdkMocks }));
vi.mock("./localAuth", () => localMocks);

import { createContext } from "./_core/context";

const localUser = {
  id: 99,
  openId: "local-development-user",
  name: "Développeur local",
  email: "local@localhost",
  loginMethod: "local-development",
  role: "admin" as const,
  createdAt: new Date(),
  updatedAt: new Date(),
  lastSignedIn: new Date(),
};

const oauthUser = {
  ...localUser,
  id: 7,
  openId: "oauth-user",
  name: "Utilisateur OAuth",
  email: "oauth@example.com",
  loginMethod: "manus",
  role: "user" as const,
};

function options() {
  return {
    req: { headers: { host: "localhost:3000" }, socket: { remoteAddress: "::1" } },
    res: {},
  } as Parameters<typeof createContext>[0];
}

describe("authentication order in the tRPC context", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("uses the local identity directly without verifying any OAuth/JWT cookie", async () => {
    localMocks.isLocalDevelopmentRequest.mockReturnValue(true);
    localMocks.getLocalDevelopmentUser.mockResolvedValue(localUser);
    sdkMocks.authenticateRequest.mockRejectedValue(new Error("stale cookie should never be read"));

    const context = await createContext(options());

    expect(context.user).toEqual(localUser);
    expect(localMocks.getLocalDevelopmentUser).toHaveBeenCalledOnce();
    expect(sdkMocks.authenticateRequest).not.toHaveBeenCalled();
  });

  it("keeps OAuth authentication for non-local requests", async () => {
    localMocks.isLocalDevelopmentRequest.mockReturnValue(false);
    sdkMocks.authenticateRequest.mockResolvedValue(oauthUser);

    const context = await createContext(options());

    expect(context.user).toEqual(oauthUser);
    expect(sdkMocks.authenticateRequest).toHaveBeenCalledOnce();
    expect(localMocks.getLocalDevelopmentUser).not.toHaveBeenCalled();
  });

  it("never falls back to OAuth when local database initialization fails", async () => {
    localMocks.isLocalDevelopmentRequest.mockReturnValue(true);
    localMocks.getLocalDevelopmentUser.mockRejectedValue(new Error("database unavailable"));
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);

    const context = await createContext(options());

    expect(context.user).toBeNull();
    expect(sdkMocks.authenticateRequest).not.toHaveBeenCalled();
    errorSpy.mockRestore();
  });
});
