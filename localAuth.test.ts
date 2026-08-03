import { describe, expect, it, vi } from "vitest";

vi.mock("./db", () => ({
  getUserByOpenId: vi.fn(),
  upsertUser: vi.fn(),
}));

import { isLocalDevelopmentRequest, isLoopbackAddress, isLoopbackHostname } from "./localAuth";

function request(host: string | undefined, remoteAddress: string | undefined) {
  return {
    headers: host ? { host } : {},
    socket: { remoteAddress },
  } as Parameters<typeof isLocalDevelopmentRequest>[0];
}

describe("local development authentication boundary", () => {
  it("recognizes only explicit loopback hostnames and addresses", () => {
    expect(isLoopbackHostname("localhost")).toBe(true);
    expect(isLoopbackHostname("127.0.0.1")).toBe(true);
    expect(isLoopbackHostname("::1")).toBe(true);
    expect(isLoopbackHostname("localhost.example.com")).toBe(false);
    expect(isLoopbackAddress("::ffff:127.0.0.1")).toBe(true);
    expect(isLoopbackAddress("192.168.1.20")).toBe(false);
  });

  it("allows a development request only when host and socket are both local", () => {
    expect(isLocalDevelopmentRequest(request("localhost:3000", "::1"), "development")).toBe(true);
    expect(isLocalDevelopmentRequest(request("127.0.0.1:3000", "::ffff:127.0.0.1"), "development")).toBe(true);
    expect(isLocalDevelopmentRequest(request("[::1]:3000", "::1"), "development")).toBe(true);
  });

  it("rejects production, remote hosts and remote socket addresses", () => {
    expect(isLocalDevelopmentRequest(request("localhost:3000", "::1"), "production")).toBe(false);
    expect(isLocalDevelopmentRequest(request("app.example.com", "::1"), "development")).toBe(false);
    expect(isLocalDevelopmentRequest(request("localhost:3000", "10.0.0.8"), "development")).toBe(false);
    expect(isLocalDevelopmentRequest(request(undefined, "::1"), "development")).toBe(false);
  });

  it("does not trust forwarded host headers when the actual Host is remote", () => {
    const forwarded = {
      headers: { host: "app.example.com", "x-forwarded-host": "localhost:3000" },
      socket: { remoteAddress: "::1" },
    } as Parameters<typeof isLocalDevelopmentRequest>[0];
    expect(isLocalDevelopmentRequest(forwarded, "development")).toBe(false);
  });
});
