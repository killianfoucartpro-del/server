import axios from "axios";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { checkSendGridKey } from "./client";

vi.mock("axios", () => ({
  default: {
    get: vi.fn(),
    post: vi.fn(),
    isAxiosError: vi.fn(() => false),
  },
}));

const mockedGet = vi.mocked(axios.get);

describe("SendGrid result classification", () => {
  beforeEach(() => {
    mockedGet.mockReset();
  });

  it("classifies unauthorized credentials as invalid", async () => {
    mockedGet.mockResolvedValueOnce({ status: 401, data: { errors: [{ message: "authorization required" }] } });
    const result = await checkSendGridKey("SG.invalid_key_payload_1234567890");
    expect(result.status).toBe("invalid");
    expect(result.providerStatus).toBe(401);
  });

  it("classifies zero-credit accounts as free plan", async () => {
    mockedGet
      .mockResolvedValueOnce({ status: 200, data: { total: 0, used: 0, reset_frequency: "monthly" } })
      .mockResolvedValueOnce({ status: 200, data: [] });
    const result = await checkSendGridKey("SG.free_key_payload_1234567890");
    expect(result.status).toBe("free");
    expect(result.creditLimit).toBe(0);
  });

  it("selects the most frequently observed sender alias", async () => {
    mockedGet
      .mockResolvedValueOnce({ status: 200, data: { total: 1000, used: 10, reset_frequency: "monthly" } })
      .mockResolvedValueOnce({ status: 200, data: [{ domain: "example.com" }] })
      .mockResolvedValueOnce({
        status: 200,
        data: { messages: [{ from_email: "ops@example.com" }, { from_email: "ops@example.com" }, { from_email: "info@example.com" }] },
      });
    const result = await checkSendGridKey("SG.valid_key_payload_1234567890");
    expect(result.status).toBe("valid");
    expect(result.fromEmail).toBe("ops@example.com");
    expect(result.domains).toEqual(["example.com"]);
  });
});
