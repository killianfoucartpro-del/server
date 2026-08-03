import { describe, expect, it } from "vitest";
import { clampExecutionSettings, normalizeProxy, parseApiKeys, parseProxies } from "./parsers";

describe("SendGrid import parsers", () => {
  it("parses CSV/TXT keys, strips labels and removes duplicates", () => {
    const first = "SG.first_payload_1234567890.second_payload_1234567890";
    const second = "SG.another_payload_1234567890.final_payload_1234567890";
    const parsed = parseApiKeys(`apikey\n${first}\nAPIKEY: ${first},${second}\ninvalid value`);

    expect(parsed.values).toEqual([first, second]);
    expect(parsed.duplicates).toBe(1);
    expect(parsed.rejected).toBe(1);
  });

  it("normalizes authenticated proxies and rejects malformed endpoints", () => {
    expect(normalizeProxy("http://user:pass@127.0.0.1:8080")).toBe("user:pass@127.0.0.1:8080");
    expect(normalizeProxy("missing-credentials.example:8080")).toBeNull();
    expect(normalizeProxy("user:pass@host:70000")).toBeNull();

    const parsed = parseProxies("user:pass@host:8080\nuser:pass@host:8080\nbad");
    expect(parsed.values).toEqual(["user:pass@host:8080"]);
    expect(parsed.duplicates).toBe(1);
    expect(parsed.rejected).toBe(1);
  });

  it("clamps parallelism and rate limits to safe server bounds", () => {
    expect(clampExecutionSettings(0, 1)).toEqual({ concurrency: 1, rateLimitPerMinute: 6 });
    expect(clampExecutionSettings(99, 999)).toEqual({ concurrency: 10, rateLimitPerMinute: 120 });
    expect(clampExecutionSettings(4, 60)).toEqual({ concurrency: 4, rateLimitPerMinute: 60 });
  });
});
