import { afterEach, describe, expect, it, vi } from "vitest";

describe("apiUrl", () => {
  afterEach(() => {
    delete (window as unknown as { __CONFIG__?: unknown }).__CONFIG__;
    vi.resetModules();
  });

  it("reads the value injected at container start", async () => {
    (window as unknown as { __CONFIG__: { API_URL: string } }).__CONFIG__ = {
      API_URL: "http://backend.internal:9000",
    };
    const { apiUrl } = await import("./config");
    expect(apiUrl).toBe("http://backend.internal:9000");
  });

  it("falls back to localhost when config.js is missing", async () => {
    const { apiUrl } = await import("./config");
    expect(apiUrl).toBe("http://localhost:8010");
  });

  it("drops a trailing slash so path joins stay clean", async () => {
    (window as unknown as { __CONFIG__: { API_URL: string } }).__CONFIG__ = {
      API_URL: "http://backend.internal:9000/",
    };
    const { apiUrl } = await import("./config");
    expect(apiUrl).toBe("http://backend.internal:9000");
  });
});
