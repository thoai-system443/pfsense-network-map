import { afterEach, describe, expect, it, vi } from "vitest";

import { getTopology, queryCheck, uploadConfig } from "./api";

function mockFetch(body: unknown, status = 200) {
  const spy = vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  });
  globalThis.fetch = spy as unknown as typeof fetch;
  return spy;
}

afterEach(() => vi.restoreAllMocks());

describe("api client", () => {
  it("posts the file as multipart to the configs endpoint", async () => {
    const spy = mockFetch({ config_id: "abc" }, 201);
    await uploadConfig(new File(["<pfsense/>"], "config.xml"));
    const [url, init] = spy.mock.calls[0];
    expect(url).toBe("http://localhost:8010/api/v1/configs");
    expect(init.method).toBe("POST");
    expect(init.body).toBeInstanceOf(FormData);
  });

  it("builds the topology url from the config id", async () => {
    const spy = mockFetch({ nodes: [], edges: [] });
    await getTopology("abc");
    expect(spy.mock.calls[0][0]).toBe("http://localhost:8010/api/v1/configs/abc/topology");
  });

  it("sends the check query as json", async () => {
    const spy = mockFetch({ verdict: "pass" });
    await queryCheck("abc", {
      source: "192.168.1.5",
      destination: "8.8.8.8",
      port: 443,
      protocol: "tcp",
    });
    const [, init] = spy.mock.calls[0];
    expect(JSON.parse(init.body as string).port).toBe(443);
  });

  it("throws with the server detail when the request fails", async () => {
    mockFetch({ detail: "file is not valid XML" }, 400);
    await expect(uploadConfig(new File(["bad"], "config.xml"))).rejects.toThrow(
      "file is not valid XML",
    );
  });

  it("throws a generic message when the error body has no detail", async () => {
    mockFetch({}, 500);
    await expect(getTopology("abc")).rejects.toThrow("request failed with status 500");
  });
});
