import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import * as api from "@/lib/api";

import { TopologyPage } from "./Topology";

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/c/abc/topology"]}>
        <Routes>
          <Route path="/c/:configId/topology" element={<TopologyPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => vi.restoreAllMocks());

describe("TopologyPage", () => {
  it("renders the nodes returned by the backend", async () => {
    vi.spyOn(api, "getTopology").mockResolvedValue({
      nodes: [
        { id: "fw", label: "fw1", kind: "firewall", subnet: null },
        { id: "lan", label: "LAN", kind: "interface", subnet: "192.168.1.0/24" },
      ],
      edges: [{ source: "fw", target: "lan", kind: "link" }],
    });
    renderPage();
    expect(await screen.findByText("LAN")).toBeInTheDocument();
  });

  it("requests the topology for the config in the url", async () => {
    const spy = vi.spyOn(api, "getTopology").mockResolvedValue({ nodes: [], edges: [] });
    renderPage();
    await screen.findByText(/nothing to display/i);
    expect(spy).toHaveBeenCalledWith("abc");
  });

  it("shows the error when the config is gone", async () => {
    vi.spyOn(api, "getTopology").mockRejectedValue(new Error("config not found"));
    renderPage();
    expect(await screen.findByText(/config not found/)).toBeInTheDocument();
  });

  it("says outright that routed networks are not drawn", async () => {
    vi.spyOn(api, "getTopology").mockResolvedValue({ nodes: [], edges: [] });
    renderPage();
    expect(await screen.findByText(/behind an internal router/i)).toBeInTheDocument();
  });
});
