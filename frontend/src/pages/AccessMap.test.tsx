import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import * as api from "@/lib/api";

import { AccessMapPage } from "./AccessMap";

const graph = {
  nodes: [
    { id: "lan", label: "LAN", kind: "interface" as const, subnet: "192.168.1.0/24" },
    { id: "internet", label: "Internet", kind: "internet" as const, subnet: null },
  ],
  edges: [
    {
      source: "lan",
      target: "internet",
      ports: "443",
      rules: [
        {
          seq: 0,
          interface: "lan",
          action: "pass" as const,
          descr: "Allow LAN to any HTTPS",
          tracker: null,
          floating: false,
          quick: true,
          synthetic: false,
        },
      ],
    },
  ],
};

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/c/abc/access"]}>
        <Routes>
          <Route path="/c/:configId/access" element={<AccessMapPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => vi.restoreAllMocks());

describe("AccessMapPage", () => {
  it("labels each edge with its allowed ports", async () => {
    vi.spyOn(api, "getAccessGraph").mockResolvedValue(graph);
    renderPage();
    expect(await screen.findByText("443")).toBeInTheDocument();
  });

  it("defaults to querying every protocol", async () => {
    const spy = vi.spyOn(api, "getAccessGraph").mockResolvedValue(graph);
    renderPage();
    await screen.findByText("LAN");
    expect(spy).toHaveBeenCalledWith("abc", "any");
  });

  it("refetches when the protocol filter changes", async () => {
    const spy = vi.spyOn(api, "getAccessGraph").mockResolvedValue(graph);
    renderPage();
    await screen.findByText("LAN");
    await userEvent.selectOptions(screen.getByLabelText(/protocol/i), "tcp");
    await waitFor(() => expect(spy).toHaveBeenCalledWith("abc", "tcp"));
  });

  it("lists the rules behind an edge when it is clicked", async () => {
    vi.spyOn(api, "getAccessGraph").mockResolvedValue(graph);
    renderPage();
    await userEvent.click(await screen.findByText("443"));
    expect(await screen.findByText(/Allow LAN to any HTTPS/)).toBeInTheDocument();
  });

  it("names zones by their display label, never by the raw id", async () => {
    vi.spyOn(api, "getAccessGraph").mockResolvedValue({
      nodes: [
        { id: "opt1", label: "DMZ", kind: "interface" as const, subnet: "10.10.20.0/24" },
        { id: "tunnel-0", label: "Remote access", kind: "tunnel" as const, subnet: "10.8.0.0/24" },
      ],
      edges: [{ source: "opt1", target: "tunnel-0", ports: "80", rules: [] }],
    });
    renderPage();
    expect(await screen.findByText("DMZ → Remote access")).toBeInTheDocument();
    expect(screen.queryByText(/opt1 → tunnel-0/)).not.toBeInTheDocument();
  });
});
