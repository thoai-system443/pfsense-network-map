import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import * as api from "@/lib/api";

import { InventoryPage } from "./Inventory";

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/c/abc/inventory"]}>
        <Routes>
          <Route path="/c/:configId/inventory" element={<InventoryPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const interfaces = [
  {
    firewall: "fw-edge",
    name: "lan",
    descr: "LAN",
    if_: "em1",
    ipaddr: "192.168.1.1",
    subnet: 24,
    enabled: true,
    is_vlan: false,
    vlan_tag: null,
    parent_if: null,
  },
  {
    firewall: "fw-edge",
    name: "opt1",
    descr: "DMZ",
    if_: "em2.20",
    ipaddr: "10.10.20.1",
    subnet: 24,
    enabled: true,
    is_vlan: true,
    vlan_tag: 20,
    parent_if: "em2",
  },
];

afterEach(() => vi.restoreAllMocks());

describe("InventoryPage", () => {
  it("lists interfaces with their addresses", async () => {
    vi.spyOn(api, "getInterfaces").mockResolvedValue(interfaces);
    renderPage();
    expect(await screen.findByText("192.168.1.1/24")).toBeInTheDocument();
  });

  it("filters rows by the search box", async () => {
    vi.spyOn(api, "getInterfaces").mockResolvedValue(interfaces);
    renderPage();
    await screen.findByText("LAN");
    await userEvent.type(screen.getByLabelText(/filter/i), "DMZ");
    expect(screen.queryByText("LAN")).not.toBeInTheDocument();
    expect(screen.getByText("DMZ")).toBeInTheDocument();
  });

  it("matches the filter against the address, not just the name", async () => {
    vi.spyOn(api, "getInterfaces").mockResolvedValue(interfaces);
    renderPage();
    await screen.findByText("LAN");
    await userEvent.type(screen.getByLabelText(/filter/i), "10.10.20");
    expect(screen.getByText("DMZ")).toBeInTheDocument();
    expect(screen.queryByText("LAN")).not.toBeInTheDocument();
  });

  it("switches to the aliases table", async () => {
    vi.spyOn(api, "getInterfaces").mockResolvedValue(interfaces);
    vi.spyOn(api, "getAliases").mockResolvedValue([
      {
        firewall: "fw-edge",
        name: "WEB_SERVERS",
        type: "host",
        items: ["192.168.1.10"],
        descr: "Web",
        resolved_addresses: ["192.168.1.10/32"],
      },
    ]);
    renderPage();
    await userEvent.click(screen.getByRole("tab", { name: /aliases/i }));
    expect(await screen.findByText("WEB_SERVERS")).toBeInTheDocument();
  });

  it("surfaces an alias cycle instead of hiding it", async () => {
    vi.spyOn(api, "getInterfaces").mockResolvedValue(interfaces);
    vi.spyOn(api, "getAliases").mockResolvedValue([
      {
        firewall: "fw-edge",
        name: "LOOP_A",
        type: "host",
        items: ["LOOP_B"],
        descr: "a",
        error: "alias cycle: LOOP_A -> LOOP_B -> LOOP_A",
      },
    ]);
    renderPage();
    await userEvent.click(screen.getByRole("tab", { name: /aliases/i }));
    expect(await screen.findByText(/alias cycle/i)).toBeInTheDocument();
  });

  it("links an interface row to a search prefilled with its subnet", async () => {
    vi.spyOn(api, "getInterfaces").mockResolvedValue(interfaces);
    renderPage();
    const link = await screen.findByRole("link", { name: /192\.168\.1\.1\/24/ });
    expect(link).toHaveAttribute("href", "/c/abc/search?source=192.168.1.1%2F24");
  });
});
