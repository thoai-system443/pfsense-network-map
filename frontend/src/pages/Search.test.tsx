import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import * as api from "@/lib/api";

import { SearchPage } from "./Search";

function renderPage(path = "/c/abc/search") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/c/:configId/search" element={<SearchPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const rule = {
  seq: 0,
  interface: "lan",
  action: "pass" as const,
  descr: "Allow LAN to any HTTPS",
  tracker: null,
  floating: false,
  quick: true,
  synthetic: false,
};

afterEach(() => vi.restoreAllMocks());

describe("SearchPage", () => {
  it("opens on the cross-firewall walk and reports every hop", async () => {
    vi.spyOn(api, "queryPath").mockResolvedValue({
      verdict: "block",
      truncated: false,
      stopped_reason: null,
      hops: [
        {
          firewall_id: "fw-0",
          firewall_name: "fw-edge",
          in_interface: "lan",
          verdict: "pass",
          decided_by: rule,
          out_interface: "opt1",
          next_hop: "10.10.20.2",
          translated_address: null,
          translated_port: null,
        },
        {
          firewall_id: "fw-1",
          firewall_name: "fw-core",
          in_interface: "wan",
          verdict: "block",
          decided_by: null,
          out_interface: "lan",
          next_hop: null,
          translated_address: null,
          translated_port: null,
        },
      ],
    });
    renderPage();
    await userEvent.type(screen.getByLabelText(/^source$/i), "192.168.1.50");
    await userEvent.type(screen.getByLabelText(/^destination$/i), "10.20.5.10");
    await userEvent.click(screen.getByRole("button", { name: /^check$/i }));

    expect(await screen.findByText("fw-edge")).toBeInTheDocument();
    expect(screen.getByText("fw-core")).toBeInTheDocument();
  });

  it("says when the walk left the loaded firewalls", async () => {
    vi.spyOn(api, "queryPath").mockResolvedValue({
      verdict: "pass",
      truncated: true,
      stopped_reason: "next hop 203.0.113.1 belongs to a device that is not loaded here",
      hops: [],
    });
    renderPage();
    await userEvent.type(screen.getByLabelText(/^source$/i), "192.168.1.50");
    await userEvent.type(screen.getByLabelText(/^destination$/i), "8.8.8.8");
    await userEvent.click(screen.getByRole("button", { name: /^check$/i }));

    expect(await screen.findByText(/not loaded here/i)).toBeInTheDocument();
  });

  it("shows the verdict and the deciding rule for a path check", async () => {
    vi.spyOn(api, "queryCheck").mockResolvedValue({
      verdict: "pass",
      decided_by: rule,
      in_interface: "lan",
      translated_address: null,
      translated_port: null,
      unresolved: false,
      trace: [],
    });
    renderPage();
    await userEvent.click(screen.getByRole("tab", { name: /path check/i }));
    await userEvent.type(screen.getByLabelText(/^source$/i), "192.168.1.50");
    await userEvent.type(screen.getByLabelText(/^destination$/i), "8.8.8.8");
    await userEvent.type(screen.getByLabelText(/^port$/i), "443");
    await userEvent.click(screen.getByRole("button", { name: /^check$/i }));

    expect(await screen.findByText(/^pass$/i)).toBeInTheDocument();
    expect(await screen.findByText(/Allow LAN to any HTTPS/)).toBeInTheDocument();
  });

  it("reports the translated destination when NAT applies", async () => {
    vi.spyOn(api, "queryCheck").mockResolvedValue({
      verdict: "pass",
      decided_by: rule,
      in_interface: "wan",
      translated_address: "192.168.1.10",
      translated_port: 8443,
      unresolved: false,
      trace: [],
    });
    renderPage();
    await userEvent.click(screen.getByRole("tab", { name: /path check/i }));
    await userEvent.type(screen.getByLabelText(/^source$/i), "8.8.8.8");
    await userEvent.type(screen.getByLabelText(/^destination$/i), "203.0.113.2");
    await userEvent.click(screen.getByRole("button", { name: /^check$/i }));

    expect(await screen.findByText(/192\.168\.1\.10:8443/)).toBeInTheDocument();
  });

  it("lists reachable regions on the From tab", async () => {
    vi.spyOn(api, "queryFrom").mockResolvedValue([
      { addresses: ["0.0.0.0/0"], ports: "443", verdict: "pass", decided_by: rule },
      { addresses: ["0.0.0.0/0"], ports: "0-442", verdict: "block", decided_by: null },
    ]);
    renderPage();
    await userEvent.click(screen.getByRole("tab", { name: /^from$/i }));
    await userEvent.type(screen.getByLabelText(/^source$/i), "192.168.1.50");
    await userEvent.click(screen.getByRole("button", { name: /explore/i }));

    expect(await screen.findByText("0-442")).toBeInTheDocument();
    expect(screen.getByText("default deny")).toBeInTheDocument();
  });

  it("lists sources grouped by interface on the To tab", async () => {
    vi.spyOn(api, "queryTo").mockResolvedValue([
      { in_interface: "lan", addresses: ["192.168.1.0/24"], verdict: "pass", decided_by: rule },
    ]);
    renderPage();
    await userEvent.click(screen.getByRole("tab", { name: /^to$/i }));
    await userEvent.type(screen.getByLabelText(/^destination$/i), "8.8.8.8");
    await userEvent.click(screen.getByRole("button", { name: /explore/i }));

    expect(await screen.findByText("192.168.1.0/24")).toBeInTheDocument();
  });

  it("warns when a result depends on an alias it could not resolve", async () => {
    vi.spyOn(api, "queryCheck").mockResolvedValue({
      verdict: "pass",
      decided_by: rule,
      in_interface: "lan",
      translated_address: null,
      translated_port: null,
      unresolved: true,
      trace: [],
    });
    renderPage();
    await userEvent.click(screen.getByRole("tab", { name: /path check/i }));
    await userEvent.type(screen.getByLabelText(/^source$/i), "192.168.1.50");
    await userEvent.type(screen.getByLabelText(/^destination$/i), "8.8.8.8");
    await userEvent.click(screen.getByRole("button", { name: /^check$/i }));

    expect(await screen.findByText(/could not be resolved offline/i)).toBeInTheDocument();
  });

  it("shows the server error instead of a blank result", async () => {
    vi.spyOn(api, "queryCheck").mockRejectedValue(new Error("cannot resolve 'nope'"));
    renderPage();
    await userEvent.click(screen.getByRole("tab", { name: /path check/i }));
    await userEvent.type(screen.getByLabelText(/^source$/i), "nope");
    await userEvent.type(screen.getByLabelText(/^destination$/i), "8.8.8.8");
    await userEvent.click(screen.getByRole("button", { name: /^check$/i }));

    expect(await screen.findByText(/cannot resolve 'nope'/)).toBeInTheDocument();
  });

  it("prefills the source from the query string so Inventory can link here", () => {
    renderPage("/c/abc/search?source=WEB_SERVERS");
    expect(screen.getByLabelText(/^source$/i)).toHaveValue("WEB_SERVERS");
  });
});
