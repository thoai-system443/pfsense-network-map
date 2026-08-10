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
    await userEvent.type(screen.getByLabelText(/^source$/i), "192.168.1.50");
    await userEvent.type(screen.getByLabelText(/^destination$/i), "8.8.8.8");
    await userEvent.click(screen.getByRole("button", { name: /^check$/i }));

    expect(await screen.findByText(/could not be resolved offline/i)).toBeInTheDocument();
  });

  it("shows the server error instead of a blank result", async () => {
    vi.spyOn(api, "queryCheck").mockRejectedValue(new Error("cannot resolve 'nope'"));
    renderPage();
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
