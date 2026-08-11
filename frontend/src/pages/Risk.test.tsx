import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import * as api from "@/lib/api";
import type { RiskReport } from "@/lib/types";

import { RiskPage } from "./Risk";

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/c/abc/risk"]}>
        <Routes>
          <Route path="/c/:configId/risk" element={<RiskPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const rule = {
  seq: 2,
  interface: "opt1",
  action: "pass" as const,
  descr: "Postgres from the 10 space",
  tracker: null,
  floating: false,
  quick: true,
  synthetic: false,
};

const report: RiskReport = {
  exposures: [
    {
      subject: { id: "lan", label: "LAN", kind: "interface", cidrs: ["192.168.1.0/24"] },
      reaches_other_subnets_any_port: ["DMZ"],
      reaches_internet: true,
      internet_ports: "443",
      reachable_from_all_internal: false,
      inbound_internal_ports: "",
      reachable_from_internet: false,
      inbound_internet_ports: "",
    },
    {
      subject: { id: "alias:DB_SERVER", label: "DB_SERVER", kind: "alias", cidrs: ["10.10.20.50/32"] },
      reaches_other_subnets_any_port: [],
      reaches_internet: false,
      internet_ports: "",
      reachable_from_all_internal: false,
      inbound_internal_ports: "",
      reachable_from_internet: true,
      inbound_internet_ports: "8443",
    },
    {
      subject: { id: "opt2", label: "GUEST", kind: "interface", cidrs: ["172.16.5.0/24"] },
      reaches_other_subnets_any_port: [],
      reaches_internet: false,
      internet_ports: "",
      reachable_from_all_internal: false,
      inbound_internal_ports: "",
      reachable_from_internet: false,
      inbound_internet_ports: "",
    },
  ],
  deny_all: [
    {
      kind: "block-all-not-quick",
      interface: "opt1",
      rule: { ...rule, descr: "Block everything on DMZ", action: "block" },
      detail: "this block-all has no quick flag, so evaluation continues",
    },
  ],
};

afterEach(() => vi.restoreAllMocks());

describe("RiskPage", () => {
  it("marks a zone that reaches other subnets on every port", async () => {
    vi.spyOn(api, "getRiskReport").mockResolvedValue(report);
    renderPage();
    const row = (await screen.findByText("LAN")).closest("tr")!;
    expect(row).toHaveTextContent("DMZ");
  });

  it("shows the ports behind an internet exposure rather than just a tick", async () => {
    vi.spyOn(api, "getRiskReport").mockResolvedValue(report);
    renderPage();
    const row = (await screen.findByText("DB_SERVER")).closest("tr")!;
    expect(row).toHaveTextContent("8443");
  });

  it("leaves out objects with nothing flagged", async () => {
    vi.spyOn(api, "getRiskReport").mockResolvedValue(report);
    renderPage();
    await screen.findByText("LAN");
    expect(screen.queryByText("GUEST")).not.toBeInTheDocument();
  });

  it("says how many objects were checked, so an empty table is not ambiguous", async () => {
    vi.spyOn(api, "getRiskReport").mockResolvedValue(report);
    renderPage();
    expect(await screen.findByText(/2 of 3 objects/i)).toBeInTheDocument();
  });

  it("says outright when no object is exposed", async () => {
    vi.spyOn(api, "getRiskReport").mockResolvedValue({
      ...report,
      exposures: [report.exposures[2]],
    });
    renderPage();
    expect(await screen.findByText(/none of the 1 object/i)).toBeInTheDocument();
  });

  it("no longer shows the unoccupied address space section", async () => {
    vi.spyOn(api, "getRiskReport").mockResolvedValue(report);
    renderPage();
    await screen.findByText("LAN");
    expect(screen.queryByText(/granted to nothing/i)).not.toBeInTheDocument();
  });

  it("lists deny-all findings with the reason", async () => {
    vi.spyOn(api, "getRiskReport").mockResolvedValue(report);
    renderPage();
    expect(await screen.findByText(/no quick flag/)).toBeInTheDocument();
  });

  it("says so when nothing was found instead of showing empty tables", async () => {
    vi.spyOn(api, "getRiskReport").mockResolvedValue({ exposures: [], deny_all: [] });
    renderPage();
    expect(await screen.findByText(/every block-all rule/i)).toBeInTheDocument();
  });

  it("searches which sources reach a port", async () => {
    vi.spyOn(api, "getRiskReport").mockResolvedValue(report);
    const spy = vi.spyOn(api, "getPortAccess").mockResolvedValue([
      {
        source_id: "opt1",
        source_label: "DMZ",
        destination_cidrs: ["10.10.20.50/32"],
        ports: "5432",
        rule,
      },
    ]);
    renderPage();
    await userEvent.type(await screen.findByLabelText(/port/i), "5432");
    await userEvent.click(screen.getByRole("button", { name: /who reaches/i }));

    expect(spy).toHaveBeenCalledWith("abc", 5432, "tcp");
    const results = await screen.findByRole("table", { name: /sources reaching the port/i });
    expect(within(results).getByText("10.10.20.50/32")).toBeInTheDocument();
    expect(within(results).getByText("DMZ")).toBeInTheDocument();
  });

  it("says when nobody reaches the searched port", async () => {
    vi.spyOn(api, "getRiskReport").mockResolvedValue(report);
    vi.spyOn(api, "getPortAccess").mockResolvedValue([]);
    renderPage();
    await userEvent.type(await screen.findByLabelText(/port/i), "9999");
    await userEvent.click(screen.getByRole("button", { name: /who reaches/i }));

    expect(await screen.findByText(/nothing reaches port 9999/i)).toBeInTheDocument();
  });

  it("shows the error when the config is gone", async () => {
    vi.spyOn(api, "getRiskReport").mockRejectedValue(new Error("config not found"));
    renderPage();
    expect(await screen.findByText(/config not found/)).toBeInTheDocument();
  });
});
