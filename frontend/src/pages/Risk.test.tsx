import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import * as api from "@/lib/api";
import type { RiskReport } from "@/lib/types";

import { RiskPage, exposureRows } from "./Risk";

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
      firewall: "fw-edge",
      subject: {
        id: "lan",
        label: "LAN",
        kind: "interface",
        cidrs: ["192.168.1.0/24"],
        members: ["192.168.1.0/24"],
      },
      cidr: "192.168.1.0/24",
      reaches_networks_any_port: ["DMZ"],
      reaches_internet: true,
      internet_ports: "443",
      reachable_from_internet: false,
      inbound_internet_ports: "",
      reachable_from_networks_any_port: [],
      allowed_by: [
        { criterion: "internet", detail: "443", rule },
        { criterion: "networks", detail: "DMZ", rule },
      ],
    },
    {
      firewall: "fw-edge",
      subject: {
        id: "alias:DB_SERVER",
        label: "DB_SERVER",
        kind: "alias",
        cidrs: ["10.10.20.50/32"],
        members: ["10.10.20.50/32"],
      },
      cidr: "10.10.20.50/32",
      reaches_networks_any_port: [],
      reaches_internet: false,
      internet_ports: "",
      reachable_from_internet: true,
      inbound_internet_ports: "8443",
      reachable_from_networks_any_port: ["LAN"],
      allowed_by: [{ criterion: "from-internet", detail: "8443", rule }],
    },
  ],
  deny_all: [
    {
      firewall: "fw-edge",
      kind: "block-all-not-quick",
      interface: "opt1",
      rule: { ...rule, descr: "Block everything on DMZ", action: "block" },
      detail: "this block-all has no quick flag, so evaluation continues",
    },
  ],
};

afterEach(() => vi.restoreAllMocks());

describe("RiskPage", () => {
  it("marks an address that reaches another network on every port", async () => {
    vi.spyOn(api, "getRiskReport").mockResolvedValue(report);
    renderPage();
    // Keyed on the address, not the object: "LAN" is both an object label and
    // the name of a network another row can be reached from.
    const row = (await screen.findByText("192.168.1.0/24")).closest("tr")!;
    expect(row).toHaveTextContent("DMZ");
  });

  it("gives each IP or network its own row", async () => {
    const [lan, db] = report.exposures;
    vi.spyOn(api, "getRiskReport").mockResolvedValue({
      ...report,
      exposures: [
        lan,
        db,
        { ...db, cidr: "10.10.20.51/32", inbound_internet_ports: "9443" },
      ],
    });
    renderPage();
    expect(await screen.findByText("10.10.20.50/32")).toBeInTheDocument();
    expect(screen.getByText("10.10.20.51/32").closest("tr")!).toHaveTextContent("9443");
  });

  it("shows the ports behind an internet exposure rather than just a tick", async () => {
    vi.spyOn(api, "getRiskReport").mockResolvedValue(report);
    renderPage();
    const row = (await screen.findByText("DB_SERVER")).closest("tr")!;
    expect(row).toHaveTextContent("8443");
  });

  it("counts the addresses listed, so a short table is not ambiguous", async () => {
    vi.spyOn(api, "getRiskReport").mockResolvedValue(report);
    renderPage();
    expect(await screen.findByText(/2 addresses match/i)).toBeInTheDocument();
  });

  it("says outright when nothing is exposed", async () => {
    vi.spyOn(api, "getRiskReport").mockResolvedValue({ ...report, exposures: [] });
    renderPage();
    expect(await screen.findByText(/no address matches/i)).toBeInTheDocument();
  });

  it("no longer shows the unoccupied address space section", async () => {
    vi.spyOn(api, "getRiskReport").mockResolvedValue(report);
    renderPage();
    await screen.findByText("192.168.1.0/24");
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
        firewall: "fw-edge",
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

    expect(spy).toHaveBeenCalledWith("abc", 5432, "tcp", true);
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

describe("the hide-outbound switch", () => {
  const rows = [
    {
      firewall: "fw-edge",
      source_id: "opt1",
      source_label: "DMZ",
      destination_cidrs: ["10.10.20.50/32"],
      ports: "5432",
      rule,
    },
  ];

  afterEach(() => vi.restoreAllMocks());

  async function search(port: string) {
    vi.spyOn(api, "getRiskReport").mockResolvedValue(report);
    const spy = vi.spyOn(api, "getPortAccess").mockResolvedValue(rows);
    renderPage();
    await userEvent.type(await screen.findByLabelText(/^port$/i), port);
    return spy;
  }

  it("is on by default", async () => {
    await search("5432");
    expect(screen.getByLabelText(/hide traffic out to the internet/i)).toBeChecked();
  });

  it("asks the backend to hide outbound internet traffic", async () => {
    const spy = await search("5432");
    await userEvent.click(screen.getByRole("button", { name: /who reaches/i }));
    expect(spy).toHaveBeenCalledWith("abc", 5432, "tcp", true);
  });

  it("shows outbound traffic once unticked", async () => {
    const spy = await search("5432");
    await userEvent.click(screen.getByLabelText(/hide traffic out to the internet/i));
    await userEvent.click(screen.getByRole("button", { name: /who reaches/i }));
    expect(spy).toHaveBeenCalledWith("abc", 5432, "tcp", false);
  });

  it("says the empty result ignored outbound internet traffic", async () => {
    vi.spyOn(api, "getRiskReport").mockResolvedValue(report);
    vi.spyOn(api, "getPortAccess").mockResolvedValue([]);
    renderPage();
    await userEvent.type(await screen.findByLabelText(/^port$/i), "9999");
    await userEvent.click(screen.getByRole("button", { name: /who reaches/i }));
    expect(
      await screen.findByText(/ignoring traffic out to the internet/i),
    ).toBeInTheDocument();
  });
});

describe("exporting exposure by object", () => {
  it("prints only the exposure section, via the browser's own PDF export", async () => {
    vi.spyOn(api, "getRiskReport").mockResolvedValue(report);
    const print = vi.fn();
    vi.stubGlobal("print", print);

    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: /export pdf/i }));

    expect(print).toHaveBeenCalledOnce();
    // The print stylesheet keys off this attribute; without it the whole page
    // would end up in the PDF.
    const section = screen.getByRole("table", { name: "Exposure by object" }).closest("section");
    expect(section).toHaveAttribute("data-print-region");
    vi.unstubAllGlobals();
  });

  it("puts each flag and its ports in their own column", () => {
    const [lan] = exposureRows([report.exposures[0]]);
    expect(lan).toEqual([
      "fw-edge",
      "LAN",
      "interface",
      "192.168.1.0/24",
      "DMZ",
      "yes",
      "443",
      "no",
      "",
      "",
    ]);
  });

  it("leaves the ports column empty when the flag is off", () => {
    // internet_ports can carry a leftover value; a "no" row must not imply one.
    const [row] = exposureRows([
      { ...report.exposures[1], internet_ports: "443", reaches_internet: false },
    ]);
    expect(row[5]).toBe("no");
    expect(row[6]).toBe("");
  });

  it("exports the rows shown and leaves out the objects with nothing flagged", async () => {
    vi.spyOn(api, "getRiskReport").mockResolvedValue(report);
    // jsdom's Blob has no text(), so capture what downloadCsv puts into it.
    let captured = "";
    class CapturingBlob {
      constructor(parts: string[]) {
        captured = parts.join("");
      }
    }
    vi.stubGlobal("Blob", CapturingBlob);
    vi.stubGlobal("URL", { ...URL, createObjectURL: () => "blob:stub", revokeObjectURL: () => {} });
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});

    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: /export csv/i }));

    expect(captured.startsWith("\uFEFF")).toBe(true);
    expect(captured).toContain("LAN");
    expect(captured).toContain("DB_SERVER");
    expect(captured).not.toContain("GUEST");
    vi.unstubAllGlobals();
  });
});

describe("the debug view", () => {
  it("is off until asked for", async () => {
    vi.spyOn(api, "getRiskReport").mockResolvedValue(report);
    renderPage();
    await screen.findByText("192.168.1.0/24");
    expect(screen.queryByText(/reaches internet on/i)).not.toBeInTheDocument();
  });

  it("names the rule that allows each finding", async () => {
    vi.spyOn(api, "getRiskReport").mockResolvedValue(report);
    renderPage();
    await screen.findByText("192.168.1.0/24");
    await userEvent.click(screen.getByLabelText(/debug/i));

    expect(screen.getByText(/reaches internet on/i)).toBeInTheDocument();
    expect(screen.getAllByText(new RegExp(rule.descr)).length).toBeGreaterThan(0);
    expect(screen.getByText(/reachable from internet on/i)).toBeInTheDocument();
  });
});
