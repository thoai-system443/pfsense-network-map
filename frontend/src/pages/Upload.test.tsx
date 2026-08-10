import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import * as api from "@/lib/api";

import { UploadPage } from "./Upload";

const navigate = vi.fn();
vi.mock("react-router-dom", async () => ({
  ...(await vi.importActual<typeof import("react-router-dom")>("react-router-dom")),
  useNavigate: () => navigate,
}));

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <UploadPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const meta = {
  config_id: "abc123",
  filename: "config.xml",
  version: "22.5",
  hostname: "fw1",
  counts: { interfaces: 2, aliases: 1, rules: 2 },
  warnings: [],
};

async function chooseFile(contents = "<pfsense/>") {
  await userEvent.upload(
    screen.getByLabelText(/config\.xml/i),
    new File([contents], "config.xml", { type: "text/xml" }),
  );
}

afterEach(() => {
  navigate.mockClear();
  vi.restoreAllMocks();
});

describe("UploadPage", () => {
  it("asks for a config.xml file", () => {
    renderPage();
    expect(screen.getByLabelText(/config\.xml/i)).toBeInTheDocument();
  });

  it("navigates to the topology view after a clean upload", async () => {
    vi.spyOn(api, "uploadConfig").mockResolvedValue(meta);
    renderPage();
    await chooseFile();
    await waitFor(() => expect(navigate).toHaveBeenCalledWith("/c/abc123/topology"));
  });

  it("shows the parse warnings so schema gaps are visible", async () => {
    vi.spyOn(api, "uploadConfig").mockResolvedValue({
      ...meta,
      warnings: [
        { path: "pfsense/mystery", message: "unrecognised element, ignored", severity: "warning" },
      ],
    });
    renderPage();
    await chooseFile();
    expect(await screen.findByText(/pfsense\/mystery/)).toBeInTheDocument();
  });

  it("does not navigate away while warnings are unread", async () => {
    vi.spyOn(api, "uploadConfig").mockResolvedValue({
      ...meta,
      warnings: [
        { path: "pfsense/mystery", message: "unrecognised element, ignored", severity: "warning" },
      ],
    });
    renderPage();
    await chooseFile();
    await screen.findByText(/pfsense\/mystery/);
    expect(navigate).not.toHaveBeenCalled();
  });

  it("shows the server error when parsing fails", async () => {
    vi.spyOn(api, "uploadConfig").mockRejectedValue(new Error("file is not valid XML"));
    renderPage();
    await chooseFile("oops");
    expect(await screen.findByText(/file is not valid XML/)).toBeInTheDocument();
  });
});
