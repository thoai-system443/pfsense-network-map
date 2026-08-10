import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it } from "vitest";

import { AppShell } from "./AppShell";

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/c/:configId/*" element={<AppShell />} />
        <Route path="/" element={<AppShell />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("AppShell", () => {
  it("shows the product name", () => {
    renderAt("/");
    expect(screen.getByText("pfSense Network Map")).toBeInTheDocument();
  });

  it("hides navigation until a config is loaded", () => {
    renderAt("/");
    expect(screen.queryByRole("link", { name: /topology/i })).not.toBeInTheDocument();
  });

  it("shows navigation once a config id is in the url", () => {
    renderAt("/c/abc123/topology");
    expect(screen.getByRole("link", { name: /topology/i })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /access map/i })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /search/i })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /inventory/i })).toBeInTheDocument();
  });

  it("points navigation at the current config", () => {
    renderAt("/c/abc123/topology");
    expect(screen.getByRole("link", { name: /topology/i })).toHaveAttribute(
      "href",
      "/c/abc123/topology",
    );
  });
});
