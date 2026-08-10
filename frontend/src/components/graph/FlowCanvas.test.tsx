import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { GraphNode } from "@/lib/types";

import { FlowCanvas } from "./FlowCanvas";

const nodes: GraphNode[] = [
  { id: "fw", label: "fw1", kind: "firewall", subnet: null },
  { id: "lan", label: "LAN", kind: "interface", subnet: "192.168.1.0/24" },
];

describe("FlowCanvas", () => {
  it("renders a label for every node", () => {
    render(<FlowCanvas nodes={nodes} edges={[]} />);
    expect(screen.getByText("fw1")).toBeInTheDocument();
    expect(screen.getByText("LAN")).toBeInTheDocument();
  });

  it("shows the subnet under the label", () => {
    render(<FlowCanvas nodes={nodes} edges={[]} />);
    expect(screen.getByText("192.168.1.0/24")).toBeInTheDocument();
  });

  it("renders an empty state when there is nothing to draw", () => {
    render(<FlowCanvas nodes={[]} edges={[]} />);
    expect(screen.getByText(/nothing to display/i)).toBeInTheDocument();
  });
});
