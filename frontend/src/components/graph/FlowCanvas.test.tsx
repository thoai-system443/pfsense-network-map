import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { GraphNode } from "@/lib/types";

import { FlowCanvas } from "./FlowCanvas";

const nodes: GraphNode[] = [
  { id: "fw", label: "fw1", kind: "firewall", subnet: null },
  { id: "lan", label: "LAN", kind: "interface", subnet: "192.168.1.0/24" },
  { id: "dmz", label: "DMZ", kind: "interface", subnet: "10.10.20.0/24" },
];

const edges = [
  { id: "lan-dmz", source: "lan", target: "dmz", label: "443" },
  { id: "dmz-lan", source: "dmz", target: "lan", label: "80" },
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

  it("lets nodes be dragged", () => {
    render(<FlowCanvas nodes={nodes} edges={[]} />);
    // React Flow marks a node undraggable with the nodrag class.
    const node = screen.getByText("LAN").closest(".react-flow__node");
    expect(node).not.toHaveClass("nodrag");
  });

  it("hides nodes that are not in the visible set", () => {
    render(<FlowCanvas nodes={nodes} edges={edges} visibleNodeIds={new Set(["lan", "dmz"])} />);
    expect(screen.getByText("LAN")).toBeInTheDocument();
    expect(screen.queryByText("fw1")).not.toBeInTheDocument();
  });

  it("shows every node when no visible set is given", () => {
    render(<FlowCanvas nodes={nodes} edges={edges} />);
    expect(screen.getByText("fw1")).toBeInTheDocument();
    expect(screen.getByText("DMZ")).toBeInTheDocument();
  });

  it("reports which node was clicked", async () => {
    const onNodeClick = vi.fn();
    render(<FlowCanvas nodes={nodes} edges={[]} onNodeClick={onNodeClick} />);
    await userEvent.click(screen.getByText("LAN"));
    expect(onNodeClick).toHaveBeenCalledWith("lan");
  });

  it("keeps a node's position when the visible set changes", () => {
    const { rerender } = render(<FlowCanvas nodes={nodes} edges={edges} />);
    const before = screen.getByText("LAN").closest(".react-flow__node") as HTMLElement;
    const positionBefore = before.style.transform;

    rerender(<FlowCanvas nodes={nodes} edges={edges} visibleNodeIds={new Set(["lan", "dmz"])} />);
    const after = screen.getByText("LAN").closest(".react-flow__node") as HTMLElement;

    expect(after.style.transform).toBe(positionBefore);
  });
});
