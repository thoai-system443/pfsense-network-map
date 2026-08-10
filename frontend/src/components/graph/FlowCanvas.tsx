import { Background, Controls, MarkerType, ReactFlow } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useMemo } from "react";

import type { GraphNode } from "@/lib/types";

import { ZoneNode } from "./ZoneNode";
import { radial } from "./layout";

export interface CanvasEdge {
  id: string;
  source: string;
  target: string;
  label?: string;
  dashed?: boolean;
}

// Defined at module scope: a fresh object each render makes React Flow warn and
// remount every node.
const nodeTypes = { zone: ZoneNode };

export function FlowCanvas({
  nodes,
  edges,
  onEdgeClick,
  directed = false,
}: {
  nodes: GraphNode[];
  edges: CanvasEdge[];
  onEdgeClick?: (edgeId: string) => void;
  /** Access flows are directional; topology links are not. */
  directed?: boolean;
}) {
  const centreId = nodes.find((node) => node.kind === "firewall")?.id ?? null;
  const positions = useMemo(() => radial(nodes, centreId), [nodes, centreId]);

  const flowNodes = useMemo(
    () =>
      nodes.map((node) => ({
        id: node.id,
        type: "zone" as const,
        position: positions[node.id] ?? { x: 0, y: 0 },
        data: { label: node.label, subnet: node.subnet, kind: node.kind },
      })),
    [nodes, positions],
  );

  const flowEdges = useMemo(
    () =>
      edges.map((edge) => ({
        id: edge.id,
        source: edge.source,
        target: edge.target,
        label: edge.label,
        animated: false,
        style: edge.dashed ? { strokeDasharray: "6 4" } : undefined,
        // Without an arrowhead a directed graph reads as undirected, which is
        // the one thing the access map exists to answer.
        markerEnd: directed ? { type: MarkerType.ArrowClosed } : undefined,
      })),
    [edges, directed],
  );

  if (nodes.length === 0) {
    return (
      <div className="flex h-[600px] items-center justify-center rounded-lg border bg-card text-sm text-muted-foreground">
        Nothing to display
      </div>
    );
  }

  return (
    <div className="h-[600px] rounded-lg border bg-card">
      <ReactFlow
        nodes={flowNodes}
        edges={flowEdges}
        nodeTypes={nodeTypes}
        onEdgeClick={(_, edge) => onEdgeClick?.(edge.id)}
        fitView
      >
        <Background />
        <Controls />
      </ReactFlow>
    </div>
  );
}
