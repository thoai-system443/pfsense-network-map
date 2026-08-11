import { Background, Controls, MarkerType, ReactFlow, useNodesState } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useMemo } from "react";

import type { GraphNode } from "@/lib/types";

import { ZoneNode, type ZoneNodeType } from "./ZoneNode";
import { radial } from "./layout";

export interface CanvasEdge {
  id: string;
  source: string;
  target: string;
  label?: string;
  dashed?: boolean;
}

export interface FlowCanvasProps {
  nodes: GraphNode[];
  edges: CanvasEdge[];
  onEdgeClick?: (edgeId: string) => void;
  onNodeClick?: (nodeId: string) => void;
  onPaneClick?: () => void;
  /** Access flows are directional; topology links are not. */
  directed?: boolean;
  /** null shows everything. Hiding rather than removing keeps positions put. */
  visibleNodeIds?: ReadonlySet<string> | null;
  visibleEdgeIds?: ReadonlySet<string> | null;
}

// Defined at module scope: a fresh object each render makes React Flow warn and
// remount every node.
const nodeTypes = { zone: ZoneNode };

function buildNodes(nodes: GraphNode[]): ZoneNodeType[] {
  const centreId = nodes.find((node) => node.kind === "firewall")?.id ?? null;
  const positions = radial(nodes, centreId);
  return nodes.map((node) => ({
    id: node.id,
    type: "zone" as const,
    position: positions[node.id] ?? { x: 0, y: 0 },
    data: { label: node.label, subnet: node.subnet, kind: node.kind },
  }));
}

export function FlowCanvas(props: FlowCanvasProps) {
  if (props.nodes.length === 0) {
    return (
      <div className="flex h-[600px] items-center justify-center rounded-lg border bg-card text-sm text-muted-foreground">
        Nothing to display
      </div>
    );
  }

  // Remounting on a genuinely new node set is what reseeds the layout. Doing it
  // with an effect instead re-ran on every render the drag itself caused, which
  // overwrote each position update the moment it landed and made nodes look
  // immovable.
  return <PositionedCanvas key={props.nodes.map((node) => node.id).join("|")} {...props} />;
}

function PositionedCanvas({
  nodes,
  edges,
  onEdgeClick,
  onNodeClick,
  onPaneClick,
  directed = false,
  visibleNodeIds = null,
  visibleEdgeIds = null,
}: FlowCanvasProps) {
  // Positions live in state so a node stays where the user dragged it.
  const [positioned, , onNodesChange] = useNodesState<ZoneNodeType>(buildNodes(nodes));

  const flowNodes = useMemo(
    () =>
      positioned.map((node) => ({
        ...node,
        hidden: visibleNodeIds ? !visibleNodeIds.has(node.id) : false,
      })),
    [positioned, visibleNodeIds],
  );

  const flowEdges = useMemo(
    () =>
      edges.map((edge) => ({
        id: edge.id,
        source: edge.source,
        target: edge.target,
        label: edge.label,
        animated: false,
        hidden: visibleEdgeIds ? !visibleEdgeIds.has(edge.id) : false,
        style: edge.dashed ? { strokeDasharray: "6 4" } : undefined,
        // Without an arrowhead a directed graph reads as undirected, which is
        // the one thing the access map exists to answer.
        markerEnd: directed ? { type: MarkerType.ArrowClosed } : undefined,
      })),
    [edges, directed, visibleEdgeIds],
  );

  return (
    <div className="h-[600px] rounded-lg border bg-card">
      <ReactFlow
        nodes={flowNodes}
        edges={flowEdges}
        nodeTypes={nodeTypes}
        onNodesChange={onNodesChange}
        onNodeClick={(_, node) => onNodeClick?.(node.id)}
        onEdgeClick={(_, edge) => onEdgeClick?.(edge.id)}
        onPaneClick={() => onPaneClick?.()}
        nodesConnectable={false}
        fitView
      >
        <Background />
        <Controls />
      </ReactFlow>
    </div>
  );
}
