import type { GraphNode } from "@/lib/types";

const RADIUS = 320;

export interface Position {
  x: number;
  y: number;
}

/**
 * Both graphs are small — a firewall with a handful of zones — so a ring around
 * an optional centre reads better than a hierarchical layout and avoids pulling
 * in a layout library.
 */
export function radial(nodes: GraphNode[], centreId: string | null): Record<string, Position> {
  const positions: Record<string, Position> = {};
  const ring = nodes.filter((node) => node.id !== centreId);

  if (centreId && nodes.some((node) => node.id === centreId)) {
    positions[centreId] = { x: 0, y: 0 };
  }

  ring.forEach((node, index) => {
    const angle = (2 * Math.PI * index) / Math.max(ring.length, 1) - Math.PI / 2;
    positions[node.id] = {
      x: Math.round(Math.cos(angle) * RADIUS),
      y: Math.round(Math.sin(angle) * RADIUS),
    };
  });

  return positions;
}
