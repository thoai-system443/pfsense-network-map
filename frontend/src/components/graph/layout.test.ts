import { describe, expect, it } from "vitest";

import type { GraphNode } from "@/lib/types";

import { radial } from "./layout";

const node = (id: string, kind: GraphNode["kind"]): GraphNode => ({
  id,
  label: id,
  kind,
  subnet: null,
});

describe("radial", () => {
  it("puts the centre node at the origin", () => {
    const positions = radial([node("fw", "firewall"), node("lan", "interface")], "fw");
    expect(positions.fw).toEqual({ x: 0, y: 0 });
  });

  it("spreads the remaining nodes around the centre", () => {
    const positions = radial(
      [node("fw", "firewall"), node("a", "interface"), node("b", "interface")],
      "fw",
    );
    expect(positions.a).not.toEqual(positions.b);
  });

  it("places every node on the ring when there is no centre", () => {
    const positions = radial([node("a", "interface"), node("b", "interface")], null);
    expect(Object.keys(positions)).toEqual(["a", "b"]);
    expect(positions.a).not.toEqual({ x: 0, y: 0 });
  });

  it("gives a position to every node", () => {
    const nodes = ["a", "b", "c", "d"].map((id) => node(id, "interface"));
    expect(Object.keys(radial(nodes, null))).toHaveLength(4);
  });
});
