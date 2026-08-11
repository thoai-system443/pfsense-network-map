import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { useParams } from "react-router-dom";

import { FlowCanvas } from "@/components/graph/FlowCanvas";
import { Button } from "@/components/ui/button";
import { getAccessGraph } from "@/lib/api";

const PROTOCOLS = ["any", "tcp", "udp"];

const edgeId = (source: string, target: string, index: number) => `${source}-${target}-${index}`;

export function AccessMapPage() {
  const { configId = "" } = useParams<{ configId: string }>();
  const [protocol, setProtocol] = useState("any");
  const [selectedEdge, setSelectedEdge] = useState<string | null>(null);
  const [focusedNode, setFocusedNode] = useState<string | null>(null);

  const query = useQuery({
    queryKey: ["access-graph", configId, protocol],
    queryFn: () => getAccessGraph(configId, protocol),
  });

  const data = query.data ?? { nodes: [], edges: [] };

  // Zone ids are pfSense's technical names (opt1, tunnel-0). Everything the user
  // reads must use the display label, the same as the nodes on the canvas.
  const labelOf = (id: string) => data.nodes.find((node) => node.id === id)?.label ?? id;

  const shownEdges = useMemo(
    () =>
      data.edges
        .map((edge, index) => ({ edge, id: edgeId(edge.source, edge.target, index) }))
        .filter(
          ({ edge }) =>
            !focusedNode || edge.source === focusedNode || edge.target === focusedNode,
        ),
    [data.edges, focusedNode],
  );

  // A focused zone stays visible even with no flows, otherwise clicking a zone
  // that reaches nothing would make it vanish under the click.
  const visibleNodeIds = useMemo(() => {
    if (!focusedNode) return null;
    const ids = new Set<string>([focusedNode]);
    for (const { edge } of shownEdges) {
      ids.add(edge.source);
      ids.add(edge.target);
    }
    return ids;
  }, [focusedNode, shownEdges]);

  const visibleEdgeIds = useMemo(
    () => (focusedNode ? new Set(shownEdges.map(({ id }) => id)) : null),
    [focusedNode, shownEdges],
  );

  if (query.isError) {
    return (
      <div
        role="alert"
        className="rounded-md border border-destructive bg-card p-4 text-sm text-destructive"
      >
        {query.error.message}
      </div>
    );
  }

  const canvasEdges = data.edges.map((edge, index) => ({
    id: edgeId(edge.source, edge.target, index),
    source: edge.source,
    target: edge.target,
    label: edge.ports,
  }));
  const selected = data.edges.find(
    (edge, index) => edgeId(edge.source, edge.target, index) === selectedEdge,
  );

  const toggleFocus = (nodeId: string) => {
    setFocusedNode((current) => (current === nodeId ? null : nodeId));
    setSelectedEdge(null);
  };

  const clearFocus = () => {
    setFocusedNode(null);
    setSelectedEdge(null);
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Access map</h1>
          <p className="text-sm text-muted-foreground">
            An arrow means every firewall on the way allows at least some traffic. Drag zones to
            untangle the graph. Click a zone to keep only its flows, click it again to bring the
            rest back.
          </p>
        </div>
        <label className="text-sm" htmlFor="protocol">
          <span className="block pb-1 text-muted-foreground">Protocol</span>
          <select
            id="protocol"
            className="cursor-pointer rounded-md border border-input bg-card px-2 py-1.5"
            value={protocol}
            onChange={(event) => setProtocol(event.target.value)}
          >
            {PROTOCOLS.map((item) => (
              <option key={item} value={item}>
                {item}
              </option>
            ))}
          </select>
        </label>
      </div>

      {focusedNode && (
        <div className="flex flex-wrap items-center gap-3 rounded-md border border-primary bg-card px-4 py-2 text-sm">
          <span>
            Showing only flows that touch <strong>{labelOf(focusedNode)}</strong>
          </span>
          <Button type="button" variant="outline" size="sm" onClick={clearFocus}>
            Show all zones
          </Button>
        </div>
      )}

      <FlowCanvas
        nodes={data.nodes}
        edges={canvasEdges}
        onEdgeClick={setSelectedEdge}
        onNodeClick={toggleFocus}
        onPaneClick={clearFocus}
        visibleNodeIds={visibleNodeIds}
        visibleEdgeIds={visibleEdgeIds}
        directed
      />

      {/*
       * The same flows as a list. The canvas alone is unreadable to a screen
       * reader and hides port labels behind hover, so the list is the accessible
       * path to the same data, not a duplicate.
       */}
      <section className="rounded-lg border bg-card">
        <h2 className="border-b px-4 py-2 text-sm font-medium">
          {focusedNode
            ? `Flows touching ${labelOf(focusedNode)} (${shownEdges.length})`
            : `Allowed flows (${shownEdges.length})`}
        </h2>
        {shownEdges.length === 0 ? (
          <p className="px-4 py-3 text-sm text-muted-foreground">
            {focusedNode
              ? `No flows touch ${labelOf(focusedNode)} for this protocol.`
              : "No traffic is allowed between zones for this protocol."}
          </p>
        ) : (
          <ul className="divide-y">
            {shownEdges.map(({ edge, id }) => (
              <li key={id}>
                <button
                  type="button"
                  onClick={() => setSelectedEdge(id)}
                  aria-pressed={selectedEdge === id}
                  className={`flex w-full cursor-pointer items-baseline gap-3 px-4 py-2 text-left text-sm transition-colors duration-150 hover:bg-muted ${
                    selectedEdge === id ? "bg-muted" : ""
                  }`}
                >
                  <span className="font-medium">
                    {labelOf(edge.source)} → {labelOf(edge.target)}
                  </span>
                  <span className="tabular text-muted-foreground">{edge.ports}</span>
                  {edge.truncated && (
                    <span className="text-accent">chain left the loaded firewalls</span>
                  )}
                </button>
              </li>
            ))}
          </ul>
        )}
      </section>

      {selected && (
        <section className="space-y-2 rounded-lg border bg-card p-4">
          <h2 className="font-medium">
            {labelOf(selected.source)} → {labelOf(selected.target)} on ports{" "}
            <span className="tabular">{selected.ports}</span>
          </h2>
          <ul className="space-y-1 text-sm">
            {selected.rules.map((rule) => (
              <li key={`${rule.interface}-${rule.seq}`}>
                <span className="text-muted-foreground">
                  #{rule.seq} on {rule.interface}
                  {rule.floating ? " (floating)" : ""}
                  {rule.synthetic ? " (implicit)" : ""} —{" "}
                </span>
                {rule.descr || "(no description)"}
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}
