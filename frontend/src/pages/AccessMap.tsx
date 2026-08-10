import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useParams } from "react-router-dom";

import { FlowCanvas } from "@/components/graph/FlowCanvas";
import { getAccessGraph } from "@/lib/api";

const PROTOCOLS = ["any", "tcp", "udp"];

export function AccessMapPage() {
  const { configId = "" } = useParams<{ configId: string }>();
  const [protocol, setProtocol] = useState("any");
  const [selectedEdge, setSelectedEdge] = useState<string | null>(null);

  const query = useQuery({
    queryKey: ["access-graph", configId, protocol],
    queryFn: () => getAccessGraph(configId, protocol),
  });

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

  const data = query.data ?? { nodes: [], edges: [] };
  const edgeId = (source: string, target: string, index: number) => `${source}-${target}-${index}`;
  // Zone ids are pfSense's technical names (opt1, tunnel-0). Everything the user
  // reads must use the display label, the same as the nodes on the canvas.
  const labels = new Map(data.nodes.map((node) => [node.id, node.label]));
  const labelOf = (id: string) => labels.get(id) ?? id;
  const edges = data.edges.map((edge, index) => ({
    id: edgeId(edge.source, edge.target, index),
    source: edge.source,
    target: edge.target,
    label: edge.ports,
  }));
  const selected = data.edges.find(
    (edge, index) => edgeId(edge.source, edge.target, index) === selectedEdge,
  );

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Access map</h1>
          <p className="text-sm text-muted-foreground">
            An arrow means at least some traffic is allowed. Click it to see which rules decided it.
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

      <FlowCanvas nodes={data.nodes} edges={edges} onEdgeClick={setSelectedEdge} directed />

      {/*
       * The same flows as a list. The canvas alone is unreadable to a screen
       * reader and hides port labels behind hover, so the list is the accessible
       * path to the same data, not a duplicate.
       */}
      <section className="rounded-lg border bg-card">
        <h2 className="border-b px-4 py-2 text-sm font-medium">
          Allowed flows ({data.edges.length})
        </h2>
        {data.edges.length === 0 ? (
          <p className="px-4 py-3 text-sm text-muted-foreground">
            No traffic is allowed between zones for this protocol.
          </p>
        ) : (
          <ul className="divide-y">
            {data.edges.map((edge, index) => {
              const id = edgeId(edge.source, edge.target, index);
              return (
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
                  </button>
                </li>
              );
            })}
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
