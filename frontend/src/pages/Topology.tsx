import { useQuery } from "@tanstack/react-query";
import { useParams } from "react-router-dom";

import { FlowCanvas } from "@/components/graph/FlowCanvas";
import { getTopology } from "@/lib/api";

export function TopologyPage() {
  const { configId = "" } = useParams<{ configId: string }>();
  const query = useQuery({
    queryKey: ["topology", configId],
    queryFn: () => getTopology(configId),
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

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Topology</h1>
        <p className="text-sm text-muted-foreground">
          Subnets attached directly to the firewall. Networks behind an internal router are not
          shown, because static routes are outside this tool&apos;s scope. Dashed outlines are VLANs
          and VPN tunnels.
        </p>
      </div>
      <FlowCanvas
        nodes={data.nodes}
        edges={data.edges.map((edge, index) => ({
          id: `${edge.source}-${edge.target}-${index}`,
          source: edge.source,
          target: edge.target,
          dashed: edge.kind === "tunnel",
        }))}
      />
    </div>
  );
}
