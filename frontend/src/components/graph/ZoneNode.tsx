import { Handle, type Node, type NodeProps, Position } from "@xyflow/react";

export type ZoneNodeType = Node<
  { label: string; subnet: string | null; kind: string },
  "zone"
>;

const KIND_STYLE: Record<string, string> = {
  firewall: "border-primary border-2 font-semibold",
  interface: "border-border",
  vlan: "border-border border-dashed",
  tunnel: "border-accent border-dashed",
  internet: "border-muted-foreground border-2",
};

export function ZoneNode({ data }: NodeProps<ZoneNodeType>) {
  return (
    <div
      className={`min-w-36 rounded-md border bg-card px-4 py-2 text-center text-sm shadow-sm ${
        KIND_STYLE[data.kind] ?? "border-border"
      }`}
    >
      <Handle type="target" position={Position.Top} />
      <div>{data.label}</div>
      {data.subnet && <div className="tabular text-xs text-muted-foreground">{data.subnet}</div>}
      <Handle type="source" position={Position.Bottom} />
    </div>
  );
}
