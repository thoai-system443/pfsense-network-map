import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";

import { getAliases, getInterfaces, getNat, getRules } from "@/lib/api";

type Tab = "interfaces" | "aliases" | "rules" | "nat";

const TABS: { id: Tab; label: string }[] = [
  { id: "interfaces", label: "Interfaces" },
  { id: "aliases", label: "Aliases" },
  { id: "rules", label: "Rules" },
  { id: "nat", label: "NAT" },
];

function matches(filter: string, values: (string | number | null | undefined)[]) {
  if (!filter) return true;
  const needle = filter.toLowerCase();
  return values.some((value) => String(value ?? "").toLowerCase().includes(needle));
}

export function InventoryPage() {
  const { configId = "" } = useParams<{ configId: string }>();
  const [tab, setTab] = useState<Tab>("interfaces");
  const [filter, setFilter] = useState("");

  const interfaces = useQuery({
    queryKey: ["interfaces", configId],
    queryFn: () => getInterfaces(configId),
    enabled: tab === "interfaces",
  });
  const aliases = useQuery({
    queryKey: ["aliases", configId],
    queryFn: () => getAliases(configId, true),
    enabled: tab === "aliases",
  });
  const rules = useQuery({
    queryKey: ["rules", configId],
    queryFn: () => getRules(configId),
    enabled: tab === "rules",
  });
  const nat = useQuery({
    queryKey: ["nat", configId],
    queryFn: () => getNat(configId),
    enabled: tab === "nat",
  });

  const searchLink = (source: string) =>
    `/c/${configId}/search?source=${encodeURIComponent(source)}`;

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Inventory</h1>
        <p className="text-sm text-muted-foreground">
          Everything the backup declares. Click an address or alias to search from it.
        </p>
      </div>

      <div className="flex flex-wrap items-end justify-between gap-4">
        <div role="tablist" className="flex gap-1 border-b">
          {TABS.map((item) => (
            <button
              key={item.id}
              type="button"
              role="tab"
              aria-selected={tab === item.id}
              className={`cursor-pointer border-b-2 px-4 py-2 text-sm transition-colors duration-150 ${
                tab === item.id
                  ? "border-primary font-medium text-foreground"
                  : "border-transparent text-muted-foreground hover:text-foreground"
              }`}
              onClick={() => setTab(item.id)}
            >
              {item.label}
            </button>
          ))}
        </div>
        <label className="text-sm" htmlFor="inventory-filter">
          <span className="block pb-1 text-muted-foreground">Filter</span>
          <input
            id="inventory-filter"
            className="tabular w-72 rounded-md border border-input bg-card px-2 py-1.5"
            value={filter}
            placeholder="IP, network, port, or name"
            onChange={(event) => setFilter(event.target.value)}
          />
        </label>
      </div>

      {tab === "interfaces" && (
        <Table headers={["Name", "Device", "Address", "VLAN", "Enabled"]}>
          {(interfaces.data ?? [])
            .filter((row) => matches(filter, [row.name, row.descr, row.ipaddr, row.if_]))
            .map((row) => (
              <tr key={row.name}>
                <td className="px-4 py-2 font-medium">{row.descr}</td>
                <td className="tabular px-4 py-2">{row.if_}</td>
                <td className="tabular px-4 py-2">
                  {row.ipaddr && row.subnet !== null ? (
                    <Link
                      className="cursor-pointer text-primary underline underline-offset-2"
                      to={searchLink(`${row.ipaddr}/${row.subnet}`)}
                    >
                      {row.ipaddr}/{row.subnet}
                    </Link>
                  ) : (
                    "—"
                  )}
                </td>
                <td className="tabular px-4 py-2">
                  {row.is_vlan ? `${row.vlan_tag} on ${row.parent_if}` : "—"}
                </td>
                <td className="px-4 py-2">{row.enabled ? "yes" : "no"}</td>
              </tr>
            ))}
        </Table>
      )}

      {tab === "aliases" && (
        <Table headers={["Name", "Type", "Members", "Resolved"]}>
          {(aliases.data ?? [])
            .filter((row) => matches(filter, [row.name, row.descr, ...row.items]))
            .map((row) => (
              <tr key={row.name} className="align-top">
                <td className="px-4 py-2">
                  <Link
                    className="cursor-pointer text-primary underline underline-offset-2"
                    to={searchLink(row.name)}
                  >
                    {row.name}
                  </Link>
                </td>
                <td className="px-4 py-2">{row.type}</td>
                <td className="tabular px-4 py-2">{row.items.join(", ")}</td>
                <td className="tabular px-4 py-2">
                  {row.error ? (
                    <span className="text-destructive">{row.error}</span>
                  ) : (
                    (row.resolved_addresses?.join(", ") ?? row.resolved_ports ?? "—")
                  )}
                </td>
              </tr>
            ))}
        </Table>
      )}

      {tab === "rules" && (
        <Table headers={["#", "Interface", "Action", "Protocol", "Description", "Flags"]}>
          {(rules.data ?? [])
            .filter((row) => matches(filter, [row.descr, row.protocol, ...row.interfaces]))
            .map((row) => (
              <tr key={row.seq} className={row.disabled ? "opacity-50" : ""}>
                <td className="tabular px-4 py-2">{row.seq}</td>
                <td className="tabular px-4 py-2">{row.interfaces.join(", ")}</td>
                <td className="px-4 py-2">{row.action}</td>
                <td className="px-4 py-2">{row.protocol}</td>
                <td className="px-4 py-2">{row.descr}</td>
                <td className="px-4 py-2 text-muted-foreground">
                  {[row.floating && "floating", row.quick && "quick", row.disabled && "disabled"]
                    .filter(Boolean)
                    .join(", ")}
                </td>
              </tr>
            ))}
        </Table>
      )}

      {tab === "nat" && nat.data && (
        <div className="space-y-6">
          <section className="space-y-2">
            <h2 className="font-medium">Port forwards</h2>
            <Table headers={["Interface", "Protocol", "Target", "Local port", "Description"]}>
              {nat.data.port_forwards
                .filter((row) => matches(filter, [row.descr, row.target, row.local_port]))
                .map((row, index) => (
                  <tr key={index}>
                    <td className="tabular px-4 py-2">{row.interface}</td>
                    <td className="px-4 py-2">{row.protocol}</td>
                    <td className="tabular px-4 py-2">
                      <Link
                        className="cursor-pointer text-primary underline underline-offset-2"
                        to={searchLink(row.target)}
                      >
                        {row.target}
                      </Link>
                    </td>
                    <td className="tabular px-4 py-2">{row.local_port ?? "—"}</td>
                    <td className="px-4 py-2">{row.descr}</td>
                  </tr>
                ))}
            </Table>
          </section>

          <section className="space-y-2">
            <h2 className="font-medium">Outbound NAT</h2>
            <p className="text-sm text-muted-foreground">
              Shown for reference only. Outbound NAT runs after the filter decision, so it never
              changes whether traffic is allowed.
            </p>
            <Table headers={["Interface", "Source", "Destination", "Target"]}>
              {nat.data.outbound
                .filter((row) => matches(filter, [row.source, row.destination, row.descr]))
                .map((row, index) => (
                  <tr key={index}>
                    <td className="tabular px-4 py-2">{row.interface}</td>
                    <td className="tabular px-4 py-2">{row.source}</td>
                    <td className="tabular px-4 py-2">{row.destination}</td>
                    <td className="px-4 py-2">{row.target}</td>
                  </tr>
                ))}
            </Table>
          </section>
        </div>
      )}
    </div>
  );
}

function Table({ headers, children }: { headers: string[]; children: React.ReactNode }) {
  return (
    <div className="overflow-x-auto rounded-lg border bg-card">
      <table className="w-full text-left text-sm">
        <thead>
          <tr className="border-b">
            {headers.map((header) => (
              <th key={header} className="px-4 py-2 font-medium text-muted-foreground">
                {header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y">{children}</tbody>
      </table>
    </div>
  );
}
