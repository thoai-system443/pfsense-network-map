import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useParams } from "react-router-dom";

import { Button } from "@/components/ui/button";
import { getPortAccess, getRiskReport } from "@/lib/api";
import type { Exposure, PortAccess } from "@/lib/types";

/** A dash reads better than an empty cell when the answer is a definite "no". */
const NONE = "—";

function Flag({ on, detail }: { on: boolean; detail?: string }) {
  if (!on) return <span className="text-muted-foreground">{NONE}</span>;
  return (
    <span className="font-medium text-destructive">
      yes{detail ? <span className="tabular font-normal"> ({detail})</span> : null}
    </span>
  );
}

export function RiskPage() {
  const { configId = "" } = useParams<{ configId: string }>();
  const [port, setPort] = useState("");
  const [protocol, setProtocol] = useState("tcp");
  const [searched, setSearched] = useState<string | null>(null);

  const report = useQuery({
    queryKey: ["risk", configId],
    queryFn: () => getRiskReport(configId),
  });

  const portSearch = useMutation<PortAccess[], Error>({
    mutationFn: () => getPortAccess(configId, Number(port), protocol),
    onSuccess: () => setSearched(port),
  });

  if (report.isError) {
    return (
      <div
        role="alert"
        className="rounded-md border border-destructive bg-card p-4 text-sm text-destructive"
      >
        {report.error.message}
      </div>
    );
  }

  const data = report.data ?? { exposures: [], unoccupied_grants: [], deny_all: [] };

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Risk</h1>
        <p className="max-w-3xl text-sm text-muted-foreground">
          Everything below is derived from the same evaluation the Search page uses, so a finding
          here always matches what a path check reports for the same traffic.
        </p>
      </div>

      <ExposureTable exposures={data.exposures} />

      <section className="space-y-2">
        <h2 className="font-medium">Who reaches a port</h2>
        <p className="text-sm text-muted-foreground">
          Every source allowed to reach anything at all on this port, across all destinations.
        </p>
        <form
          className="flex flex-wrap items-end gap-4"
          onSubmit={(event) => {
            event.preventDefault();
            portSearch.mutate();
          }}
        >
          <label className="text-sm" htmlFor="risk-port">
            <span className="block pb-1 text-muted-foreground">Port</span>
            <input
              id="risk-port"
              className="tabular w-40 rounded-md border border-input bg-card px-2 py-1.5"
              value={port}
              placeholder="5432"
              onChange={(event) => setPort(event.target.value)}
            />
          </label>
          <label className="text-sm" htmlFor="risk-protocol">
            <span className="block pb-1 text-muted-foreground">Protocol</span>
            <select
              id="risk-protocol"
              className="cursor-pointer rounded-md border border-input bg-card px-2 py-1.5"
              value={protocol}
              onChange={(event) => setProtocol(event.target.value)}
            >
              {["any", "tcp", "udp"].map((item) => (
                <option key={item} value={item}>
                  {item}
                </option>
              ))}
            </select>
          </label>
          <Button type="submit" disabled={!port || portSearch.isPending}>
            Who reaches it
          </Button>
        </form>

        {portSearch.isError && (
          <div role="alert" className="text-sm text-destructive">
            {portSearch.error.message}
          </div>
        )}

        {portSearch.data &&
          (portSearch.data.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              Nothing reaches port {searched} on {protocol}.
            </p>
          ) : (
            <Table label="Sources reaching the port" headers={["Source", "Destinations", "Ports", "Allowed by"]}>
              {portSearch.data.map((row, index) => (
                <tr key={index} className="align-top">
                  <td className="px-4 py-2 font-medium">{row.source_label}</td>
                  <td className="tabular px-4 py-2">{row.destination_cidrs.join(", ")}</td>
                  <td className="tabular px-4 py-2">{row.ports}</td>
                  <td className="px-4 py-2">{row.rule?.descr || "(no description)"}</td>
                </tr>
              ))}
            </Table>
          ))}
      </section>

      <section className="space-y-2">
        <h2 className="font-medium">Address space granted to nothing</h2>
        <p className="max-w-3xl text-sm text-muted-foreground">
          A rule written wider than the objects that actually exist hands the same access to every
          address in the gap, the moment anything appears there. That never shows in the rule table.
        </p>
        {data.unoccupied_grants.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No unoccupied address space is granted by any pass rule.
          </p>
        ) : (
          <Table
            label="Address space granted to nothing"
            headers={["Rule", "Interface", "Side", "Granted", "Unoccupied", "Addresses"]}
          >
            {data.unoccupied_grants.map((grant, index) => (
              <tr key={index} className="align-top">
                <td className="px-4 py-2">{grant.rule.descr || "(no description)"}</td>
                <td className="tabular px-4 py-2">{grant.interface}</td>
                <td className="px-4 py-2">{grant.side}</td>
                <td className="tabular px-4 py-2">{grant.granted_cidrs.join(", ")}</td>
                <td className="tabular px-4 py-2">{grant.unoccupied_cidrs.join(", ")}</td>
                <td className="tabular px-4 py-2 font-medium text-destructive">
                  {grant.unoccupied_addresses.toLocaleString("en-US")}
                </td>
              </tr>
            ))}
          </Table>
        )}
      </section>

      <section className="space-y-2">
        <h2 className="font-medium">Deny-all checks</h2>
        {data.deny_all.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            Every block-all rule stops evaluation, and no rule sits stranded behind one.
          </p>
        ) : (
          <ul className="space-y-2">
            {data.deny_all.map((finding, index) => (
              <li key={index} className="rounded-md border border-destructive bg-card p-3 text-sm">
                <div className="font-medium">
                  <span className="tabular">{finding.interface}</span> —{" "}
                  {finding.rule.descr || "(no description)"}
                </div>
                <p className="text-muted-foreground">{finding.detail}</p>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

function ExposureTable({ exposures }: { exposures: Exposure[] }) {
  return (
    <section className="space-y-2">
      <h2 className="font-medium">Exposure by object</h2>
      <Table
        label="Exposure by object"
        headers={[
          "Object",
          "Addresses",
          "Reaches other subnets on every port",
          "Reaches the internet",
          "Reachable from every internal zone",
          "Reachable from the internet",
        ]}
      >
        {exposures.map((exposure) => (
          <tr key={exposure.subject.id} className="align-top">
            <td className="px-4 py-2 font-medium">{exposure.subject.label}</td>
            <td className="tabular px-4 py-2">{exposure.subject.cidrs.join(", ")}</td>
            <td className="px-4 py-2">
              {exposure.reaches_other_subnets_any_port.length > 0 ? (
                <span className="font-medium text-destructive">
                  {exposure.reaches_other_subnets_any_port.join(", ")}
                </span>
              ) : (
                <span className="text-muted-foreground">{NONE}</span>
              )}
            </td>
            <td className="px-4 py-2">
              <Flag on={exposure.reaches_internet} detail={exposure.internet_ports} />
            </td>
            <td className="px-4 py-2">
              <Flag
                on={exposure.reachable_from_all_internal}
                detail={exposure.inbound_internal_ports}
              />
            </td>
            <td className="px-4 py-2">
              <Flag
                on={exposure.reachable_from_internet}
                detail={exposure.inbound_internet_ports}
              />
            </td>
          </tr>
        ))}
      </Table>
    </section>
  );
}

function Table({
  label,
  headers,
  children,
}: {
  // Four tables share this page; without a name a screen reader announces each
  // of them as just "table".
  label: string;
  headers: string[];
  children: React.ReactNode;
}) {
  return (
    <div className="overflow-x-auto rounded-lg border bg-card">
      <table aria-label={label} className="w-full text-left text-sm">
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
