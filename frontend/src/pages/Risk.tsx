import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useParams } from "react-router-dom";

import { Button } from "@/components/ui/button";
import { getPortAccess, getRiskReport } from "@/lib/api";
import { downloadCsv, toCsv } from "@/lib/csv";
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
  // Hides only the outbound direction. Traffic coming in from the internet is
  // never hidden: that is the exposure worth knowing about.
  const [hideOutbound, setHideOutbound] = useState(true);
  const [searched, setSearched] = useState<string | null>(null);

  const report = useQuery({
    queryKey: ["risk", configId],
    queryFn: () => getRiskReport(configId),
  });

  const portSearch = useMutation<PortAccess[], Error>({
    mutationFn: () => getPortAccess(configId, Number(port), protocol, hideOutbound),
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

  const data = report.data ?? { exposures: [], deny_all: [] };

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
        <p className="max-w-3xl text-sm text-muted-foreground">
          Every source allowed to reach anything at all on this port, across all destinations.
          <strong> Hide traffic out to the internet</strong> drops only the outbound direction, so a
          default-allow-outbound rule does not bury the rest. Traffic coming <em>in</em> from the
          internet is always shown.
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
          <label
            className="flex cursor-pointer items-center gap-2 pb-1.5 text-sm"
            htmlFor="risk-hide-outbound"
          >
            <input
              id="risk-hide-outbound"
              type="checkbox"
              className="size-4 cursor-pointer accent-[var(--primary)]"
              checked={hideOutbound}
              onChange={(event) => setHideOutbound(event.target.checked)}
            />
            Hide traffic out to the internet
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
              Nothing reaches port {searched} on {protocol}
              {hideOutbound ? ", ignoring traffic out to the internet" : ""}.
            </p>
          ) : (
            <Table
              label="Sources reaching the port"
              headers={["Firewall", "Source", "Destinations", "Ports", "Allowed by"]}
            >
              {portSearch.data.map((row, index) => (
                <tr key={index} className="align-top">
                  <td className="px-4 py-2 text-muted-foreground">{row.firewall}</td>
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
                  <span className="text-muted-foreground">{finding.firewall} / </span>
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

/** True when at least one of the four criteria fired. */
function isExposed(exposure: Exposure): boolean {
  return (
    exposure.reaches_other_subnets_any_port.length > 0 ||
    exposure.reaches_internet ||
    exposure.reachable_from_all_internal ||
    exposure.reachable_from_internet
  );
}

const EXPOSURE_HEADERS = [
  "Firewall",
  "Object",
  "Kind",
  "Addresses",
  "Reaches other subnets on every port",
  "Reaches the internet",
  "Internet ports",
  "Reachable from every internal zone",
  "Inbound internal ports",
  "Reachable from the internet",
  "Inbound internet ports",
];

const yesNo = (on: boolean) => (on ? "yes" : "no");

/** The exported rows. Each flag and its ports get a column of their own, because
 *  a spreadsheet cannot filter or sort on "yes (443, 8443)". */
export function exposureRows(exposures: Exposure[]): string[][] {
  return exposures.map((exposure) => [
    exposure.firewall,
    exposure.subject.label,
    exposure.subject.kind,
    exposure.subject.cidrs.join(", "),
    exposure.reaches_other_subnets_any_port.join(", "),
    yesNo(exposure.reaches_internet),
    exposure.reaches_internet ? exposure.internet_ports : "",
    yesNo(exposure.reachable_from_all_internal),
    exposure.reachable_from_all_internal ? exposure.inbound_internal_ports : "",
    yesNo(exposure.reachable_from_internet),
    exposure.reachable_from_internet ? exposure.inbound_internet_ports : "",
  ]);
}

function ExposureTable({ exposures }: { exposures: Exposure[] }) {
  const exposed = exposures.filter(isExposed);

  if (exposures.length > 0 && exposed.length === 0) {
    return (
      <section className="space-y-2">
        <h2 className="font-medium">Exposure by object</h2>
        <p className="text-sm text-muted-foreground">
          None of the {exposures.length} object{exposures.length === 1 ? "" : "s"} checked matches
          any of the four criteria.
        </p>
      </section>
    );
  }

  return (
    <section className="space-y-2" data-print-region>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="font-medium">Exposure by object</h2>
        <div className="flex gap-2" data-print-hide>
          <Button
            type="button"
            variant="outline"
            onClick={() =>
              downloadCsv("exposure-by-object.csv", toCsv(EXPOSURE_HEADERS, exposureRows(exposed)))
            }
          >
            Export CSV
          </Button>
          {/* The browser's own print-to-PDF. See the @media print block in
              index.css for what ends up on the page. */}
          <Button type="button" variant="outline" onClick={() => window.print()}>
            Export PDF
          </Button>
        </div>
      </div>
      {/*
        The count matters: a short table with no total reads as "the analysis
        found little", when it actually means "most objects came back clean".
      */}
      <p className="text-sm text-muted-foreground">
        {exposed.length} of {exposures.length} objects match at least one criterion. Objects with
        nothing flagged are left out, of the table and of the export alike.
      </p>
      <Table
        label="Exposure by object"
        headers={[
          "Firewall",
          "Object",
          "Addresses",
          "Reaches other subnets on every port",
          "Reaches the internet",
          "Reachable from every internal zone",
          "Reachable from the internet",
        ]}
      >
        {exposed.map((exposure) => (
          <tr key={`${exposure.firewall}-${exposure.subject.id}`} className="align-top">
            <td className="px-4 py-2 text-muted-foreground">{exposure.firewall}</td>
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
