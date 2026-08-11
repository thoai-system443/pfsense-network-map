import { useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { useParams, useSearchParams } from "react-router-dom";

import { Button } from "@/components/ui/button";
import { queryCheck, queryFrom, queryPath, queryTo } from "@/lib/api";
import type {
  CheckRegions,
  CheckResponse,
  CheckResult,
  PathRegions,
  PathResponse,
  PathResult,
  Region,
  SourceRegion,
} from "@/lib/types";

type Tab = "path" | "check" | "from" | "to";

const TABS: { id: Tab; label: string }[] = [
  { id: "path", label: "Across firewalls" },
  { id: "check", label: "Path check" },
  { id: "from", label: "From" },
  { id: "to", label: "To" },
];

const VERDICT_STYLE: Record<string, string> = {
  pass: "text-[var(--success)]",
  block: "text-destructive",
  reject: "text-accent",
  unrouted: "text-accent",
  // Deliberately not the pass colour: partial means some protocols are allowed
  // and others are not, and reading it as "allowed" is the mistake to prevent.
  partial: "text-accent",
};

const PROTOCOLS_IN_ANY = ["tcp", "udp", "icmp"];

export function SearchPage() {
  const { configId = "" } = useParams<{ configId: string }>();
  const [params] = useSearchParams();
  const [tab, setTab] = useState<Tab>("path");
  const [source, setSource] = useState(params.get("source") ?? "");
  const [destination, setDestination] = useState(
    params.get("destination") ?? "",
  );
  const [port, setPort] = useState("");
  const [protocol, setProtocol] = useState("tcp");

  const path = useMutation<PathResponse, Error>({
    mutationFn: () =>
      queryPath(configId, {
        source,
        destination,
        port: port ? Number(port) : null,
        protocol,
      }),
  });
  const check = useMutation<CheckResponse, Error>({
    mutationFn: () =>
      queryCheck(configId, {
        source,
        destination,
        port: port ? Number(port) : null,
        protocol,
      }),
  });
  const from = useMutation<Region[], Error>({
    mutationFn: () => queryFrom(configId, { source, protocol }),
  });
  const to = useMutation<SourceRegion[], Error>({
    mutationFn: () =>
      queryTo(configId, {
        destination,
        port: port ? Number(port) : null,
        protocol,
      }),
  });

  const active =
    tab === "path"
      ? path
      : tab === "check"
        ? check
        : tab === "from"
          ? from
          : to;

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Search</h1>
        <p className="text-sm text-muted-foreground">
          Every field accepts an IP, a CIDR, an alias name, or an interface
          name.
        </p>
      </div>

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

      <form
        className="flex flex-wrap items-end gap-4"
        onSubmit={(event) => {
          event.preventDefault();
          active.mutate();
        }}
      >
        {tab !== "to" && (
          <Field
            id="source"
            label="Source"
            value={source}
            onChange={setSource}
            placeholder="192.168.1.50, lan, WEB_SERVERS"
          />
        )}
        {tab !== "from" && (
          <Field
            id="destination"
            label="Destination"
            value={destination}
            onChange={setDestination}
            placeholder="8.8.8.8, opt1, 10.0.0.0/8"
          />
        )}
        {tab !== "from" && (
          <Field
            id="port"
            label="Port"
            value={port}
            onChange={setPort}
            placeholder="443"
          />
        )}
        <label className="text-sm" htmlFor="search-protocol">
          <span className="block pb-1 text-muted-foreground">Protocol</span>
          <select
            id="search-protocol"
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
        <Button type="submit" disabled={active.isPending}>
          {tab === "path" || tab === "check" ? "Check" : "Explore"}
        </Button>
      </form>

      {active.isError && (
        <div
          role="alert"
          className="rounded-md border border-destructive bg-card p-4 text-sm text-destructive"
        >
          {active.error.message}
        </div>
      )}

      {tab === "path" &&
        path.data &&
        (path.data.kind === "regions" ? (
          <PathRegionTable result={path.data} />
        ) : (
          <PathOutcome result={path.data} />
        ))}
      {tab === "check" &&
        check.data &&
        (check.data.kind === "regions" ? (
          <CheckRegionTable result={check.data} />
        ) : (
          <CheckOutcome result={check.data} />
        ))}
      {tab === "from" && from.data && <RegionTable regions={from.data} />}
      {tab === "to" && to.data && <SourceTable regions={to.data} />}
    </div>
  );
}

function Field({
  id,
  label,
  value,
  onChange,
  placeholder,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
}) {
  return (
    <label className="text-sm" htmlFor={id}>
      <span className="block pb-1 text-muted-foreground">{label}</span>
      <input
        id={id}
        className="tabular w-64 rounded-md border border-input bg-card px-2 py-1.5"
        value={value}
        placeholder={placeholder}
        onChange={(event) => onChange(event.target.value)}
      />
    </label>
  );
}

function PathOutcome({ result }: { result: PathResult }) {
  return (
    <section className="space-y-3 rounded-lg border bg-card p-4">
      <p
        className={`text-2xl font-semibold uppercase ${VERDICT_STYLE[result.verdict] ?? ""}`}
      >
        {result.verdict}
      </p>
      <p className="text-sm text-muted-foreground">
        A packet passes only if every firewall on the way allows it. The first
        one that refuses ends the walk.
      </p>
      <ol className="space-y-2">
        {result.hops.map((hop, index) => (
          <li key={index} className="rounded-md border p-3 text-sm">
            <div className="flex flex-wrap items-baseline gap-2">
              <span className="font-medium">{hop.firewall_name}</span>
              <span className="tabular text-muted-foreground">
                in {hop.in_interface}
                {hop.out_interface ? ` → out ${hop.out_interface}` : ""}
                {hop.next_hop ? ` → ${hop.next_hop}` : ""}
              </span>
              <span
                className={`font-medium uppercase ${VERDICT_STYLE[hop.verdict] ?? ""}`}
              >
                {hop.verdict}
              </span>
            </div>
            {hop.translated_address && (
              <p className="text-muted-foreground">
                NAT rewrote the destination to{" "}
                <code>
                  {hop.translated_address}:{hop.translated_port}
                </code>
              </p>
            )}
            <p className="text-muted-foreground">
              {hop.decided_by
                ? `Rule #${hop.decided_by.seq} on ${hop.decided_by.interface}: ${
                    hop.decided_by.descr || "(no description)"
                  }`
                : "No rule matched — the implicit default deny applied."}
            </p>
          </li>
        ))}
      </ol>
      {result.stopped_reason && (
        <p className="text-sm text-accent">
          The walk stopped early: {result.stopped_reason}. Anything past that
          point is unknown to this tool.
        </p>
      )}
    </section>
  );
}

function Unresolved() {
  return (
    <p className="text-sm text-accent">
      This result involves an alias that could not be resolved offline, so it
      may be incomplete.
    </p>
  );
}

function ProtocolBreakdown({ result }: { result: CheckResult }) {
  if (!result.per_protocol) return null;
  return (
    <div className="space-y-1">
      <p className="text-sm text-muted-foreground">
        &quot;any&quot; is not one question. Each protocol was checked on its
        own:
      </p>
      <ul className="flex flex-wrap gap-2">
        {PROTOCOLS_IN_ANY.filter((name) => result.per_protocol?.[name]).map(
          (name) => {
            const verdict = result.per_protocol![name];
            const rule = result.per_protocol_rules?.[name];
            return (
              <li key={name} className="rounded-md border px-3 py-1.5 text-sm">
                <span className="tabular font-medium">{name}</span>{" "}
                <span
                  className={`font-medium uppercase ${VERDICT_STYLE[verdict]}`}
                >
                  {verdict}
                </span>
                {rule && (
                  <span className="text-muted-foreground">
                    {" "}
                    — #{rule.seq} {rule.descr || "(no description)"}
                  </span>
                )}
              </li>
            );
          },
        )}
      </ul>
    </div>
  );
}

function PartialNotice() {
  return (
    <p className="rounded-md border border-accent bg-accent/10 p-3 text-sm">
      <span className="font-medium">Partial, not allowed.</span> Some protocols
      get through and others do not — read the breakdown below rather than
      treating this as a pass.
    </p>
  );
}

function CheckOutcome({ result }: { result: CheckResult }) {
  return (
    <section className="space-y-3 rounded-lg border bg-card p-4">
      <p
        className={`text-2xl font-semibold uppercase ${VERDICT_STYLE[result.verdict]}`}
      >
        {result.verdict}
      </p>
      {result.verdict === "partial" && <PartialNotice />}
      <ProtocolBreakdown result={result} />
      <p className="text-sm text-muted-foreground">
        Entered on interface{" "}
        <span className="tabular">{result.in_interface}</span>
      </p>
      {result.translated_address && (
        <p className="text-sm">
          NAT rewrote the destination to{" "}
          <code>
            {result.translated_address}:{result.translated_port}
          </code>{" "}
          before the filter ran.
        </p>
      )}
      {!result.per_protocol && (
        <p className="text-sm">
          {result.decided_by
            ? `Decided by rule #${result.decided_by.seq} on ${result.decided_by.interface}: ${
                result.decided_by.descr || "(no description)"
              }`
            : "No rule matched — the implicit default deny applied."}
        </p>
      )}
      {result.unresolved && <Unresolved />}
      {result.trace.length > 0 && (
        <details className="text-sm">
          <summary className="cursor-pointer text-muted-foreground">
            Rules examined ({result.trace.length})
          </summary>
          <ol className="mt-2 space-y-1">
            {result.trace.map((entry, index) => (
              <li
                key={index}
                className={entry.matched ? "" : "text-muted-foreground"}
              >
                #{entry.rule.seq} {entry.rule.descr || "(no description)"} —{" "}
                {entry.reason}
              </li>
            ))}
          </ol>
        </details>
      )}
    </section>
  );
}

function ResultTable({
  headers,
  children,
}: {
  headers: string[];
  children: React.ReactNode;
}) {
  return (
    <div className="overflow-x-auto rounded-lg border bg-card">
      <table className="w-full text-left text-sm">
        <thead>
          <tr className="border-b">
            {headers.map((header) => (
              <th
                key={header}
                className="px-4 py-2 font-medium text-muted-foreground"
              >
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

function RegionTable({ regions }: { regions: Region[] }) {
  return (
    <ResultTable
      headers={["Destinations", "Ports", "Protocol", "Verdict", "Decided by"]}
    >
      {regions.map((region, index) => (
        <tr key={index} className="align-top">
          <td className="tabular px-4 py-2">{region.addresses.join(", ")}</td>
          <td className="tabular px-4 py-2">{region.ports}</td>
          <td className="tabular px-4 py-2">{region.protocol ?? "all"}</td>
          <td
            className={`px-4 py-2 font-medium ${VERDICT_STYLE[region.verdict]}`}
          >
            {region.verdict}
          </td>
          <td className="px-4 py-2">
            {region.decided_by?.descr || "default deny"}
          </td>
        </tr>
      ))}
    </ResultTable>
  );
}

function SourceTable({ regions }: { regions: SourceRegion[] }) {
  return (
    <ResultTable
      headers={["Interface", "Sources", "Protocol", "Verdict", "Decided by"]}
    >
      {regions.map((region, index) => (
        <tr key={index} className="align-top">
          <td className="tabular px-4 py-2">{region.in_interface}</td>
          <td className="tabular px-4 py-2">{region.addresses.join(", ")}</td>
          <td className="tabular px-4 py-2">{region.protocol ?? "all"}</td>
          <td
            className={`px-4 py-2 font-medium ${VERDICT_STYLE[region.verdict]}`}
          >
            {region.verdict}
          </td>
          <td className="px-4 py-2">
            {region.decided_by?.descr || "default deny"}
          </td>
        </tr>
      ))}
    </ResultTable>
  );
}

function RegionVerdictCell({ verdict }: { verdict: string }) {
  return (
    <td
      className={`px-4 py-2 font-medium uppercase ${VERDICT_STYLE[verdict] ?? ""}`}
    >
      {verdict}
    </td>
  );
}

function CheckRegionTable({ result }: { result: CheckRegions }) {
  return (
    <section className="space-y-3">
      <p className="text-sm text-muted-foreground">
        A subnet is a set of addresses, and the ruleset can treat parts of it
        differently. Every part of what you asked about appears below with its
        own verdict. Entered on interface{" "}
        <span className="tabular">{result.in_interface}</span>.
      </p>
      <ResultTable
        headers={["Sources", "Destinations", "Verdict", "Decided by", "NAT"]}
      >
        {result.regions.map((region, index) => (
          <tr key={index} className="align-top">
            <td className="tabular px-4 py-2">{region.sources.join(", ")}</td>
            <td className="tabular px-4 py-2">
              {region.destinations.join(", ")}
            </td>
            <RegionVerdictCell verdict={region.verdict} />
            <td className="px-4 py-2">
              {region.decided_by?.descr || "default deny"}
            </td>
            <td className="tabular px-4 py-2 text-muted-foreground">
              {region.translated_address
                ? `${region.translated_address}${region.translated_port ? `:${region.translated_port}` : ""}`
                : "—"}
            </td>
          </tr>
        ))}
      </ResultTable>
      {result.unresolved && <Unresolved />}
    </section>
  );
}

function PathRegionTable({ result }: { result: PathRegions }) {
  return (
    <section className="space-y-3">
      <p className="text-sm text-muted-foreground">
        Hosts inside one subnet can enter at different firewalls and be refused
        at different hops, so each part of the space is walked separately.
      </p>
      <ResultTable headers={["Sources", "Destinations", "Verdict", "Path"]}>
        {result.regions.map((region, index) => (
          <tr key={index} className="align-top">
            <td className="tabular px-4 py-2">
              {region.sources.join(", ") || "—"}
            </td>
            <td className="tabular px-4 py-2">
              {region.destinations.join(", ") || "—"}
            </td>
            <RegionVerdictCell verdict={region.verdict} />
            <td className="px-4 py-2">
              <span className="tabular">
                {region.hops
                  .map((hop) => `${hop.firewall_name} (${hop.in_interface})`)
                  .join(" → ") || "—"}
              </span>
              {region.hops.some((hop) => hop.translated_address) && (
                <span className="block text-muted-foreground">
                  NAT →{" "}
                  {region.hops
                    .filter((hop) => hop.translated_address)
                    .map(
                      (hop) =>
                        `${hop.translated_address}:${hop.translated_port}`,
                    )
                    .join(", ")}
                </span>
              )}
              {region.stopped_reason && (
                <span className="block text-accent">
                  Stopped: {region.stopped_reason}
                </span>
              )}
            </td>
          </tr>
        ))}
      </ResultTable>
    </section>
  );
}
