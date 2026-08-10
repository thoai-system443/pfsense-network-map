import { useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { useParams, useSearchParams } from "react-router-dom";

import { Button } from "@/components/ui/button";
import { queryCheck, queryFrom, queryTo } from "@/lib/api";
import type { CheckResult, Region, SourceRegion, Verdict } from "@/lib/types";

type Tab = "check" | "from" | "to";

const TABS: { id: Tab; label: string }[] = [
  { id: "check", label: "Path check" },
  { id: "from", label: "From" },
  { id: "to", label: "To" },
];

const VERDICT_STYLE: Record<Verdict, string> = {
  pass: "text-[var(--success)]",
  block: "text-destructive",
  reject: "text-accent",
};

export function SearchPage() {
  const { configId = "" } = useParams<{ configId: string }>();
  const [params] = useSearchParams();
  const [tab, setTab] = useState<Tab>("check");
  const [source, setSource] = useState(params.get("source") ?? "");
  const [destination, setDestination] = useState(params.get("destination") ?? "");
  const [port, setPort] = useState("");
  const [protocol, setProtocol] = useState("tcp");

  const check = useMutation<CheckResult, Error>({
    mutationFn: () =>
      queryCheck(configId, { source, destination, port: port ? Number(port) : null, protocol }),
  });
  const from = useMutation<Region[], Error>({
    mutationFn: () => queryFrom(configId, { source, protocol }),
  });
  const to = useMutation<SourceRegion[], Error>({
    mutationFn: () =>
      queryTo(configId, { destination, port: port ? Number(port) : null, protocol }),
  });

  const active = tab === "check" ? check : tab === "from" ? from : to;

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Search</h1>
        <p className="text-sm text-muted-foreground">
          Every field accepts an IP, a CIDR, an alias name, or an interface name.
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
          <Field id="port" label="Port" value={port} onChange={setPort} placeholder="443" />
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
          {tab === "check" ? "Check" : "Explore"}
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

      {tab === "check" && check.data && <CheckOutcome result={check.data} />}
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

function Unresolved() {
  return (
    <p className="text-sm text-accent">
      This result involves an alias that could not be resolved offline, so it may be incomplete.
    </p>
  );
}

function CheckOutcome({ result }: { result: CheckResult }) {
  return (
    <section className="space-y-3 rounded-lg border bg-card p-4">
      <p className={`text-2xl font-semibold uppercase ${VERDICT_STYLE[result.verdict]}`}>
        {result.verdict}
      </p>
      <p className="text-sm text-muted-foreground">
        Entered on interface <span className="tabular">{result.in_interface}</span>
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
      <p className="text-sm">
        {result.decided_by
          ? `Decided by rule #${result.decided_by.seq} on ${result.decided_by.interface}: ${
              result.decided_by.descr || "(no description)"
            }`
          : "No rule matched — the implicit default deny applied."}
      </p>
      {result.unresolved && <Unresolved />}
      {result.trace.length > 0 && (
        <details className="text-sm">
          <summary className="cursor-pointer text-muted-foreground">
            Rules examined ({result.trace.length})
          </summary>
          <ol className="mt-2 space-y-1">
            {result.trace.map((entry, index) => (
              <li key={index} className={entry.matched ? "" : "text-muted-foreground"}>
                #{entry.rule.seq} {entry.rule.descr || "(no description)"} — {entry.reason}
              </li>
            ))}
          </ol>
        </details>
      )}
    </section>
  );
}

function ResultTable({ headers, children }: { headers: string[]; children: React.ReactNode }) {
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

function RegionTable({ regions }: { regions: Region[] }) {
  return (
    <ResultTable headers={["Destinations", "Ports", "Verdict", "Decided by"]}>
      {regions.map((region, index) => (
        <tr key={index} className="align-top">
          <td className="tabular px-4 py-2">{region.addresses.join(", ")}</td>
          <td className="tabular px-4 py-2">{region.ports}</td>
          <td className={`px-4 py-2 font-medium ${VERDICT_STYLE[region.verdict]}`}>
            {region.verdict}
          </td>
          <td className="px-4 py-2">{region.decided_by?.descr || "default deny"}</td>
        </tr>
      ))}
    </ResultTable>
  );
}

function SourceTable({ regions }: { regions: SourceRegion[] }) {
  return (
    <ResultTable headers={["Interface", "Sources", "Verdict", "Decided by"]}>
      {regions.map((region, index) => (
        <tr key={index} className="align-top">
          <td className="tabular px-4 py-2">{region.in_interface}</td>
          <td className="tabular px-4 py-2">{region.addresses.join(", ")}</td>
          <td className={`px-4 py-2 font-medium ${VERDICT_STYLE[region.verdict]}`}>
            {region.verdict}
          </td>
          <td className="px-4 py-2">{region.decided_by?.descr || "default deny"}</td>
        </tr>
      ))}
    </ResultTable>
  );
}
