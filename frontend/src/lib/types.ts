export type Verdict = "pass" | "block" | "reject" | "partial";

/**
 * A rule can also be "match": a floating shaper rule that assigns a queue and
 * decides nothing. It never appears as a verdict, only as a rule's own action.
 */
export type RuleAction = Verdict | "match";

export interface ParseWarning {
  path: string;
  message: string;
  severity: "info" | "warning" | "error";
}

export interface FirewallMeta {
  id: string;
  name: string;
  filename: string;
  version: string | null;
}

/** Warnings carry the firewall that raised them once a workspace holds several. */
export interface TaggedWarning extends ParseWarning {
  firewall: string;
}

export interface ConfigMeta {
  config_id: string;
  filename: string;
  version: string | null;
  hostname: string;
  firewalls: FirewallMeta[];
  counts: Record<string, number>;
  warnings: TaggedWarning[];
}

export interface Interface {
  firewall: string;
  name: string;
  descr: string;
  if_: string;
  ipaddr: string | null;
  subnet: number | null;
  enabled: boolean;
  is_vlan: boolean;
  vlan_tag: number | null;
  parent_if: string | null;
}

export interface Alias {
  firewall: string;
  name: string;
  type: string;
  items: string[];
  descr: string;
  resolved_addresses?: string[] | null;
  resolved_ports?: string | null;
  error?: string | null;
}

export interface AddrSpec {
  any: boolean;
  network: string | null;
  address: string | null;
  not_: boolean;
  port: string | null;
}

export interface FilterRule {
  firewall: string;
  seq: number;
  interfaces: string[];
  floating: boolean;
  quick: boolean;
  direction: string;
  action: RuleAction;
  disabled: boolean;
  ipprotocol: string;
  protocol: string;
  source: AddrSpec;
  destination: AddrSpec;
  descr: string;
  tracker: string | null;
  synthetic: boolean;
}

export interface PortForward {
  interface: string;
  protocol: string;
  destination: AddrSpec;
  target: string;
  local_port: string | null;
  disabled: boolean;
  descr: string;
}

export interface OneToOne {
  interface: string;
  external: string;
  internal: string;
  disabled: boolean;
  descr: string;
}

export interface OutboundRule {
  interface: string;
  source: string;
  destination: string;
  target: string;
  descr: string;
}

export interface NatConfig {
  firewall: string;
  port_forwards: PortForward[];
  one_to_one: OneToOne[];
  outbound: OutboundRule[];
}

export interface RuleRef {
  seq: number;
  interface: string;
  action: RuleAction;
  descr: string;
  tracker: string | null;
  floating: boolean;
  quick: boolean;
  synthetic: boolean;
}

export interface GraphNode {
  id: string;
  label: string;
  kind: "firewall" | "interface" | "vlan" | "tunnel" | "internet";
  subnet: string | null;
  /** True when more than one firewall sits on this network. */
  shared?: boolean;
  firewalls?: string[];
}

export interface TopologyEdge {
  source: string;
  target: string;
  kind: "link" | "tunnel";
}

export interface AccessEdge {
  source: string;
  target: string;
  ports: string;
  rules: RuleRef[];
  /** The chain left the loaded firewalls before this flow could be settled. */
  truncated?: boolean;
}

export interface Hop {
  firewall_id: string;
  firewall_name: string;
  in_interface: string;
  verdict: Verdict;
  decided_by: RuleRef | null;
  out_interface: string | null;
  next_hop: string | null;
  translated_address: string | null;
  translated_port: number | null;
}

export interface PathResult {
  verdict: Verdict | "unrouted";
  truncated: boolean;
  stopped_reason: string | null;
  hops: Hop[];
}

export interface TraceEntry {
  rule: RuleRef;
  matched: boolean;
  reason: string;
}

export interface CheckResult {
  kind: "point";
  verdict: Verdict;
  /** Per-protocol answers when the query asked for "any". */
  per_protocol: Record<string, Verdict> | null;
  per_protocol_rules: Record<string, RuleRef | null> | null;
  decided_by: RuleRef | null;
  in_interface: string;
  translated_address: string | null;
  translated_port: number | null;
  unresolved: boolean;
  trace: TraceEntry[];
}

/** One part of the source x destination space, with the rule that decided it. */
export interface PathRegion {
  sources: string[];
  destinations: string[];
  verdict: Verdict;
  decided_by: RuleRef | null;
  translated_address: string | null;
  translated_port: number | null;
  translated_via: string | null;
}

export interface CheckRegions {
  kind: "regions";
  in_interface: string;
  unresolved: boolean;
  translated_address: string | null;
  translated_port: number | null;
  regions: PathRegion[];
}

export type CheckResponse = CheckResult | CheckRegions;

export interface PathRegionResult {
  sources: string[];
  destinations: string[];
  verdict: Verdict | "unrouted";
  truncated: boolean;
  stopped_reason: string | null;
  hops: Hop[];
}

export interface PathRegions {
  kind: "regions";
  regions: PathRegionResult[];
}

export type PathResponse = (PathResult & { kind: "point" }) | PathRegions;

export interface Region {
  addresses: string[];
  ports: string;
  verdict: Verdict;
  decided_by: RuleRef | null;
  /** Set when the region only holds for one protocol; null means all of them. */
  protocol: string | null;
}

export interface SourceRegion {
  in_interface: string;
  addresses: string[];
  verdict: Verdict;
  decided_by: RuleRef | null;
  protocol: string | null;
}

export interface RiskSubject {
  id: string;
  label: string;
  kind: "interface" | "tunnel" | "alias";
  cidrs: string[];
}

export interface Exposure {
  firewall: string;
  subject: RiskSubject;
  reaches_other_subnets_any_port: string[];
  reaches_internet: boolean;
  internet_ports: string;
  reachable_from_all_internal: boolean;
  inbound_internal_ports: string;
  reachable_from_internet: boolean;
  inbound_internet_ports: string;
}

export interface PortAccess {
  firewall: string;
  source_id: string;
  source_label: string;
  destination_cidrs: string[];
  ports: string;
  rule: RuleRef | null;
}

export interface DenyAllFinding {
  firewall: string;
  kind: "block-all-not-quick" | "unreachable-rule";
  interface: string;
  rule: RuleRef;
  detail: string;
}

export interface RiskReport {
  exposures: Exposure[];
  deny_all: DenyAllFinding[];
}
