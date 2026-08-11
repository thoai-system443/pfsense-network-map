export type Verdict = "pass" | "block" | "reject";

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

export interface ConfigMeta {
  config_id: string;
  filename: string;
  version: string | null;
  hostname: string;
  counts: Record<string, number>;
  warnings: ParseWarning[];
}

export interface Interface {
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
}

export interface TraceEntry {
  rule: RuleRef;
  matched: boolean;
  reason: string;
}

export interface CheckResult {
  verdict: Verdict;
  decided_by: RuleRef | null;
  in_interface: string;
  translated_address: string | null;
  translated_port: number | null;
  unresolved: boolean;
  trace: TraceEntry[];
}

export interface Region {
  addresses: string[];
  ports: string;
  verdict: Verdict;
  decided_by: RuleRef | null;
}

export interface SourceRegion {
  in_interface: string;
  addresses: string[];
  verdict: Verdict;
  decided_by: RuleRef | null;
}

export interface RiskSubject {
  id: string;
  label: string;
  kind: "interface" | "tunnel" | "alias";
  cidrs: string[];
}

export interface Exposure {
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
  source_id: string;
  source_label: string;
  destination_cidrs: string[];
  ports: string;
  rule: RuleRef | null;
}

export interface DenyAllFinding {
  kind: "block-all-not-quick" | "unreachable-rule";
  interface: string;
  rule: RuleRef;
  detail: string;
}

export interface RiskReport {
  exposures: Exposure[];
  deny_all: DenyAllFinding[];
}
