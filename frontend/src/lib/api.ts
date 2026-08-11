import { apiUrl } from "./config";
import type {
  AccessEdge,
  Alias,
  CheckResult,
  ConfigMeta,
  FilterRule,
  GraphNode,
  Interface,
  NatConfig,
  PortAccess,
  Region,
  RiskReport,
  SourceRegion,
  TopologyEdge,
} from "./types";

const base = `${apiUrl}/api/v1`;

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${base}${path}`, init);
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = (body as { detail?: string }).detail;
    throw new Error(detail ?? `request failed with status ${response.status}`);
  }
  return body as T;
}

function postJson<T>(path: string, payload: unknown): Promise<T> {
  return request<T>(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

export function uploadConfig(file: File): Promise<ConfigMeta> {
  const form = new FormData();
  form.append("file", file);
  return request<ConfigMeta>("/configs", { method: "POST", body: form });
}

export const getConfigMeta = (id: string) => request<ConfigMeta>(`/configs/${id}`);
export const getInterfaces = (id: string) => request<Interface[]>(`/configs/${id}/interfaces`);
export const getAliases = (id: string, resolved = false) =>
  request<Alias[]>(`/configs/${id}/aliases?resolved=${resolved}`);
export const getRules = (id: string, iface?: string) =>
  request<FilterRule[]>(`/configs/${id}/rules${iface ? `?interface=${iface}` : ""}`);
export const getNat = (id: string) => request<NatConfig>(`/configs/${id}/nat`);
export const getTopology = (id: string) =>
  request<{ nodes: GraphNode[]; edges: TopologyEdge[] }>(`/configs/${id}/topology`);
export const getAccessGraph = (id: string, protocol: string) =>
  request<{ nodes: GraphNode[]; edges: AccessEdge[] }>(
    `/configs/${id}/access-graph?protocol=${protocol}`,
  );

export const queryCheck = (
  id: string,
  body: { source: string; destination: string; port: number | null; protocol: string },
) => postJson<CheckResult>(`/configs/${id}/query/check`, body);

export const queryFrom = (id: string, body: { source: string; protocol: string }) =>
  postJson<Region[]>(`/configs/${id}/query/from`, body);

export const queryTo = (
  id: string,
  body: { destination: string; port: number | null; protocol: string },
) => postJson<SourceRegion[]>(`/configs/${id}/query/to`, body);

export const getRiskReport = (id: string) => request<RiskReport>(`/configs/${id}/risk`);

export const getPortAccess = (id: string, port: number, protocol: string) =>
  request<PortAccess[]>(`/configs/${id}/risk/port?port=${port}&protocol=${protocol}`);
