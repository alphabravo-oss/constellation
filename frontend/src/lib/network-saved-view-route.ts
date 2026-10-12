import { normalizeNetworkSavedViewSnapshot, type NetworkSavedViewSnapshot } from "./network-saved-views";

export const NETWORK_VIEW_PARAM = "network_view";
export function networkViewSnapshotFromParams(params: URLSearchParams): NetworkSavedViewSnapshot | null {
  const raw = params.get(NETWORK_VIEW_PARAM);
  if (!raw || raw.length > 100_000) return null;
  try { return normalizeNetworkSavedViewSnapshot(JSON.parse(raw)); } catch { return null; }
}
export function networkViewHref(clusterID: string, params: URLSearchParams, hash = "", destination: "network" | "new" | "import" | "pcap" = "network", snapshot?: NetworkSavedViewSnapshot) {
  const query = new URLSearchParams(params);
  if (snapshot) query.set(NETWORK_VIEW_PARAM, JSON.stringify(snapshot));
  const suffix = destination === "network" ? "" : destination === "pcap" ? "/pcap/new" : `/views/${destination}`;
  return `/clusters/${encodeURIComponent(clusterID)}/network${suffix}${query.size ? `?${query}` : ""}${hash ? `#${hash.replace(/^#/, "")}` : ""}`;
}
