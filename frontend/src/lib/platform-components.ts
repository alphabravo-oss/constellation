/**
 * Namespaces owned by the Kubernetes distribution or by the security/data
 * platform itself. Hiding these is a presentation concern only: collection,
 * detection, and enforcement continue to include them.
 *
 * Keep this list exact. Prefix matching would incorrectly hide customer
 * workloads such as `astronomer-screenshot-demo` or `constellation-api`.
 */
export const PLATFORM_NAMESPACES = new Set([
  "kube-system",
  "kube-public",
  "kube-node-lease",
  "constellation",
  "constellation-system",
  "astronomer",
  "astronomer-system",
  "astronomer-delivery-system",
  "astronomer-monitoring",
  "astronomer-trivy-system",
  "astronomer-logging",
  "astronomer-ingress-nginx",
  "astronomer-cert-manager",
  "astronomer-gatekeeper-system",
]);

export function isPlatformNamespace(namespace: string | null | undefined): boolean {
  return PLATFORM_NAMESPACES.has((namespace ?? "").trim().toLowerCase());
}

export function namespaceFromWorkloadID(workloadID: string | null | undefined): string {
  return (workloadID ?? "").trim().split("/", 1)[0] ?? "";
}

export function isPlatformWorkloadID(workloadID: string | null | undefined): boolean {
  return isPlatformNamespace(namespaceFromWorkloadID(workloadID));
}
