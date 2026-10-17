export function scanEngineEvidence(statuses?: Record<string, string>) {
  const entries = Object.entries(statuses ?? {});
  const names = [...new Set(["syft", "trivy", "grype", ...entries.map(([name]) => name)])];
  const engines = names.map((name) => ({ name, status: statuses?.[name] === "succeeded" ? "succeeded" : statuses?.[name] === "failed" ? "failed" : "not reported" }));
  const message = entries.length === 0
    ? "This scan has no recorded engine outcomes. Rescan to verify scanner coverage."
    : engines.some(({ status }) => status === "failed")
      ? "Some scanners failed. Findings may be incomplete; resolve the failure and rescan."
      : engines.some(({ status }) => status === "not reported")
        ? "Some scanners did not report an outcome. This scan does not establish full scanner coverage."
        : "Syft, Trivy and Grype completed successfully. Review findings and artifact evidence below.";
  return { engines, message };
}

export function artifactIssue(report?: { status?: string; reason?: string }, error?: unknown): string | null {
  if (error) {
    const status = (error as { response?: { status?: number } }).response?.status;
    if (status !== 404) return "Evidence could not be loaded. Try again.";
  }
  if (report?.status === "error") return "Inspection failed. " + (report.reason || "Resolve the scanner failure and rescan.");
  if (report?.status === "unavailable" || report?.status === "skipped") return "Inspection unavailable. " + (report.reason || "Rescan when this inspection is available.");
  return null;
}
