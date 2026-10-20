import { detailPath, type RiskTabProps } from "./workspace";
export function EvidenceUnavailable({ workspace, evidence }: RiskTabProps & { evidence: string }) {
  return <div className="space-y-3 rounded-md border border-border bg-card p-4">
    <h2 className="text-sm font-semibold">{evidence} mapping not reported</h2>
    <p className="text-sm text-muted-foreground">The entity response does not provide a verified mapping to {evidence.toLowerCase()} evidence. Nearby names and unrelated cluster records are not included.</p>
    <a href={detailPath(workspace)} className="text-sm text-link">Review the exact entity detail</a>
  </div>;
}
