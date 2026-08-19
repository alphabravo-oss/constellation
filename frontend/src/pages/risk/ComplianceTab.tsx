import { useQuery } from "@tanstack/react-query";
import { compliance } from "@/api/client";

export default function ComplianceTab({ entityId }: { entityType: string; entityId: string }) {
  const q = useQuery({
    queryKey: ["risk-compliance", entityId],
    queryFn: () => compliance.summary(),
    enabled: !!entityId,
  });
  if (q.isPending) return <p className="text-xs text-muted-foreground">Loading…</p>;
  const frameworks = q.data?.frameworks ?? [];
  return (
    <ul className="space-y-1 text-xs" data-testid="risk-compliance-tab">
      {frameworks.map((f) => (
        <li key={f.framework} className="flex items-center justify-between rounded-md border border-border bg-card px-3 py-2">
          <span>{f.framework}</span>
          <span className="text-muted-foreground">{Math.round(f.pass_pct)}% pass</span>
        </li>
      ))}
    </ul>
  );
}
