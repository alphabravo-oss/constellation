import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";

interface Subfactor { name: string; description: string; score: number; raw: number; weight: number }
interface RiskBlock { composite: number; factors: Subfactor[] }
interface FindingWithRisk {
  id: string; title: string; severity: string; risk_score: number;
  risk?: RiskBlock;
}

export default function OverviewTab({ entityType, entityId }: { entityType: string; entityId: string }) {
  // For an entityType=finding we hit /findings/{id}; deployment → /deployments/{id};
  // everything else (asset) → /assets/{id}. All return enough data to render the
  // overview header + risk decomposition.
  const path =
    entityType === "finding" ? `/findings/${entityId}` :
    entityType === "deployment" ? `/deployments/${entityId}` :
    `/assets/${entityId}`;
  const q = useQuery({
    queryKey: ["risk-overview", entityType, entityId],
    queryFn: () => api.get(path).then((r) => r.data),
    enabled: !!entityId,
  });

  if (q.isPending) return <p className="text-xs text-muted-foreground">Loading…</p>;
  if (q.isError) return <p className="text-xs text-destructive">Failed to load entity.</p>;
  const data = q.data as FindingWithRisk;
  const risk = data.risk;

  return (
    <section className="space-y-4">
      <div className="rounded-lg border border-border bg-card p-4">
        <h2 className="text-sm font-medium">Composite Risk Score</h2>
        <p className="mt-1 text-3xl font-semibold">{risk?.composite ?? data.risk_score ?? 0}</p>
        <p className="text-xs text-muted-foreground">/ 100</p>
      </div>
      {risk?.factors && (
        <div className="rounded-lg border border-border bg-card p-4">
          <h2 className="mb-2 text-sm font-medium">Risk subfactor breakdown</h2>
          <ul className="space-y-2">
            {risk.factors.map((s) => (
              <li key={s.name} data-testid={`risk-subfactor-${s.name}`}>
                <div className="flex items-center justify-between text-xs">
                  <span className="font-medium">{s.name}</span>
                  <span className="font-mono text-muted-foreground">{s.score} ({Math.round(s.weight * 100)}%)</span>
                </div>
                <div className="mt-1 h-1.5 w-full rounded-full bg-muted">
                  <div className="h-1.5 rounded-full bg-foreground" style={{ width: `${s.raw}%` }} />
                </div>
                <p className="mt-1 text-[11px] text-muted-foreground">{s.description}</p>
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}
