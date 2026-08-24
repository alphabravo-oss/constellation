// WhatIfScore — B8 score what-if / prediction control.
//
// "Fix these N → score X→Y". The operator toggles severity bands to
// hypothetically resolve; the backend recomputes the projected risk score
// (POST /api/v1/security/score/predict) without mutating anything. Models
// NeuVector's predict-score control.
import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { scorePredict } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";

const BANDS = ["critical", "high", "medium", "low"] as const;

export function WhatIfScore() {
  const { clusterId } = useCluster();
  const [resolve, setResolve] = useState<Set<string>>(new Set());

  const resolveSeverities = useMemo(() => [...resolve], [resolve]);

  const q = useQuery({
    queryKey: ["score-predict", clusterId, resolveSeverities.join(",")],
    queryFn: () => scorePredict.predict({ resolve_severities: resolveSeverities }, { cluster_id: clusterId }),
    // Keep the current-score baseline visible even with nothing selected.
    placeholderData: (prev) => prev,
  });

  const toggle = (band: string) =>
    setResolve((prev) => {
      const next = new Set(prev);
      if (next.has(band)) {
        next.delete(band);
      } else {
        next.add(band);
      }
      return next;
    });

  const data = q.data;
  const cur = data?.current.score ?? 0;
  const proj = data?.projected.score ?? cur;
  const resolved = data?.resolved ?? 0;

  return (
    <section
      className="rounded-md border border-border bg-card p-4"
      data-testid="what-if-score"
    >
      <div className="mb-3 flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold">Score what-if</h3>
          <p className="text-[11px] text-muted-foreground">
            Select severities to resolve and preview the projected risk score.
          </p>
        </div>
        <span className="rounded-full border border-border px-2 py-0.5 text-[10px] uppercase tracking-wide text-muted-foreground">
          predict
        </span>
      </div>

      <div className="mb-3 flex flex-wrap gap-1.5">
        {BANDS.map((b) => {
          const n = data?.current.counts[b] ?? 0;
          return (
            <button
              key={b}
              type="button"
              onClick={() => toggle(b)}
              disabled={n === 0}
              className={`rounded-full border px-2.5 py-0.5 text-[11px] capitalize transition-colors disabled:opacity-40 ${
                resolve.has(b)
                  ? "border-primary bg-primary/10 text-primary"
                  : "border-border text-muted-foreground hover:bg-muted/40"
              }`}
              aria-pressed={resolve.has(b)}
            >
              {b} ({n})
            </button>
          );
        })}
      </div>

      <div className="flex items-center gap-3">
        <ScoreChip label="Now" score={cur} grade={data?.current.grade} />
        <span className="text-muted-foreground" aria-hidden>→</span>
        <ScoreChip label="Projected" score={proj} grade={data?.projected.grade} highlight={proj !== cur} />
        <div className="ml-auto text-right text-[11px] text-muted-foreground">
          {resolved > 0 ? (
            <>
              fix <span className="font-mono text-foreground">{resolved}</span> findings ·{" "}
              <span className="font-mono text-status-success">−{Math.max(0, cur - proj)}</span> pts
            </>
          ) : (
            <>select a band to preview</>
          )}
        </div>
      </div>
    </section>
  );
}

function ScoreChip({
  label,
  score,
  grade,
  highlight,
}: {
  label: string;
  score: number;
  grade?: "good" | "fair" | "poor";
  highlight?: boolean;
}) {
  const tone =
    grade === "poor" ? "text-status-error" : grade === "fair" ? "text-status-warning" : "text-status-success";
  return (
    <div className={`rounded-md border px-3 py-1.5 ${highlight ? "border-primary" : "border-border"}`}>
      <div className="text-[10px] uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className="flex items-baseline gap-1.5">
        <span className={`text-lg font-semibold tabular-nums ${tone}`}>{score}</span>
        {grade && <span className="text-[10px] capitalize text-muted-foreground">{grade}</span>}
      </div>
    </div>
  );
}
