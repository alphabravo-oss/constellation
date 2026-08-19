import * as Tooltip from "@radix-ui/react-tooltip";
import { cn } from "@/lib/cn";
import { riskTier } from "@/lib/severity";

/**
 * RiskScore — composite 0–100 risk score with optional subfactor tooltip on hover.
 *
 * Visual: bold number + tiny risk-tier color dot. When `subfactors` provided,
 * hovering reveals 4 horizontal bars (Exploitability · Impact · Exposure · Asset Crit.)
 * to communicate "why is this risky" in a glance — modeled on StackRox's Risk
 * Drilldown subfactor breakdown.
 */
export interface Subfactor { label: string; value: number; max?: number }

export function RiskScore({
  score,
  size = "md",
  subfactors,
  className,
}: {
  score: number;
  size?: "sm" | "md" | "lg";
  subfactors?: Subfactor[];
  className?: string;
}) {
  const tier = riskTier(score);
  const num = (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 text-mono font-semibold",
        size === "sm" && "text-xs",
        size === "md" && "text-sm",
        size === "lg" && "text-2xl",
        className,
      )}
    >
      <span
        aria-hidden
        className={cn(
          "inline-block rounded-full",
          size === "lg" ? "h-2.5 w-2.5" : "h-1.5 w-1.5",
        )}
        style={{ background: tier.color }}
      />
      {Math.round(score)}
    </span>
  );

  if (!subfactors?.length) return num;

  return (
    <Tooltip.Provider delayDuration={150}>
      <Tooltip.Root>
        <Tooltip.Trigger asChild>
          <button type="button" className="cursor-help">{num}</button>
        </Tooltip.Trigger>
        <Tooltip.Portal>
          <Tooltip.Content
            side="top"
            sideOffset={6}
            className="z-50 rounded-md border border-border bg-popover p-3 text-xs shadow-[var(--elev-3)] min-w-[220px]"
          >
            <div className="mb-2 flex items-center justify-between gap-3">
              <span className="font-medium">Risk Score</span>
              <span className="text-mono text-sm" style={{ color: tier.color }}>{Math.round(score)} · {tier.label}</span>
            </div>
            <ul className="space-y-1.5">
              {subfactors.map((sf) => {
                const max = sf.max ?? 100;
                const pct = Math.max(0, Math.min(100, (sf.value / max) * 100));
                return (
                  <li key={sf.label} className="space-y-0.5">
                    <div className="flex items-center justify-between text-[10px] text-muted-foreground">
                      <span>{sf.label}</span>
                      <span className="text-mono">{sf.value}</span>
                    </div>
                    <div className="h-1 w-full rounded-full bg-muted overflow-hidden">
                      <div
                        className="h-full rounded-full"
                        style={{ width: `${pct}%`, background: tier.color }}
                      />
                    </div>
                  </li>
                );
              })}
            </ul>
            <Tooltip.Arrow className="fill-popover" />
          </Tooltip.Content>
        </Tooltip.Portal>
      </Tooltip.Root>
    </Tooltip.Provider>
  );
}

/**
 * Big composite-risk gauge rendered as a thick arc.
 * Pure SVG, no deps. Used in EntityHeader and Dashboard hero.
 */
export function RiskGauge({ score, label, sub, size = 140 }: { score: number; label?: string; sub?: string; size?: number }) {
  const tier = riskTier(score);
  const stroke = Math.max(6, Math.round(size * 0.058));
  const r = (size - stroke * 2) / 2;
  const c = 2 * Math.PI * r;
  const filled = (Math.max(0, Math.min(100, score)) / 100) * c;
  const cx = size / 2;
  return (
    <div className="relative inline-flex shrink-0" style={{ width: size, height: size }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="-rotate-90 block">
        <circle cx={cx} cy={cx} r={r} fill="none" stroke="var(--color-border)" strokeWidth={stroke} />
        <circle
          cx={cx} cy={cx} r={r}
          fill="none"
          stroke={tier.color}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={`${filled} ${c}`}
          style={{ transition: "stroke-dasharray 320ms var(--ease-out)" }}
        />
      </svg>
      <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center text-center leading-tight">
        <span className="text-mono text-3xl font-semibold tabular-nums" style={{ color: tier.color }}>{Math.round(score)}</span>
        <span className="mt-0.5 text-[9px] uppercase tracking-[0.14em] text-muted-foreground">{label ?? "risk"}</span>
        {sub && (
          <span
            className="mt-0.5 max-w-[88%] truncate text-[9px] text-muted-foreground"
            title={sub}
          >
            {sub}
          </span>
        )}
      </div>
    </div>
  );
}
