import type { EnforcementAction } from "@/api/client";

export function NetworkEnforcementStatus({ action }: { action: Pick<EnforcementAction, "state" | "last_status" | "last_error"> }) {
  if (action.last_status === "error") {
    const protectedTarget = action.state === "active" && action.last_error?.startsWith("network policy refused: protected namespace ");
    const summary = action.state === "lifting" ? "Removal failed; policy may still be enforced"
      : protectedTarget ? "Protected workload; policy not applied" : "Policy application failed";
    return <span role="status" className="text-[color:var(--color-severity-critical)]">{summary}{action.last_error ? `: ${action.last_error}` : ". No error details were reported."}</span>;
  }
  if (action.state === "lifting") return <span>Removal pending confirmation</span>;
  if (action.state === "removed") return <span>Removal confirmed</span>;
  if (action.state !== "active") return <span>Enforcement state unknown</span>;
  return <span>{action.last_status === "ok" ? "Policy applied (applier reported)" : "Policy application pending"}</span>;
}
