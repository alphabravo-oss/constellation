import type { HTMLAttributes, ReactNode } from "react";
import { cn } from "@/lib/cn";

export function TablePrimaryText({ className, ...props }: HTMLAttributes<HTMLSpanElement>) {
  return <span className={cn("app-table-primary", className)} {...props} />;
}

export function TableSecondaryText({ className, ...props }: HTMLAttributes<HTMLSpanElement>) {
  return <span className={cn("app-table-secondary", className)} {...props} />;
}

export function TableCodeText({ className, ...props }: HTMLAttributes<HTMLSpanElement>) {
  return <span className={cn("app-table-code", className)} {...props} />;
}

export function TableNumericText({ className, ...props }: HTMLAttributes<HTMLSpanElement>) {
  return <span className={cn("app-table-numeric", className)} {...props} />;
}

export function TableEntityCell({ primary, secondary }: { primary: ReactNode; secondary?: ReactNode }) {
  return <div className="min-w-0"><div className="app-table-primary truncate">{primary}</div>{secondary != null && <div className="app-table-secondary mt-0.5 truncate">{secondary}</div>}</div>;
}
