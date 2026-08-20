import { ChevronLeft, ChevronRight } from "lucide-react";

// Pager — shared server-side pagination control. Shows the current window of a known total
// and steps offset by whole pages. Hidden when everything fits on the first page.
export function Pager({ page, pageSize, total, rowsOnPage, onPage }: { page: number; pageSize: number; total: number; rowsOnPage: number; onPage: (p: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  if (total <= pageSize && page === 0) return null;
  const from = total === 0 ? 0 : page * pageSize + 1;
  const to = page * pageSize + rowsOnPage;
  return (
    <div className="mt-3 flex items-center justify-between text-xs text-muted-foreground">
      <span>Showing <span className="tabular-nums text-foreground">{from.toLocaleString()}–{to.toLocaleString()}</span> of <span className="tabular-nums text-foreground">{total.toLocaleString()}</span></span>
      <div className="flex items-center gap-2">
        <button type="button" disabled={page <= 0} onClick={() => onPage(page - 1)} className="inline-flex items-center gap-1 rounded-md border border-border bg-card px-2 py-1 hover:bg-accent disabled:opacity-40"><ChevronLeft className="h-3.5 w-3.5" />Prev</button>
        <span className="tabular-nums">Page {page + 1} of {pages.toLocaleString()}</span>
        <button type="button" disabled={page + 1 >= pages} onClick={() => onPage(page + 1)} className="inline-flex items-center gap-1 rounded-md border border-border bg-card px-2 py-1 hover:bg-accent disabled:opacity-40">Next<ChevronRight className="h-3.5 w-3.5" /></button>
      </div>
    </div>
  );
}
