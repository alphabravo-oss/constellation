import { ChevronLeft, ChevronRight } from "lucide-react";

// Pager — shared server-side pagination control. Two modes:
//   total mode:   pass `total` — shows "Showing A–B of N · Page p of M".
//   cursor mode:  pass `hasMore` instead (for tables too large to COUNT cheaply, e.g. the
//                 audit log) — shows "Showing A–B · Page p", Next enabled while more exist.
export function Pager({ page, pageSize, total, hasMore, rowsOnPage, onPage }: { page: number; pageSize: number; total?: number; hasMore?: boolean; rowsOnPage: number; onPage: (p: number) => void }) {
  const cursor = total === undefined;
  if (!cursor && total! <= pageSize && page === 0) return null;
  if (cursor && page === 0 && !hasMore) return null;
  const from = rowsOnPage === 0 ? 0 : page * pageSize + 1;
  const to = rowsOnPage === 0 ? 0 : page * pageSize + rowsOnPage;
  const pages = cursor ? 0 : Math.max(1, Math.ceil(total! / pageSize));
  const nextDisabled = cursor ? !hasMore : page + 1 >= pages;
  return (
    <div className="mt-3 flex items-center justify-between text-sm text-muted-foreground">
      <span>
        Showing <span className="tabular-nums text-foreground">{from.toLocaleString()}–{to.toLocaleString()}</span>
        {!cursor && <> of <span className="tabular-nums text-foreground">{total!.toLocaleString()}</span></>}
      </span>
      <div className="flex items-center gap-2">
        <button type="button" disabled={page <= 0} onClick={() => onPage(page - 1)} className="inline-flex items-center gap-1 h-8 rounded-md border border-border px-2.5 text-sm transition-colors hover:bg-accent hover:text-foreground disabled:pointer-events-none disabled:opacity-50"><ChevronLeft className="h-3.5 w-3.5" />Prev</button>
        <span className="tabular-nums">Page {page + 1}{!cursor && <> of {pages.toLocaleString()}</>}</span>
        <button type="button" disabled={nextDisabled} onClick={() => onPage(page + 1)} className="inline-flex items-center gap-1 h-8 rounded-md border border-border px-2.5 text-sm transition-colors hover:bg-accent hover:text-foreground disabled:pointer-events-none disabled:opacity-50">Next<ChevronRight className="h-3.5 w-3.5" /></button>
      </div>
    </div>
  );
}
