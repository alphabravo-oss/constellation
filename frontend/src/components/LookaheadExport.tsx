import { useMutation } from "@tanstack/react-query";
import { downloadLookaheadCSV } from "@/api/client";
import { useExportGuard } from "@/hooks/useExportGuard";
import { Button } from "@/components/ui/button";

/** Matching exports for large inventories whose API deliberately uses lookahead. */
interface LookaheadExportProps {
  context: string; disabled: boolean; isCurrent: () => boolean; path: string;
  params: Record<string, string | number | undefined>; filename: string;
}
export function LookaheadExport(props: LookaheadExportProps) {
  return <ScopedLookaheadExport key={props.context} {...props} />;
}
function ScopedLookaheadExport({ context, disabled, isCurrent, path, params, filename }: LookaheadExportProps) {
  const capture = useExportGuard(context, disabled, isCurrent);
  const request = useMutation({ mutationFn: async () => {
    const current = capture();
    if (!current()) throw new Error("Export is unavailable");
    return { context, result: await downloadLookaheadCSV(path, params, filename, current) };
  } });
  const result = request.data?.context === context && !disabled ? request.data.result : undefined;
  return <div className="flex flex-wrap items-center gap-2 text-xs">
    <Button variant="outline" disabled={disabled || request.isPending} onClick={() => request.mutate()}>{request.isPending ? "Exporting…" : "Export matching CSV"}</Button>
    <span className="text-muted-foreground">Up to 100,000 matching records, across pages.</span>
    {request.isError && <span role="alert">Export failed or its reviewed scope changed. Refresh before retrying.</span>}
    {result && <span role="status">{result.truncated ? `Exported the first ${result.exported.toLocaleString()} matching records; more exist. Narrow the filters for a complete export.` : `Exported all ${result.exported.toLocaleString()} matching records across pages.`}</span>}
  </div>;
}
