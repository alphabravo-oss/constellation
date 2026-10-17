import { type ReactNode } from "react";
import { DataTable, type Column } from "@/components/ui/data-table";
import { type ColumnKind } from "@/components/ui/data-table-layout";
import { type CsvCell } from "@/lib/csv";
export interface EvidenceField<T> { key: keyof T; label: string; kind?: ColumnKind; cell?: (row: T) => ReactNode; value?: (row: T) => CsvCell; }
function display(value: unknown): string { return value === null || value === undefined || value === "" ? "Not reported" : typeof value === "object" ? JSON.stringify(value) : String(value); }
export function EvidenceInventory<T extends object>({ rows, fields, testId, title, source, sourceLimit, rowTestId, onRowClick }: { rows: T[]; fields: EvidenceField<T>[]; testId: string; title?: string; source?: string; sourceLimit?: number; rowTestId?: (row: T) => string; onRowClick?: (row: T) => void }) {
  const wrapped = rows.map((row, index) => ({ ...row, _evidenceKey: index }));
  const columns: Column<T & { _evidenceKey: number }>[] = fields.map(field => ({ id: String(field.key), header: field.label, kind: field.kind ?? "text", wrap: !["count", "status", "actions"].includes(field.kind ?? "text"), numeric: field.kind === "count", cell: row => field.cell ? field.cell(row) : display(row[field.key]), exportValue: row => field.value ? field.value(row) : display(row[field.key]) }));
  return <section className="space-y-3" data-testid={testId}>
    {title && <h2 className="text-sm font-semibold">{title}</h2>}
    {source && <p className="text-xs text-muted-foreground">{source}</p>}
    <DataTable rows={wrapped} columns={columns} rowKey={row => row._evidenceKey} preferencesKey={testId} exportFileName={`${testId}-returned-evidence`} exportLabel="Export returned evidence" sourceLimit={sourceLimit} sourceCount={rows.length} rowTestId={rowTestId} onRowClick={onRowClick} emptyState={<p className="p-4 text-sm text-muted-foreground">No evidence returned by this source. Coverage or protection is not established.</p>} />
  </section>;
}
