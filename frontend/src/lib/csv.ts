export type CsvCell = string | number | boolean | null | undefined;

// downloadCsv builds a CSV from a header + row matrix and triggers a client-side
// download. Used to give every list view the ad-hoc export NeuVector ships table-wide.
export function downloadCsv(filename: string, headers: string[], rows: Array<Array<CsvCell>>) {
  const esc = (v: CsvCell) => {
    const s = String(v ?? "");
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const lines = [headers.map(esc).join(","), ...rows.map((r) => r.map(esc).join(","))];
  const blob = new Blob([lines.join("\n")], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename.endsWith(".csv") ? filename : `${filename}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}
