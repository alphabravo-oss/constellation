import { useRef } from "react";
import { toast } from "sonner";
import { Download, Upload } from "lucide-react";

type ImportResult = { created: number; updated: number; results: Array<{ name: string; status: string; error?: string }> };

// Shared YAML import/export buttons for GitOps-portable config lists (groups, vuln profiles,
// …). Export downloads a .yaml file; Import reads a picked file and POSTs it, then toasts a
// created/updated/failed summary and calls onImported so the caller can refetch.
export function ImportExportButtons({
  filename,
  label,
  exportYaml,
  importYaml,
  onImported,
}: {
  filename: string;
  label: string; // e.g. "groups" / "profiles" — used in toasts
  exportYaml: () => Promise<string>;
  importYaml: (text: string) => Promise<ImportResult>;
  onImported: () => void;
}) {
  const fileRef = useRef<HTMLInputElement>(null);

  const doExport = async () => {
    try {
      const yaml = await exportYaml();
      const blob = new Blob([yaml], { type: "application/x-yaml" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      toast.error(`Failed to export ${label}`);
    }
  };
  const doImport = async (file: File) => {
    try {
      const res = await importYaml(await file.text());
      const errs = res.results.filter((r) => r.status === "error");
      if (errs.length) toast.warning(`Imported ${res.created} new, ${res.updated} updated; ${errs.length} failed`);
      else toast.success(`Imported ${res.created} new, ${res.updated} updated`);
      onImported();
    } catch {
      toast.error(`Failed to import ${label} (invalid bundle?)`);
    }
  };

  return (
    <>
      <input ref={fileRef} type="file" accept=".yaml,.yml,application/x-yaml,text/yaml" className="hidden"
        onChange={(e) => { const f = e.target.files?.[0]; if (f) doImport(f); e.target.value = ""; }} />
      <button type="button" onClick={() => fileRef.current?.click()} className="inline-flex items-center gap-1.5 rounded-md border border-border bg-card px-3 py-1.5 text-xs font-medium hover:bg-accent">
        <Upload className="h-3.5 w-3.5" /> Import
      </button>
      <button type="button" onClick={doExport} className="inline-flex items-center gap-1.5 rounded-md border border-border bg-card px-3 py-1.5 text-xs font-medium hover:bg-accent">
        <Download className="h-3.5 w-3.5" /> Export
      </button>
    </>
  );
}
