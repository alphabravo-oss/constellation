import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Wand2 } from "lucide-react";
import { toast } from "sonner";

import { enterprise, type MigrationPreview } from "@/api/client";
import { PageHeader } from "@/components/ui/page";
import { DataTable, type Column } from "@/components/ui/data-table";
import { StatCard } from "@/components/ui/stat-card";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Field, Select, Textarea } from "@/components/ui/form";

type MigrationPolicy = MigrationPreview["policies"][number];
type MigrationFileProfile = MigrationPreview["file_profiles"][number];

const policyColumns: Column<MigrationPolicy>[] = [
  {
    id: "policy",
    header: "Policy",
    cell: (p) => (
      <div data-testid="migration-preview-policy">
        <div className="font-medium">{p.name}</div>
        <div className="text-muted-foreground">{p.engine} · {p.category}</div>
      </div>
    ),
  },
  { id: "action", header: "Action", cell: (p) => p.diff_action },
  { id: "mode", header: "Mode", cell: (p) => p.mode },
];

const fileProfileColumns: Column<MigrationFileProfile>[] = [
  {
    id: "profile",
    header: "File profile",
    cell: (p) => (
      <div data-testid="migration-preview-file-profile">
        <div className="font-medium">{p.group}</div>
        {p.description ? <div className="text-muted-foreground">{p.description}</div> : null}
      </div>
    ),
  },
  { id: "mode", header: "Mode", cell: (p) => p.mode },
  { id: "rules", header: "Rules", cell: (p) => p.rules.length },
  { id: "action", header: "Action", cell: (p) => p.diff_action },
];

/**
 * Migration Imports — its own home (plan §4). Previously an inline wizard buried in
 * the Settings hub; now a focused page. Paste an export from another tool, preview
 * the generated policies/file-profiles + rollback bundle before importing.
 */
export function MigrationPage() {
  const sourcesQ = useQuery({ queryKey: ["migration-sources"], queryFn: () => enterprise.migration() });
  const sources = sourcesQ.data?.sources ?? [];

  const [source, setSource] = useState("neuvector");
  const [exportText, setExportText] = useState("");
  const [selectedPolicy, setSelectedPolicy] = useState<string | null>(null);

  const preview = useMutation({
    mutationFn: () => enterprise.migrationPreview({ source, export: exportText }),
    onSuccess: (data) => {
      setSelectedPolicy(data.policies[0]?.name ?? null);
      toast.success("Migration preview generated");
    },
    onError: () => toast.error("Migration preview failed"),
  });
  const data = preview.data;
  const selected = data?.policies.find((p) => p.name === selectedPolicy) ?? data?.policies[0];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Migration Imports"
        description="Import policies and file profiles from another security tool. Preview the diff and rollback bundle before applying."
      />

      <div data-testid="migration-preview-wizard">
        <Card
          title="Paste an export"
          description="Choose the source tool and paste its exported configuration to preview the generated policies, file profiles, and rollback bundle."
        >
          <div className="space-y-5">
            <div className="flex flex-wrap items-end gap-3">
              <Field label="Source" className="w-56">
                <Select
                  value={source}
                  onChange={(e) => setSource(e.target.value)}
                  data-testid="migration-source-select"
                >
                  {sources.length === 0 && <option value="neuvector">NeuVector</option>}
                  {sources.map((s) => (
                    <option key={s.id} value={s.id}>{s.name}</option>
                  ))}
                </Select>
              </Field>
              <Button
                variant="primary"
                onClick={() => preview.mutate()}
                disabled={preview.isPending || exportText.trim().length < 8}
                data-testid="migration-preview-submit"
              >
                <Wand2 className="h-4 w-4" aria-hidden />
                Preview import
              </Button>
            </div>

            <Textarea
              value={exportText}
              onChange={(e) => setExportText(e.target.value)}
              rows={8}
              spellCheck={false}
              placeholder="Paste the exported configuration from your source tool…"
              className="font-mono text-xs"
              data-testid="migration-export-input"
            />
          </div>
        </Card>
      </div>

      {data ? (
        <div className="space-y-4" data-testid="migration-preview-result">
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <StatCard label="Policies" value={data.summary.total} />
            <StatCard label="Create" value={data.summary.create} tone="low" />
            <StatCard label="Update" value={data.summary.update} tone="medium" />
            <StatCard label="Enforce" value={data.summary.enforce} tone="high" />
          </div>
          <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
            <DataTable
              rows={data.policies}
              columns={policyColumns}
              rowKey={(p) => p.name}
              onRowClick={(p) => setSelectedPolicy(p.name)}
              showDensityToggle={false}
            />
            <Card title="Generated policy YAML">
              <pre className="max-h-64 overflow-auto rounded bg-muted p-2 text-xs" data-testid="migration-preview-yaml">
                {selected?.spec_yaml ?? "No policy selected."}
              </pre>
            </Card>
          </div>
          {data.file_profiles.length > 0 ? (
            <div data-testid="migration-preview-file-profiles">
              <DataTable
                rows={data.file_profiles}
                columns={fileProfileColumns}
                rowKey={(p) => p.group}
                showDensityToggle={false}
              />
            </div>
          ) : null}
          <Card title="Rollback bundle preview" description="Apply this bundle to revert the import if needed.">
            <pre className="max-h-40 overflow-auto rounded bg-muted p-2 text-xs" data-testid="migration-rollback-bundle">
              {data.rollback_bundle}
            </pre>
          </Card>
        </div>
      ) : null}
    </div>
  );
}
