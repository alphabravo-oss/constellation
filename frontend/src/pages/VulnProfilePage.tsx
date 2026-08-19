import { CrudPage } from "@/components/CrudPage";
import { vulnProfiles, type VulnProfile } from "@/api/client";

export function VulnProfilePage() {
  return (
    <CrudPage<VulnProfile, Omit<VulnProfile, "id" | "created_at" | "updated_at">>
      title="Vulnerability Profiles"
      description="Per-domain and per-image suppression / escalation rules applied on scan completion. Reserved entry _recent matches CVEs published within N days."
      queryKey="vuln-profiles"
      api={{
        list: (p) => vulnProfiles.list(p).then((d) => ({ items: d.profiles })),
        create: (body, p) => vulnProfiles.create(body, p),
        update: vulnProfiles.update,
        delete: vulnProfiles.delete,
      }}
      emptyBody={() => ({
        name: "",
        description: "",
        active: false,
        entries: [
          { name: "_recent", reserved: "_recent", recent_days: 14, severity_floor: "critical", action: "escalate" },
        ],
        domain_scope: {},
      })}
      toBody={(p) => ({
        name: p.name,
        description: p.description,
        active: p.active,
        entries: p.entries,
        domain_scope: p.domain_scope,
      })}
      columns={[
        { header: "Name", render: (p) => <span className="font-medium">{p.name}</span> },
        { header: "Active", render: (p) => (p.active ? "yes" : "no") },
        { header: "Entries", render: (p) => p.entries.length },
        { header: "Scope", render: (p) => `${p.domain_scope.clusters?.length ?? 0}c / ${p.domain_scope.namespaces?.length ?? 0}ns` },
      ]}
    />
  );
}
