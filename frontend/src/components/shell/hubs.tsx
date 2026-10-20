// Tabbed hubs (C1): Policies (Admission · Runtime · Network · Response),
// Agents (Components · Sensor health), Signatures (DPI signatures · DLP rules).
// Each tab is a real route; the inner page renders as a section of the hub.
import type { ReactNode } from "react";
import { useLocation } from "@tanstack/react-router";
import { EmbeddedPageProvider, PageHeader } from "@/components/ui/page";
import { cn } from "@/lib/cn";
import { LinkTabs, useProduct } from "@/ui";

interface HubTab { key: string; label: string; paths: string[] }

function clusterBase(pathname: string): string {
  const match = pathname.match(/^\/clusters\/[^/]+/);
  return match ? match[0] : "/clusters";
}

function Hub({
  title,
  description,
  tabs,
  active,
  sub,
  children,
  testId,
}: {
  title: string;
  description?: string;
  tabs: HubTab[];
  active: string;
  sub?: Array<{ label: string; path: string }>;
  children: ReactNode;
  testId: string;
}) {
  const { pathname } = useLocation();
  const { Link } = useProduct();
  const base = clusterBase(pathname);
  const rest = pathname.slice(base.length + 1);
  return (
    <div className="space-y-(--gap-section)" data-testid={testId}>
      <PageHeader
        title={title}
        description={description}
      />
      <div className="border-b border-border">
        <LinkTabs
          label={`${title} sections`}
          tabs={tabs.map((tab) => ({ to: `${base}/${tab.paths[0]}`, label: tab.label, active: tab.key === active }))}
        />
      </div>
      {sub && sub.length > 1 ? (
        <div className="inline-flex h-9 items-center rounded-md border border-border p-0.5" role="navigation" aria-label={`${title} views`}>
          {sub.map((item) => {
            const current = rest === item.path || rest.startsWith(`${item.path}/`);
            return (
              <Link
                key={item.path}
                to={`${base}/${item.path}`}
                current={current}
                className={cn(
                  "inline-flex h-7 items-center rounded-sm px-3 text-sm transition-colors focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring",
                  current ? "bg-accent font-medium text-foreground" : "text-muted-foreground hover:text-foreground",
                )}
              >
                {item.label}
              </Link>
            );
          })}
        </div>
      ) : null}
      <EmbeddedPageProvider value={true}>{children}</EmbeddedPageProvider>
    </div>
  );
}

const POLICY_TABS: HubTab[] = [
  { key: "admission", label: "Admission", paths: ["admission", "policies"] },
  { key: "runtime", label: "Runtime", paths: ["runtime-policies"] },
  { key: "network", label: "Network", paths: ["groups"] },
  { key: "response", label: "Response", paths: ["response-rules", "response"] },
];

const POLICY_SUB: Record<string, Array<{ label: string; path: string }>> = {
  admission: [{ label: "Rules", path: "admission" }, { label: "Policy catalog", path: "policies" }],
  response: [{ label: "Rules", path: "response-rules" }, { label: "Built-in catalog", path: "response" }],
};

export function PoliciesHub({ tab, children }: { tab: "admission" | "runtime" | "network" | "response"; children: ReactNode }) {
  return (
    <Hub title="Policies" tabs={POLICY_TABS} active={tab} sub={POLICY_SUB[tab]} testId="policies-hub">
      {children}
    </Hub>
  );
}

export function AgentsHub({ tab, children }: { tab: "components" | "health"; children: ReactNode }) {
  return (
    <Hub
      title="Agents"
      tabs={[
        { key: "components", label: "Components", paths: ["components"] },
        { key: "health", label: "Sensor health", paths: ["health"] },
      ]}
      active={tab}
      testId="agents-hub"
    >
      {children}
    </Hub>
  );
}

export function SignaturesHub({ tab, children }: { tab: "dpi" | "dlp"; children: ReactNode }) {
  return (
    <Hub
      title="Signatures"
      tabs={[
        { key: "dpi", label: "DPI signatures", paths: ["runtime-signatures"] },
        { key: "dlp", label: "DLP rules", paths: ["runtime-dlp"] },
      ]}
      active={tab}
      testId="signatures-hub"
    >
      {children}
    </Hub>
  );
}
