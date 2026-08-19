// App.tsx — cluster-first IA.
//
// Routing structure:
//   /login                          → LoginPage
//   /auth/login                     → LoginPage alias
//   /                               → redirect to /clusters
//   /clusters                       → ClustersLandingPage (picker, post-login landing)
//   /clusters/:id/*                 → ClusterRouter (provides cluster context via useCluster)
//       ├── dashboard               → DashboardPage (filtered by :id)
//       ├── findings                → FindingsPage (filtered by :id)
//       ├── findings/:fid           → FindingDetailPage
//       ├── nodes, images, assets, deployments, etc — see below
//   Org-level surfaces stay at root: /cve, /settings, /federation, /coverage,
//     /system-health, /access-control, /integrations, /ai.
import { lazy, Suspense } from "react";
import { Navigate, Route, Routes } from "react-router-dom";

import { AppShell } from "./components/AppShell";
import { RequireAuth } from "./components/RequireAuth";
import { LoginPage } from "./pages/LoginPage";
import { ClustersLandingPage } from "./pages/ClustersLandingPage";
import { ClusterRouter } from "./pages/ClusterRouter";

// Org-level pages — eagerly imported because they're top-level surfaces the user
// reaches from the picker and we want zero-flash navigation.
import { CVEPage } from "./pages/CVEPage";
import { CVEDetailPage } from "./pages/CVEDetailPage";
import { SettingsShell } from "./components/SettingsShell";
import { SettingsLanding } from "./pages/SettingsLanding";
import { IntegrationsPage } from "./pages/IntegrationsPage";
import { ConnectorCoveragePage } from "./pages/ConnectorCoveragePage";
import { CoveragePage } from "./pages/CoveragePage";
import { SystemHealthPage } from "./pages/SystemHealthPage";
import { AccessControlPage } from "./pages/AccessControlPage";
import { FederationPage } from "./pages/FederationPage";
import { ApiTokensPage } from "./pages/ApiTokensPage";
import { BackupPage } from "./pages/BackupPage";
import { ScannerSourcesPage } from "./pages/ScannerSourcesPage";
import { MigrationPage } from "./pages/MigrationPage";
import { AttestationTrustPage } from "./pages/AttestationTrustPage";

// Cluster-scoped pages — lazy-loaded so the picker stays cheap.
const DashboardPage         = lazy(() => import("./pages/DashboardPage").then((m) => ({ default: m.DashboardPage })));
const FindingsPage          = lazy(() => import("./pages/FindingsPage").then((m) => ({ default: m.FindingsPage })));
const FindingDetailPage     = lazy(() => import("./pages/FindingDetailPage").then((m) => ({ default: m.FindingDetailPage })));
const NodesPage             = lazy(() => import("./pages/NodesPage").then((m) => ({ default: m.NodesPage })));
const NodeDetailPage        = lazy(() => import("./pages/NodeDetailPage").then((m) => ({ default: m.NodeDetailPage })));
const ImageScansPage        = lazy(() => import("./pages/ImageScansPage").then((m) => ({ default: m.ImageScansPage })));
const ImageScanDetailPage   = lazy(() => import("./pages/ImageScanDetailPage").then((m) => ({ default: m.ImageScanDetailPage })));
const ServerlessFunctionsPage = lazy(() => import("./pages/ServerlessFunctionsPage").then((m) => ({ default: m.ServerlessFunctionsPage })));
const ServerlessFunctionDetailPage = lazy(() => import("./pages/ServerlessFunctionDetailPage").then((m) => ({ default: m.ServerlessFunctionDetailPage })));
const RepositoryScansPage   = lazy(() => import("./pages/RepositoryScansPage").then((m) => ({ default: m.RepositoryScansPage })));
const AssetsPage            = lazy(() => import("./pages/AssetsPage").then((m) => ({ default: m.AssetsPage })));
const AssetDetailPage       = lazy(() => import("./pages/AssetDetailPage").then((m) => ({ default: m.AssetDetailPage })));
const PoliciesPage          = lazy(() => import("./pages/PoliciesPage").then((m) => ({ default: m.PoliciesPage })));
const PolicyWizardPage      = lazy(() => import("./pages/PolicyWizardPage").then((m) => ({ default: m.PolicyWizardPage })));
const RiskDetailPage        = lazy(() => import("./pages/RiskDetailPage").then((m) => ({ default: m.RiskDetailPage })));
const CompliancePage        = lazy(() => import("./pages/CompliancePage").then((m) => ({ default: m.CompliancePage })));
const VulnerabilityExceptionsPage = lazy(() => import("./pages/VulnerabilityExceptionsPage").then((m) => ({ default: m.VulnerabilityExceptionsPage })));
const RuntimePage           = lazy(() => import("./pages/RuntimePage").then((m) => ({ default: m.RuntimePage })));
const ResponsePage          = lazy(() => import("./pages/ResponsePage").then((m) => ({ default: m.ResponsePage })));
const ResponseRulesPage     = lazy(() => import("./pages/ResponseRulesPage").then((m) => ({ default: m.ResponseRulesPage })));
const VulnProfilePage       = lazy(() => import("./pages/VulnProfilePage").then((m) => ({ default: m.VulnProfilePage })));
const GroupsPage            = lazy(() => import("./pages/GroupsPage").then((m) => ({ default: m.GroupsPage })));
const FileMonitorPage       = lazy(() => import("./pages/FileMonitorPage").then((m) => ({ default: m.FileMonitorPage })));
const TimelinePage          = lazy(() => import("./pages/TimelinePage").then((m) => ({ default: m.TimelinePage })));
const NetworkMapPage        = lazy(() => import("./pages/NetworkMapPage").then((m) => ({ default: m.NetworkMapPage })));
const RuntimePoliciesPage   = lazy(() => import("./pages/RuntimePoliciesPage").then((m) => ({ default: m.RuntimePoliciesPage })));
const RuntimeDLPPage        = lazy(() => import("./pages/RuntimeDLPPage").then((m) => ({ default: m.RuntimeDLPPage })));
const RuntimeSignaturesPage = lazy(() => import("./pages/RuntimeSignaturesPage").then((m) => ({ default: m.RuntimeSignaturesPage })));
const DeploymentsPage       = lazy(() => import("./pages/DeploymentsPage").then((m) => ({ default: m.DeploymentsPage })));
const DeploymentDetailPage  = lazy(() => import("./pages/DeploymentDetailPage").then((m) => ({ default: m.DeploymentDetailPage })));
const AuditPage             = lazy(() => import("./pages/AuditPage").then((m) => ({ default: m.AuditPage })));
const ClusterHealthPage     = lazy(() => import("./pages/ClusterHealthPage").then((m) => ({ default: m.ClusterHealthPage })));
const BaselinesPage         = lazy(() => import("./pages/BaselinesPage").then((m) => ({ default: m.BaselinesPage })));
const RegistriesPage        = lazy(() => import("./pages/RegistriesPage").then((m) => ({ default: m.RegistriesPage })));
const ComponentsPage        = lazy(() => import("./pages/ComponentsPage").then((m) => ({ default: m.ComponentsPage })));

function SuspenseRoute({ children }: { children: React.ReactNode }) {
  return (
    <Suspense
      fallback={
        <div className="flex items-center justify-center py-16 text-sm text-muted-foreground">
          Loading…
        </div>
      }
    >
      {children}
    </Suspense>
  );
}

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/auth/login" element={<LoginPage />} />
      <Route
        path="/"
        element={
          <RequireAuth>
            <AppShell />
          </RequireAuth>
        }
      >
        {/* Post-login landing: cluster picker, not the org dashboard. */}
        <Route index element={<Navigate to="/clusters" replace />} />

        {/* Cluster picker. */}
        <Route path="clusters" element={<ClustersLandingPage />} />

        {/* Cluster-scoped routes. */}
        <Route path="clusters/:id" element={<ClusterRouter />}>
          <Route index element={<Navigate to="dashboard" replace />} />
          <Route path="dashboard"     element={<SuspenseRoute><DashboardPage /></SuspenseRoute>} />
          <Route path="findings"      element={<SuspenseRoute><FindingsPage /></SuspenseRoute>} />
          <Route path="findings/:fid" element={<SuspenseRoute><FindingDetailPage /></SuspenseRoute>} />
          <Route path="nodes"         element={<SuspenseRoute><NodesPage /></SuspenseRoute>} />
          <Route path="nodes/:nodeName" element={<SuspenseRoute><NodeDetailPage /></SuspenseRoute>} />
          <Route path="images"        element={<SuspenseRoute><ImageScansPage /></SuspenseRoute>} />
          <Route path="images/:resultId" element={<SuspenseRoute><ImageScanDetailPage /></SuspenseRoute>} />
          <Route path="serverless"    element={<SuspenseRoute><ServerlessFunctionsPage /></SuspenseRoute>} />
          <Route path="serverless/:functionId" element={<SuspenseRoute><ServerlessFunctionDetailPage /></SuspenseRoute>} />
          <Route path="repositories"  element={<SuspenseRoute><RepositoryScansPage /></SuspenseRoute>} />
          <Route path="assets"        element={<SuspenseRoute><AssetsPage /></SuspenseRoute>} />
          <Route path="assets/:aid"   element={<SuspenseRoute><AssetDetailPage /></SuspenseRoute>} />
          <Route path="deployments"   element={<SuspenseRoute><DeploymentsPage /></SuspenseRoute>} />
          <Route path="deployments/:did" element={<SuspenseRoute><DeploymentDetailPage /></SuspenseRoute>} />
          <Route path="compliance"    element={<SuspenseRoute><CompliancePage /></SuspenseRoute>} />
          <Route path="registries"    element={<SuspenseRoute><RegistriesPage /></SuspenseRoute>} />
          <Route path="exceptions"    element={<SuspenseRoute><VulnerabilityExceptionsPage /></SuspenseRoute>} />
          <Route path="runtime"       element={<SuspenseRoute><RuntimePage /></SuspenseRoute>} />
          <Route path="runtime/baselines" element={<SuspenseRoute><BaselinesPage /></SuspenseRoute>} />
          <Route path="response"      element={<SuspenseRoute><ResponsePage /></SuspenseRoute>} />
          <Route path="response-rules" element={<SuspenseRoute><ResponseRulesPage /></SuspenseRoute>} />
          <Route path="vuln-profiles" element={<SuspenseRoute><VulnProfilePage /></SuspenseRoute>} />
          <Route path="groups"        element={<SuspenseRoute><GroupsPage /></SuspenseRoute>} />
          <Route path="file-monitor"  element={<SuspenseRoute><FileMonitorPage /></SuspenseRoute>} />
          <Route path="timeline"      element={<SuspenseRoute><TimelinePage /></SuspenseRoute>} />
          <Route path="network"       element={<SuspenseRoute><NetworkMapPage /></SuspenseRoute>} />
          {/* Wave B1: runtime_policies CRUD UI. cluster_id from :id param. */}
          <Route path="runtime-policies" element={<SuspenseRoute><RuntimePoliciesPage /></SuspenseRoute>} />
          {/* Wave C4: DLP regex rules. */}
          <Route path="runtime-dlp" element={<SuspenseRoute><RuntimeDLPPage /></SuspenseRoute>} />
          {/* Wave D4: custom DPI signatures. */}
          <Route path="runtime-signatures" element={<SuspenseRoute><RuntimeSignaturesPage /></SuspenseRoute>} />
          <Route path="policies"      element={<SuspenseRoute><PoliciesPage /></SuspenseRoute>} />
          <Route path="policies/new"  element={<SuspenseRoute><PolicyWizardPage /></SuspenseRoute>} />
          <Route path="audit"         element={<SuspenseRoute><AuditPage /></SuspenseRoute>} />
          <Route path="components"    element={<SuspenseRoute><ComponentsPage /></SuspenseRoute>} />
          <Route path="risk/:entityType/:entityId" element={<SuspenseRoute><RiskDetailPage /></SuspenseRoute>} />
          <Route path="health"        element={<SuspenseRoute><ClusterHealthPage /></SuspenseRoute>} />
        </Route>

        {/* Org-level surfaces. */}
        <Route path="cve"             element={<CVEPage />} />
        <Route path="cve/:id"         element={<CVEDetailPage />} />
        <Route path="federation"      element={<FederationPage />} />
        <Route path="posture"         element={<CoveragePage />} />

        {/* Legacy redirects — old flat routes now live under the Settings shell
            or were renamed. Keep them so bookmarks/links don't break. */}
        <Route path="coverage"        element={<Navigate to="/posture" replace />} />
        <Route path="system-health"   element={<Navigate to="/settings/health" replace />} />
        <Route path="access-control"  element={<Navigate to="/settings/access" replace />} />

        {/* Settings — one grouped shell, one home per feature (SettingsShell sub-nav). */}
        <Route path="settings" element={<SettingsShell />}>
          <Route index element={<SettingsLanding />} />
          <Route path="access"            element={<AccessControlPage />} />
          <Route path="api-tokens"        element={<ApiTokensPage />} />
          <Route path="attestation-trust" element={<AttestationTrustPage />} />
          <Route path="health"            element={<SystemHealthPage />} />
          <Route path="scanner"           element={<ScannerSourcesPage />} />
          <Route path="backup"            element={<BackupPage />} />
          <Route path="integrations"      element={<IntegrationsPage />} />
          <Route path="connectors"        element={<ConnectorCoveragePage />} />
          <Route path="migration"         element={<MigrationPage />} />
          <Route path="vulndb"            element={<Navigate to="/settings/scanner" replace />} />
        </Route>
      </Route>
    </Routes>
  );
}
