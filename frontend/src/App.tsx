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
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";

import { AppShell } from "./components/AppShell";
import { RequireAuth } from "./components/RequireAuth";
import { LoginPage } from "./pages/LoginPage";
import { ClustersLandingPage } from "./pages/ClustersLandingPage";
import { ClusterRouter } from "./pages/ClusterRouter";
import { clusters } from "./api/client";
import { sortClustersByActivity } from "./lib/clusters";

// Org-level and settings pages are lazy-loaded so heavyweight surfaces such as
// Monaco-backed editors are not part of the first authenticated route.
const CVEPage             = lazy(() => import("./pages/CVEPage").then((m) => ({ default: m.CVEPage })));
const CVEDetailPage       = lazy(() => import("./pages/CVEDetailPage").then((m) => ({ default: m.CVEDetailPage })));
const SettingsShell       = lazy(() => import("./components/SettingsShell").then((m) => ({ default: m.SettingsShell })));
const SettingsLanding     = lazy(() => import("./pages/SettingsLanding").then((m) => ({ default: m.SettingsLanding })));
const IntegrationsPage    = lazy(() => import("./pages/IntegrationsPage").then((m) => ({ default: m.IntegrationsPage })));
const ConnectorCoveragePage = lazy(() => import("./pages/ConnectorCoveragePage").then((m) => ({ default: m.ConnectorCoveragePage })));
const CoveragePage        = lazy(() => import("./pages/CoveragePage").then((m) => ({ default: m.CoveragePage })));
const SystemHealthPage    = lazy(() => import("./pages/SystemHealthPage").then((m) => ({ default: m.SystemHealthPage })));
const AccessControlPage   = lazy(() => import("./pages/AccessControlPage").then((m) => ({ default: m.AccessControlPage })));
const FederationPage      = lazy(() => import("./pages/FederationPage").then((m) => ({ default: m.FederationPage })));
const FederationPeerFormPage = lazy(() => import("./pages/FederationPeerFormPage").then((m) => ({ default: m.FederationPeerFormPage })));
const ApiTokensPage       = lazy(() => import("./pages/ApiTokensPage").then((m) => ({ default: m.ApiTokensPage })));
const BackupPage          = lazy(() => import("./pages/BackupPage").then((m) => ({ default: m.BackupPage })));
const ScannerSourcesPage  = lazy(() => import("./pages/ScannerSourcesPage").then((m) => ({ default: m.ScannerSourcesPage })));
const MigrationPage       = lazy(() => import("./pages/MigrationPage").then((m) => ({ default: m.MigrationPage })));
const RegisterClusterPage = lazy(() => import("./pages/RegisterClusterPage").then((m) => ({ default: m.RegisterClusterPage })));
const RoleBindingFormPage = lazy(() => import("./pages/access/RoleBindingFormPage").then((m) => ({ default: m.RoleBindingFormPage })));
const ServiceAccountFormPage = lazy(() => import("./pages/access/ServiceAccountFormPage").then((m) => ({ default: m.ServiceAccountFormPage })));
const LocalUserFormPage   = lazy(() => import("./pages/access/LocalUserFormPage").then((m) => ({ default: m.LocalUserFormPage })));
const CustomRoleFormPage  = lazy(() => import("./pages/access/CustomRoleFormPage").then((m) => ({ default: m.CustomRoleFormPage })));
const AuthProviderFormPage = lazy(() => import("./pages/access/AuthProviderFormPage").then((m) => ({ default: m.AuthProviderFormPage })));
const ApiTokenCreatePage  = lazy(() => import("./pages/ApiTokenCreatePage").then((m) => ({ default: m.ApiTokenCreatePage })));
const NvdConfigPage       = lazy(() => import("./pages/NvdConfigPage").then((m) => ({ default: m.NvdConfigPage })));
const BackupDestinationPage = lazy(() => import("./pages/backup/BackupDestinationPage").then((m) => ({ default: m.BackupDestinationPage })));
const BackupSchedulePage  = lazy(() => import("./pages/backup/BackupSchedulePage").then((m) => ({ default: m.BackupSchedulePage })));
const BackupRestorePage   = lazy(() => import("./pages/backup/BackupRestorePage").then((m) => ({ default: m.BackupRestorePage })));
const ReceiverFormPage    = lazy(() => import("./pages/integrations/ReceiverFormPage").then((m) => ({ default: m.ReceiverFormPage })));
const AttestationPolicyFormPage = lazy(() => import("./pages/AttestationPolicyFormPage").then((m) => ({ default: m.AttestationPolicyFormPage })));
const ConnectorFormPage   = lazy(() => import("./pages/connectors/ConnectorFormPage").then((m) => ({ default: m.ConnectorFormPage })));
const QueueScanPage       = lazy(() => import("./pages/connectors/QueueScanPage").then((m) => ({ default: m.QueueScanPage })));
const SecurityPolicyPage  = lazy(() => import("./pages/SecurityPolicyPage").then((m) => ({ default: m.SecurityPolicyPage })));
const NetworkProxyPage    = lazy(() => import("./pages/NetworkProxyPage").then((m) => ({ default: m.NetworkProxyPage })));
const DataRetentionPage   = lazy(() => import("./pages/DataRetentionPage").then((m) => ({ default: m.DataRetentionPage })));
const AttestationTrustPage = lazy(() => import("./pages/AttestationTrustPage").then((m) => ({ default: m.AttestationTrustPage })));
const EffectiveConfigPage = lazy(() => import("./pages/EffectiveConfigPage").then((m) => ({ default: m.EffectiveConfigPage })));

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
const PolicyCenterPage      = lazy(() => import("./pages/PolicyCenterPage").then((m) => ({ default: m.PolicyCenterPage })));
const PoliciesPage          = lazy(() => import("./pages/PoliciesPage").then((m) => ({ default: m.PoliciesPage })));
const AdmissionPage         = lazy(() => import("./pages/AdmissionPage").then((m) => ({ default: m.AdmissionPage })));
const AdmissionRuleFormPage = lazy(() => import("./pages/AdmissionRuleFormPage").then((m) => ({ default: m.AdmissionRuleFormPage })));
const PolicyWizardPage      = lazy(() => import("./pages/PolicyWizardPage").then((m) => ({ default: m.PolicyWizardPage })));
const RiskDetailPage        = lazy(() => import("./pages/RiskDetailPage").then((m) => ({ default: m.RiskDetailPage })));
const CompliancePage        = lazy(() => import("./pages/CompliancePage").then((m) => ({ default: m.CompliancePage })));
const VulnerabilityExceptionsPage = lazy(() => import("./pages/VulnerabilityExceptionsPage").then((m) => ({ default: m.VulnerabilityExceptionsPage })));
const RuntimePage           = lazy(() => import("./pages/RuntimePage").then((m) => ({ default: m.RuntimePage })));
const ResponsePage          = lazy(() => import("./pages/ResponsePage").then((m) => ({ default: m.ResponsePage })));
const ResponseRulesPage     = lazy(() => import("./pages/ResponseRulesPage").then((m) => ({ default: m.ResponseRulesPage })));
const VulnProfilePage       = lazy(() => import("./pages/VulnProfilePage").then((m) => ({ default: m.VulnProfilePage })));
const GroupsPage            = lazy(() => import("./pages/GroupsPage").then((m) => ({ default: m.GroupsPage })));
const GroupDetailPage       = lazy(() => import("./pages/GroupDetailPage").then((m) => ({ default: m.GroupDetailPage })));
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
const BaselineDetailPage    = lazy(() => import("./pages/baselines/BaselineDetailPage").then((m) => ({ default: m.BaselineDetailPage })));
const PolicyFormPage        = lazy(() => import("./pages/PolicyFormPage").then((m) => ({ default: m.PolicyFormPage })));
const ResponseRuleFormPage  = lazy(() => import("./pages/ResponseRuleFormPage").then((m) => ({ default: m.ResponseRuleFormPage })));
const RuntimePolicyFormPage = lazy(() => import("./pages/RuntimePolicyFormPage").then((m) => ({ default: m.RuntimePolicyFormPage })));
const RuntimeDLPFormPage    = lazy(() => import("./pages/RuntimeDLPFormPage").then((m) => ({ default: m.RuntimeDLPFormPage })));
const RuntimeSignatureFormPage = lazy(() => import("./pages/RuntimeSignatureFormPage").then((m) => ({ default: m.RuntimeSignatureFormPage })));
const FileMonitorFormPage   = lazy(() => import("./pages/FileMonitorFormPage").then((m) => ({ default: m.FileMonitorFormPage })));
const RegistriesPage        = lazy(() => import("./pages/RegistriesPage").then((m) => ({ default: m.RegistriesPage })));
const RegistryImagesPage    = lazy(() => import("./pages/RegistryImagesPage").then((m) => ({ default: m.RegistryImagesPage })));
const ContainersPage        = lazy(() => import("./pages/ContainersPage").then((m) => ({ default: m.ContainersPage })));
const NetworkRulesPage      = lazy(() => import("./pages/NetworkRulesPage").then((m) => ({ default: m.NetworkRulesPage })));
const NetworkRuleFormPage   = lazy(() => import("./pages/NetworkRuleFormPage").then((m) => ({ default: m.NetworkRuleFormPage })));
const ComponentsPage        = lazy(() => import("./pages/ComponentsPage").then((m) => ({ default: m.ComponentsPage })));
const NeuVectorSwitchboardPage = lazy(() => import("./pages/NeuVectorSwitchboardPage").then((m) => ({ default: m.NeuVectorSwitchboardPage })));

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

function LegacyClusterRedirect() {
  const location = useLocation();
  const list = useQuery({ queryKey: ["clusters"], queryFn: () => clusters.list(), staleTime: 30_000 });

  if (list.isPending) {
    return (
      <div className="flex items-center justify-center py-16 text-sm text-muted-foreground">
        Loading cluster…
      </div>
    );
  }

  const activeCluster = sortClustersByActivity(list.data?.clusters ?? [])[0]?.id;
  if (!activeCluster) {
    return <Navigate to="/clusters" replace />;
  }

  const legacyPath = location.pathname.replace(/^\/+/, "");
  return <Navigate to={`/clusters/${activeCluster}/${legacyPath}${location.search}${location.hash}`} replace />;
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

        {/* Legacy flat cluster routes. Auth still happens before the redirect. */}
        <Route path="dashboard" element={<LegacyClusterRedirect />} />
        <Route path="findings/*" element={<LegacyClusterRedirect />} />
        <Route path="nodes/*" element={<LegacyClusterRedirect />} />
        <Route path="hosts/*" element={<LegacyClusterRedirect />} />
        <Route path="containers" element={<LegacyClusterRedirect />} />
        <Route path="images/*" element={<LegacyClusterRedirect />} />
        <Route path="serverless/*" element={<LegacyClusterRedirect />} />
        <Route path="repositories" element={<LegacyClusterRedirect />} />
        <Route path="assets/*" element={<LegacyClusterRedirect />} />
        <Route path="deployments/*" element={<LegacyClusterRedirect />} />
        <Route path="services/*" element={<LegacyClusterRedirect />} />
        <Route path="workloads/*" element={<LegacyClusterRedirect />} />
        <Route path="compliance" element={<LegacyClusterRedirect />} />
        <Route path="registries/*" element={<LegacyClusterRedirect />} />
        <Route path="registry/*" element={<LegacyClusterRedirect />} />
        <Route path="exceptions/*" element={<LegacyClusterRedirect />} />
        <Route path="runtime/*" element={<LegacyClusterRedirect />} />
        <Route path="response" element={<LegacyClusterRedirect />} />
        <Route path="response-rules/*" element={<LegacyClusterRedirect />} />
        <Route path="vuln-profiles" element={<LegacyClusterRedirect />} />
        <Route path="vulnerability-profiles" element={<LegacyClusterRedirect />} />
        <Route path="groups/*" element={<LegacyClusterRedirect />} />
        <Route path="file-monitor/*" element={<LegacyClusterRedirect />} />
        <Route path="timeline" element={<LegacyClusterRedirect />} />
        <Route path="events" element={<LegacyClusterRedirect />} />
        <Route path="activity" element={<LegacyClusterRedirect />} />
        <Route path="incidents" element={<LegacyClusterRedirect />} />
        <Route path="security-events" element={<LegacyClusterRedirect />} />
        <Route path="network" element={<LegacyClusterRedirect />} />
        <Route path="network-activity" element={<LegacyClusterRedirect />} />
        <Route path="network-rules/*" element={<LegacyClusterRedirect />} />
        <Route path="neuvector" element={<LegacyClusterRedirect />} />
        <Route path="waf/*" element={<LegacyClusterRedirect />} />
        <Route path="dlp/*" element={<LegacyClusterRedirect />} />
        <Route path="runtime-policies/*" element={<LegacyClusterRedirect />} />
        <Route path="runtime-dlp/*" element={<LegacyClusterRedirect />} />
        <Route path="runtime-signatures/*" element={<LegacyClusterRedirect />} />
        <Route path="admission/*" element={<LegacyClusterRedirect />} />
        <Route path="admission-control/*" element={<LegacyClusterRedirect />} />
        <Route path="policy" element={<LegacyClusterRedirect />} />
        <Route path="policies/*" element={<LegacyClusterRedirect />} />
        <Route path="audit" element={<LegacyClusterRedirect />} />
        <Route path="audit-log" element={<LegacyClusterRedirect />} />
        <Route path="components" element={<LegacyClusterRedirect />} />
        <Route path="controllers" element={<LegacyClusterRedirect />} />
        <Route path="enforcers" element={<LegacyClusterRedirect />} />
        <Route path="agents" element={<LegacyClusterRedirect />} />
        <Route path="scanners" element={<LegacyClusterRedirect />} />
        <Route path="risk/*" element={<LegacyClusterRedirect />} />
        <Route path="health" element={<LegacyClusterRedirect />} />

        {/* Cluster picker. */}
        <Route path="clusters" element={<ClustersLandingPage />} />

        {/* Cluster-scoped routes. */}
        <Route path="clusters/:id" element={<ClusterRouter />}>
          <Route index element={<Navigate to="dashboard" replace />} />
          <Route path="dashboard"     element={<SuspenseRoute><DashboardPage /></SuspenseRoute>} />
          <Route path="neuvector"     element={<SuspenseRoute><NeuVectorSwitchboardPage /></SuspenseRoute>} />
          <Route path="findings"      element={<SuspenseRoute><FindingsPage /></SuspenseRoute>} />
          <Route path="findings/:fid" element={<SuspenseRoute><FindingDetailPage /></SuspenseRoute>} />
          <Route path="cve/:cveId"    element={<SuspenseRoute><CVEDetailPage /></SuspenseRoute>} />
          <Route path="nodes"         element={<SuspenseRoute><NodesPage /></SuspenseRoute>} />
          <Route path="hosts"         element={<Navigate to="../nodes" replace />} />
          <Route path="containers"    element={<SuspenseRoute><ContainersPage /></SuspenseRoute>} />
          <Route path="nodes/:nodeName" element={<SuspenseRoute><NodeDetailPage /></SuspenseRoute>} />
          <Route path="images"        element={<SuspenseRoute><ImageScansPage /></SuspenseRoute>} />
          <Route path="images/:resultId" element={<SuspenseRoute><ImageScanDetailPage /></SuspenseRoute>} />
          <Route path="serverless"    element={<SuspenseRoute><ServerlessFunctionsPage /></SuspenseRoute>} />
          <Route path="serverless/:functionId" element={<SuspenseRoute><ServerlessFunctionDetailPage /></SuspenseRoute>} />
          <Route path="repositories"  element={<SuspenseRoute><RepositoryScansPage /></SuspenseRoute>} />
          <Route path="assets"        element={<SuspenseRoute><AssetsPage /></SuspenseRoute>} />
          <Route path="assets/:aid"   element={<SuspenseRoute><AssetDetailPage /></SuspenseRoute>} />
          <Route path="deployments"   element={<SuspenseRoute><DeploymentsPage /></SuspenseRoute>} />
          <Route path="services"      element={<Navigate to="../deployments" replace />} />
          <Route path="workloads"     element={<Navigate to="../deployments" replace />} />
          <Route path="deployments/:did" element={<SuspenseRoute><DeploymentDetailPage /></SuspenseRoute>} />
          <Route path="compliance"    element={<SuspenseRoute><CompliancePage /></SuspenseRoute>} />
          <Route path="registries"    element={<SuspenseRoute><RegistriesPage /></SuspenseRoute>} />
          <Route path="registry"      element={<Navigate to="../registries" replace />} />
          <Route path="registries/:regId" element={<SuspenseRoute><RegistryImagesPage /></SuspenseRoute>} />
          <Route path="exceptions"    element={<SuspenseRoute><VulnerabilityExceptionsPage /></SuspenseRoute>} />
          <Route path="runtime"       element={<SuspenseRoute><RuntimePage /></SuspenseRoute>} />
          <Route path="runtime/baselines" element={<SuspenseRoute><BaselinesPage /></SuspenseRoute>} />
          <Route path="runtime/baselines/:baselineId" element={<SuspenseRoute><BaselineDetailPage /></SuspenseRoute>} />
          <Route path="response"      element={<SuspenseRoute><ResponsePage /></SuspenseRoute>} />
          <Route path="response-rules" element={<SuspenseRoute><ResponseRulesPage /></SuspenseRoute>} />
          <Route path="response-rules/new"     element={<SuspenseRoute><ResponseRuleFormPage /></SuspenseRoute>} />
          <Route path="response-rules/:ruleId" element={<SuspenseRoute><ResponseRuleFormPage /></SuspenseRoute>} />
          <Route path="vuln-profiles" element={<SuspenseRoute><VulnProfilePage /></SuspenseRoute>} />
          <Route path="vulnerability-profiles" element={<Navigate to="../vuln-profiles" replace />} />
          <Route path="groups"        element={<SuspenseRoute><GroupsPage /></SuspenseRoute>} />
          <Route path="groups/:groupId" element={<SuspenseRoute><GroupDetailPage /></SuspenseRoute>} />
          <Route path="file-monitor"  element={<SuspenseRoute><FileMonitorPage /></SuspenseRoute>} />
          <Route path="file-monitor/new"     element={<SuspenseRoute><FileMonitorFormPage /></SuspenseRoute>} />
          <Route path="file-monitor/:ruleId" element={<SuspenseRoute><FileMonitorFormPage /></SuspenseRoute>} />
          <Route path="timeline"      element={<SuspenseRoute><TimelinePage /></SuspenseRoute>} />
          <Route path="events"        element={<Navigate to="../timeline" replace />} />
          <Route path="activity"      element={<Navigate to="../timeline" replace />} />
          <Route path="incidents"     element={<Navigate to="../timeline?tab=incident" replace />} />
          <Route path="security-events" element={<Navigate to="../timeline" replace />} />
          <Route path="network"       element={<SuspenseRoute><NetworkMapPage /></SuspenseRoute>} />
          <Route path="network-activity" element={<Navigate to="../network" replace />} />
          <Route path="network-rules" element={<SuspenseRoute><NetworkRulesPage /></SuspenseRoute>} />
          <Route path="network-rules/new" element={<SuspenseRoute><NetworkRuleFormPage /></SuspenseRoute>} />
          <Route path="waf"           element={<SuspenseRoute><RuntimeSignaturesPage /></SuspenseRoute>} />
          <Route path="waf/*"         element={<Navigate to="../waf" replace />} />
          <Route path="dlp"           element={<SuspenseRoute><RuntimeDLPPage /></SuspenseRoute>} />
          <Route path="dlp/*"         element={<Navigate to="../dlp" replace />} />
          {/* Wave B1: runtime_policies CRUD UI. cluster_id from :id param. */}
          <Route path="runtime-policies" element={<SuspenseRoute><RuntimePoliciesPage /></SuspenseRoute>} />
          <Route path="runtime-policies/new"       element={<SuspenseRoute><RuntimePolicyFormPage /></SuspenseRoute>} />
          <Route path="runtime-policies/:policyId" element={<SuspenseRoute><RuntimePolicyFormPage /></SuspenseRoute>} />
          {/* Wave C4: DLP regex rules. */}
          <Route path="runtime-dlp" element={<SuspenseRoute><RuntimeDLPPage /></SuspenseRoute>} />
          <Route path="runtime-dlp/new"    element={<SuspenseRoute><RuntimeDLPFormPage /></SuspenseRoute>} />
          <Route path="runtime-dlp/:ruleId" element={<SuspenseRoute><RuntimeDLPFormPage /></SuspenseRoute>} />
          {/* Wave D4: custom DPI signatures. */}
          <Route path="runtime-signatures" element={<SuspenseRoute><RuntimeSignaturesPage /></SuspenseRoute>} />
          <Route path="runtime-signatures/new"   element={<SuspenseRoute><RuntimeSignatureFormPage /></SuspenseRoute>} />
          <Route path="runtime-signatures/:sigId" element={<SuspenseRoute><RuntimeSignatureFormPage /></SuspenseRoute>} />
          <Route path="admission"     element={<SuspenseRoute><AdmissionPage /></SuspenseRoute>} />
          <Route path="admission-control" element={<Navigate to="../admission" replace />} />
          <Route path="admission-control/*" element={<Navigate to="../admission" replace />} />
          <Route path="admission/new" element={<SuspenseRoute><AdmissionRuleFormPage /></SuspenseRoute>} />
          <Route path="policy"        element={<SuspenseRoute><PolicyCenterPage /></SuspenseRoute>} />
          <Route path="policies"      element={<SuspenseRoute><PoliciesPage /></SuspenseRoute>} />
          <Route path="policies/new"  element={<SuspenseRoute><PolicyWizardPage /></SuspenseRoute>} />
          <Route path="policies/:policyId" element={<SuspenseRoute><PolicyFormPage /></SuspenseRoute>} />
          <Route path="audit"         element={<SuspenseRoute><AuditPage /></SuspenseRoute>} />
          <Route path="audit-log"     element={<Navigate to="../audit" replace />} />
          <Route path="components"    element={<SuspenseRoute><ComponentsPage /></SuspenseRoute>} />
          <Route path="controllers"   element={<Navigate to="../components?role=controller" replace />} />
          <Route path="enforcers"     element={<Navigate to="../components?role=enforcer" replace />} />
          <Route path="agents"        element={<Navigate to="../components?role=enforcer" replace />} />
          <Route path="scanners"      element={<Navigate to="../components?role=scanner" replace />} />
          <Route path="vulndb"        element={<Navigate to="/settings/scanner" replace />} />
          <Route path="cve-sources"   element={<Navigate to="/settings/scanner" replace />} />
          <Route path="notifications" element={<Navigate to="/settings/integrations" replace />} />
          <Route path="system-config" element={<Navigate to="/settings/effective-config" replace />} />
          <Route path="sysconfig"     element={<Navigate to="/settings/effective-config" replace />} />
          <Route path="risk/:entityType/:entityId" element={<SuspenseRoute><RiskDetailPage /></SuspenseRoute>} />
          <Route path="health"        element={<SuspenseRoute><ClusterHealthPage /></SuspenseRoute>} />
        </Route>

        {/* Org-level surfaces. */}
        <Route path="cve"             element={<SuspenseRoute><CVEPage /></SuspenseRoute>} />
        <Route path="cve/:id"         element={<SuspenseRoute><CVEDetailPage /></SuspenseRoute>} />
        <Route path="federation"      element={<SuspenseRoute><FederationPage /></SuspenseRoute>} />
        <Route path="federation/new"  element={<SuspenseRoute><FederationPeerFormPage /></SuspenseRoute>} />
        <Route path="posture"         element={<SuspenseRoute><CoveragePage /></SuspenseRoute>} />

        {/* Legacy redirects — old flat routes now live under the Settings shell
            or were renamed. Keep them so bookmarks/links don't break. */}
        <Route path="coverage"        element={<Navigate to="/posture" replace />} />
        <Route path="system-health"   element={<Navigate to="/settings/health" replace />} />
        <Route path="access-control"  element={<Navigate to="/settings/access" replace />} />
        <Route path="system-config"   element={<Navigate to="/settings/effective-config" replace />} />
        <Route path="sysconfig"       element={<Navigate to="/settings/effective-config" replace />} />
        <Route path="vulndb"          element={<Navigate to="/settings/scanner" replace />} />
        <Route path="cve-sources"     element={<Navigate to="/settings/scanner" replace />} />
        <Route path="notifications"   element={<Navigate to="/settings/integrations" replace />} />
        <Route path="integrations"    element={<Navigate to="/settings/integrations" replace />} />

        {/* Settings — one grouped shell, one home per feature (SettingsShell sub-nav). */}
        <Route path="settings" element={<SuspenseRoute><SettingsShell /></SuspenseRoute>}>
          <Route index element={<SuspenseRoute><SettingsLanding /></SuspenseRoute>} />
          <Route path="clusters/new"      element={<SuspenseRoute><RegisterClusterPage /></SuspenseRoute>} />
          <Route path="access"            element={<SuspenseRoute><AccessControlPage /></SuspenseRoute>} />
          <Route path="access/bindings/new"          element={<SuspenseRoute><RoleBindingFormPage /></SuspenseRoute>} />
          <Route path="access/service-accounts/new"  element={<SuspenseRoute><ServiceAccountFormPage /></SuspenseRoute>} />
          <Route path="access/users/new"             element={<SuspenseRoute><LocalUserFormPage /></SuspenseRoute>} />
          <Route path="access/roles/new"             element={<SuspenseRoute><CustomRoleFormPage /></SuspenseRoute>} />
          <Route path="access/sso/new"               element={<SuspenseRoute><AuthProviderFormPage /></SuspenseRoute>} />
          <Route path="access/sso/:id"               element={<SuspenseRoute><AuthProviderFormPage /></SuspenseRoute>} />
          <Route path="api-tokens"        element={<SuspenseRoute><ApiTokensPage /></SuspenseRoute>} />
          <Route path="api-tokens/new"    element={<SuspenseRoute><ApiTokenCreatePage /></SuspenseRoute>} />
          <Route path="security-policy"   element={<SuspenseRoute><SecurityPolicyPage /></SuspenseRoute>} />
          <Route path="attestation-trust" element={<SuspenseRoute><AttestationTrustPage /></SuspenseRoute>} />
          <Route path="attestation-trust/new" element={<SuspenseRoute><AttestationPolicyFormPage /></SuspenseRoute>} />
          <Route path="attestation-trust/:id" element={<SuspenseRoute><AttestationPolicyFormPage /></SuspenseRoute>} />
          <Route path="health"            element={<SuspenseRoute><SystemHealthPage /></SuspenseRoute>} />
          <Route path="scanner"           element={<SuspenseRoute><ScannerSourcesPage /></SuspenseRoute>} />
          <Route path="scanner/nvd"       element={<SuspenseRoute><NvdConfigPage /></SuspenseRoute>} />
          <Route path="network"           element={<SuspenseRoute><NetworkProxyPage /></SuspenseRoute>} />
          <Route path="effective-config"  element={<SuspenseRoute><EffectiveConfigPage /></SuspenseRoute>} />
          <Route path="retention"         element={<SuspenseRoute><DataRetentionPage /></SuspenseRoute>} />
          <Route path="backup"            element={<SuspenseRoute><BackupPage /></SuspenseRoute>} />
          <Route path="backup/destination" element={<SuspenseRoute><BackupDestinationPage /></SuspenseRoute>} />
          <Route path="backup/schedule"    element={<SuspenseRoute><BackupSchedulePage /></SuspenseRoute>} />
          <Route path="backup/restore"     element={<SuspenseRoute><BackupRestorePage /></SuspenseRoute>} />
          <Route path="integrations"      element={<SuspenseRoute><IntegrationsPage /></SuspenseRoute>} />
          <Route path="integrations/receivers/new" element={<SuspenseRoute><ReceiverFormPage /></SuspenseRoute>} />
          <Route path="integrations/receivers/:id" element={<SuspenseRoute><ReceiverFormPage /></SuspenseRoute>} />
          <Route path="connectors"        element={<SuspenseRoute><ConnectorCoveragePage /></SuspenseRoute>} />
          <Route path="connectors/new"     element={<SuspenseRoute><ConnectorFormPage /></SuspenseRoute>} />
          <Route path="connectors/scan/new" element={<SuspenseRoute><QueueScanPage /></SuspenseRoute>} />
          <Route path="connectors/:id"     element={<SuspenseRoute><ConnectorFormPage /></SuspenseRoute>} />
          <Route path="migration"         element={<SuspenseRoute><MigrationPage /></SuspenseRoute>} />
          <Route path="vulndb"            element={<Navigate to="/settings/scanner" replace />} />
        </Route>
      </Route>
    </Routes>
  );
}
