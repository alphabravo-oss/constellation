// App.tsx — cluster-first IA.
//
// Routing structure:
//   /login                          → /auth/login alias
//   /auth/login                     → LoginPage
//   /                               → redirect to /clusters
//   /clusters                       → ClustersLandingPage (picker, post-login landing)
//   /clusters/:id/*                 → ClusterRouter (provides cluster context via useCluster)
//       ├── dashboard               → DashboardPage (filtered by :id)
//       ├── findings                → FindingsPage (filtered by :id)
//       ├── findings/:fid           → FindingDetailPage
//       ├── nodes, images, assets, deployments, etc — see below
//   Org-level surfaces: /cve, /federation, /posture, and /settings/*.
import { lazy } from "react";
import { parseURLSearch, stringifyURLSearch } from "@/lib/route-search";
import { createRootRoute, createRoute, createRouter, Link, Navigate, Outlet, redirect, type ParsedLocation, type RouterHistory } from "@tanstack/react-router";
import { SuspenseRoute, LegacyClusterRedirect } from "./components/RouteLayouts";

import { AppShell } from "./components/AppShell";
import { RequireAuth } from "./components/RequireAuth";
import { LoginPage } from "./pages/LoginPage";
import { ClustersLandingPage } from "./pages/ClustersLandingPage";
import { ClusterRouter } from "./pages/ClusterRouter";

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
const RoutingRuleFormPage = lazy(() => import("./pages/integrations/RoutingRuleFormPage").then((m) => ({ default: m.RoutingRuleFormPage })));
const RoutingConfigFormPage = lazy(() => import("./pages/integrations/RoutingConfigFormPage").then((m) => ({ default: m.RoutingConfigFormPage })));
const SmtpSettingsFormPage = lazy(() => import("./pages/integrations/SmtpSettingsFormPage").then((m) => ({ default: m.SmtpSettingsFormPage })));
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
const FindingSavedViewFormPage = lazy(() => import("./pages/InventorySavedViewFormPage").then(m => ({ default: m.FindingSavedViewFormPage })));
const TimelineSavedViewFormPage = lazy(() => import("./pages/InventorySavedViewFormPage").then(m => ({ default: m.TimelineSavedViewFormPage })));
const NetworkSavedViewFormPage = lazy(() => import("./pages/NetworkSavedViewFormPage").then(m => ({ default: m.NetworkSavedViewFormPage })));
const NetworkSavedViewImportPage = lazy(() => import("./pages/NetworkSavedViewFormPage").then(m => ({ default: m.NetworkSavedViewImportPage })));
const NetworkPcapFormPage = lazy(() => import("./pages/NetworkPcapFormPage").then(m => ({ default: m.NetworkPcapFormPage })));
const AssetImageAcceptanceFormPage = lazy(() => import("./pages/AssetImageAcceptanceFormPage").then(m => ({ default: m.AssetImageAcceptanceFormPage })));
const DeploymentActionFormPage = lazy(() => import("./pages/DeploymentActionFormPage").then(m => ({ default: m.DeploymentActionFormPage })));
const FindingDetailPage     = lazy(() => import("./pages/FindingDetailPage").then((m) => ({ default: m.FindingDetailPage })));
const FindingAcceptRiskFormPage = lazy(() => import("./pages/FindingActionFormPage").then(m => ({default:m.FindingAcceptRiskFormPage})));
const FindingSuppressFormPage = lazy(() => import("./pages/FindingActionFormPage").then(m => ({default:m.FindingSuppressFormPage})));
const FindingCommentFormPage = lazy(() => import("./pages/FindingActionFormPage").then(m => ({default:m.FindingCommentFormPage})));
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
const VulnProfileFormPage = lazy(() => import("./pages/VulnProfileFormPage").then((m) => ({ default: m.VulnProfileFormPage })));
const ResponseCatalogOverrideFormPage = lazy(() => import("./pages/ResponseCatalogOverrideFormPage").then((m) => ({ default: m.ResponseCatalogOverrideFormPage })));
const ComplianceExemptionFormPage = lazy(() => import("./pages/ComplianceExemptionFormPage").then((m) => ({ default: m.ComplianceExemptionFormPage })));
const ComplianceScheduleFormPage = lazy(() => import("./pages/ComplianceScheduleFormPage").then((m) => ({ default: m.ComplianceScheduleFormPage })));
const AdmissionProfileImportPage = lazy(() => import("./pages/AdmissionProfileImportPage").then((m) => ({ default: m.AdmissionProfileImportPage })));
const GroupSettingsPage = lazy(() => import("./pages/GroupSettingsPage").then((m) => ({ default: m.GroupSettingsPage })));
const AdmissionPage         = lazy(() => import("./pages/AdmissionPage").then((m) => ({ default: m.AdmissionPage })));
const AdmissionSettingsPage = lazy(() => import("./pages/AdmissionSettingsPage").then((m) => ({ default: m.AdmissionSettingsPage })));
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
const GroupFormPage = lazy(() => import("./pages/GroupFormPage").then((m) => ({ default: m.GroupFormPage })));
const DPIGroupBindingFormPage = lazy(() => import("./pages/DPIGroupBindingFormPage").then((m) => ({ default: m.DPIGroupBindingFormPage })));
const GroupDetailPage       = lazy(() => import("./pages/GroupDetailPage").then((m) => ({ default: m.GroupDetailPage })));
const FileMonitorPage       = lazy(() => import("./pages/FileMonitorPage").then((m) => ({ default: m.FileMonitorPage })));
const TimelinePage          = lazy(() => import("./pages/TimelinePage").then((m) => ({ default: m.TimelinePage })));
const NetworkMapPage        = lazy(() => import("./pages/NetworkMapPage").then((m) => ({ default: m.NetworkMapPage })));
const NetworkActionFormPage = lazy(() => import("./pages/NetworkActionFormPage").then(m=>({default:m.NetworkActionFormPage})));
const RuntimePoliciesPage   = lazy(() => import("./pages/RuntimePoliciesPage").then((m) => ({ default: m.RuntimePoliciesPage })));
const RuntimeDLPPage        = lazy(() => import("./pages/RuntimeDLPPage").then((m) => ({ default: m.RuntimeDLPPage })));
const RuntimeSignaturesPage = lazy(() => import("./pages/RuntimeSignaturesPage").then((m) => ({ default: m.RuntimeSignaturesPage })));
const DeploymentsPage       = lazy(() => import("./pages/DeploymentsPage").then((m) => ({ default: m.DeploymentsPage })));
const DeploymentDetailPage  = lazy(() => import("./pages/DeploymentDetailPage").then((m) => ({ default: m.DeploymentDetailPage })));
const AuditPage             = lazy(() => import("./pages/AuditPage").then((m) => ({ default: m.AuditPage })));
const ClusterHealthPage     = lazy(() => import("./pages/ClusterHealthPage").then((m) => ({ default: m.ClusterHealthPage })));
const BaselinesPage         = lazy(() => import("./pages/BaselinesPage").then((m) => ({ default: m.BaselinesPage })));
const BaselineDetailPage    = lazy(() => import("./pages/baselines/BaselineDetailPage").then((m) => ({ default: m.BaselineDetailPage })));
const BaselineRuleFormPage = lazy(() => import("./pages/baselines/BaselineRuleFormPage").then((m) => ({ default: m.BaselineRuleFormPage })));
const BaselineActionFormPage = lazy(() => import("./pages/baselines/BaselineActionFormPage").then((m) => ({ default: m.BaselineActionFormPage })));
const PolicyFormPage        = lazy(() => import("./pages/PolicyFormPage").then((m) => ({ default: m.PolicyFormPage })));
const ResponseRuleFormPage  = lazy(() => import("./pages/ResponseRuleFormPage").then((m) => ({ default: m.ResponseRuleFormPage })));
const RuntimePolicyFormPage = lazy(() => import("./pages/RuntimePolicyFormPage").then((m) => ({ default: m.RuntimePolicyFormPage })));
const RuntimeDLPFormPage    = lazy(() => import("./pages/RuntimeDLPFormPage").then((m) => ({ default: m.RuntimeDLPFormPage })));
const RuntimeSignatureFormPage = lazy(() => import("./pages/RuntimeSignatureFormPage").then((m) => ({ default: m.RuntimeSignatureFormPage })));
const FileMonitorFormPage   = lazy(() => import("./pages/FileMonitorFormPage").then((m) => ({ default: m.FileMonitorFormPage })));
const RegistriesPage        = lazy(() => import("./pages/RegistriesPage").then((m) => ({ default: m.RegistriesPage })));
const RegistryFormPage = lazy(() => import("./pages/RegistryFormPage").then((m) => ({ default: m.RegistryFormPage })));
const RegistryImagesPage    = lazy(() => import("./pages/RegistryImagesPage").then((m) => ({ default: m.RegistryImagesPage })));
const ContainersPage        = lazy(() => import("./pages/ContainersPage").then((m) => ({ default: m.ContainersPage })));
const NetworkRulesPage      = lazy(() => import("./pages/NetworkRulesPage").then((m) => ({ default: m.NetworkRulesPage })));
const NetworkRuleFormPage   = lazy(() => import("./pages/NetworkRuleFormPage").then((m) => ({ default: m.NetworkRuleFormPage })));
const ComponentsPage        = lazy(() => import("./pages/ComponentsPage").then((m) => ({ default: m.ComponentsPage })));
const NeuVectorSwitchboardPage = lazy(() => import("./pages/NeuVectorSwitchboardPage").then((m) => ({ default: m.NeuVectorSwitchboardPage })));

// Resolve aliases before rendering so a pending navigation cannot re-run a
// redirect against the destination URL and lose its suffix or loop.
function aliasRedirect({ to, cluster = false, from }: { to: string; cluster?: boolean; from?: string }) {
  return ({ location, params }: { location: ParsedLocation; params: Record<string, string> }) => {
    const id = params.id;
    const [targetPath, defaultSearch = ""] = to.split("?");
    const pathname = targetPath.startsWith("/") ? targetPath : cluster ? `/clusters/${id}/${targetPath}` : targetPath;
    const aliasPath = from ? (cluster ? `/clusters/${id}/${from}` : `/${from}`) : "";
    const suffix = from ? location.pathname.slice(aliasPath.length) : "";
    const search = new URLSearchParams(location.searchStr);
    new URLSearchParams(defaultSearch).forEach((value, key) => search.set(key, value));
    throw redirect({ href: `${pathname}${suffix}${search.size ? `?${search}` : ""}${location.hash ? `#${location.hash}` : ""}`, replace: true });
  };
}

const rootRoute = createRootRoute({ component: Outlet, validateSearch: (search: Record<string, unknown>) => search, notFoundComponent: () => <div className="p-8"><h1>Page not found</h1><Link to="/clusters">Go to clusters</Link></div> });
const public__loginRoute = createRoute({ getParentRoute: () => rootRoute, path: "/login", beforeLoad: aliasRedirect({ to: "/auth/login" }) });
const public__auth_loginRoute = createRoute({ getParentRoute: () => rootRoute, path: "/auth/login", component: () => (<LoginPage />) });
const authenticatedRoute = createRoute({ getParentRoute: () => rootRoute, id: "_authenticated", component: () => (<RequireAuth>
            <AppShell />
          </RequireAuth>) });
const app_indexRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "/", component: () => (<Navigate to="/clusters" replace />) });
const app_dashboardRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "dashboard", component: () => (<LegacyClusterRedirect />) });
const app_findings_splatRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "findings/$", component: () => (<LegacyClusterRedirect />) });
const app_nodes_splatRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "nodes/$", component: () => (<LegacyClusterRedirect />) });
const app_hosts_splatRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "hosts/$", component: () => (<LegacyClusterRedirect />) });
const app_containersRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "containers", component: () => (<LegacyClusterRedirect />) });
const app_images_splatRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "images/$", component: () => (<LegacyClusterRedirect />) });
const app_serverless_splatRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "serverless/$", component: () => (<LegacyClusterRedirect />) });
const app_repositoriesRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "repositories", component: () => (<LegacyClusterRedirect />) });
const app_assets_splatRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "assets/$", component: () => (<LegacyClusterRedirect />) });
const app_deployments_splatRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "deployments/$", component: () => (<LegacyClusterRedirect />) });
const app_services_splatRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "services/$", component: () => (<LegacyClusterRedirect />) });
const app_workloads_splatRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "workloads/$", component: () => (<LegacyClusterRedirect />) });
const app_complianceRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "compliance", component: () => (<LegacyClusterRedirect />) });
const app_registries_splatRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "registries/$", component: () => (<LegacyClusterRedirect />) });
const app_registry_splatRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "registry/$", component: () => (<LegacyClusterRedirect />) });
const app_exceptions_splatRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "exceptions/$", component: () => (<LegacyClusterRedirect />) });
const app_runtime_splatRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "runtime/$", component: () => (<LegacyClusterRedirect />) });
const app_responseRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "response", component: () => (<LegacyClusterRedirect />) });
const app_response_rules_splatRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "response-rules/$", component: () => (<LegacyClusterRedirect />) });
const app_vuln_profilesRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "vuln-profiles", component: () => (<LegacyClusterRedirect />) });
const app_vulnerability_profilesRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "vulnerability-profiles", component: () => (<LegacyClusterRedirect />) });
const app_groups_splatRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "groups/$", component: () => (<LegacyClusterRedirect />) });
const app_file_monitor_splatRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "file-monitor/$", component: () => (<LegacyClusterRedirect />) });
const app_timelineRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "timeline", component: () => (<LegacyClusterRedirect />) });
const app_eventsRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "events", component: () => (<LegacyClusterRedirect />) });
const app_activityRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "activity", component: () => (<LegacyClusterRedirect />) });
const app_incidentsRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "incidents", component: () => (<LegacyClusterRedirect />) });
const app_security_eventsRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "security-events", component: () => (<LegacyClusterRedirect />) });
const app_networkRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "network", component: () => (<LegacyClusterRedirect />) });
const app_network_activityRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "network-activity", component: () => (<LegacyClusterRedirect />) });
const app_network_rules_splatRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "network-rules/$", component: () => (<LegacyClusterRedirect />) });
const app_neuvectorRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "neuvector", component: () => (<LegacyClusterRedirect />) });
const app_waf_splatRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "waf/$", component: () => (<LegacyClusterRedirect />) });
const app_dlp_splatRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "dlp/$", component: () => (<LegacyClusterRedirect />) });
const app_runtime_policies_splatRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "runtime-policies/$", component: () => (<LegacyClusterRedirect />) });
const app_runtime_dlp_splatRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "runtime-dlp/$", component: () => (<LegacyClusterRedirect />) });
const app_runtime_signatures_splatRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "runtime-signatures/$", component: () => (<LegacyClusterRedirect />) });
const app_admission_splatRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "admission/$", component: () => (<LegacyClusterRedirect />) });
const app_admission_control_splatRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "admission-control/$", component: () => (<LegacyClusterRedirect />) });
const app_policyRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "policy", component: () => (<LegacyClusterRedirect />) });
const app_policies_splatRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "policies/$", component: () => (<LegacyClusterRedirect />) });
const app_auditRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "audit", component: () => (<LegacyClusterRedirect />) });
const app_audit_logRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "audit-log", component: () => (<LegacyClusterRedirect />) });
const app_componentsRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "components", component: () => (<LegacyClusterRedirect />) });
const app_controllersRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "controllers", component: () => (<LegacyClusterRedirect />) });
const app_enforcersRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "enforcers", component: () => (<LegacyClusterRedirect />) });
const app_agentsRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "agents", component: () => (<LegacyClusterRedirect />) });
const app_scannersRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "scanners", component: () => (<LegacyClusterRedirect />) });
const app_risk_splatRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "risk/$", component: () => (<LegacyClusterRedirect />) });
const app_healthRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "health", beforeLoad: aliasRedirect({ to: "/settings/health" }) });
const app_clustersRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "clusters", component: () => (<ClustersLandingPage />) });
const app_clusters_idRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "clusters/$id", component: () => (<ClusterRouter />) });
const cluster_indexRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "/", component: () => (<Navigate to="/clusters/$id/dashboard" params={(prev) => ({ id: prev.id! })} replace />) });
const cluster_dashboardRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "dashboard", component: () => (<SuspenseRoute><DashboardPage /></SuspenseRoute>) });
const cluster_neuvectorRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "neuvector", component: () => (<SuspenseRoute><NeuVectorSwitchboardPage /></SuspenseRoute>) });
const cluster_network_actionRoute = createRoute({getParentRoute:()=>app_clusters_idRoute,path:"network/actions/$action",component:()=><SuspenseRoute><NetworkActionFormPage /></SuspenseRoute>});
const cluster_findingsRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "findings", component: () => (<SuspenseRoute><FindingsPage /></SuspenseRoute>) });
const cluster_findings_savedViewRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "findings/views/new", component: () => <SuspenseRoute><FindingSavedViewFormPage /></SuspenseRoute> });
const cluster_timeline_savedViewRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "timeline/views/new", component: () => <SuspenseRoute><TimelineSavedViewFormPage /></SuspenseRoute> });
const cluster_network_savedViewRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "network/views/new", component: () => <SuspenseRoute><NetworkSavedViewFormPage /></SuspenseRoute> });
const cluster_network_importViewsRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "network/views/import", component: () => <SuspenseRoute><NetworkSavedViewImportPage /></SuspenseRoute> });
const cluster_network_pcap_newRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "network/pcap/new", component: () => <SuspenseRoute><NetworkPcapFormPage /></SuspenseRoute> });
const cluster_asset_acceptance_newRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "assets/$aid/image-acceptance/new", component: () => <SuspenseRoute><AssetImageAcceptanceFormPage action="create" /></SuspenseRoute> });
const cluster_asset_acceptance_revokeRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "assets/$aid/image-acceptance/$acceptanceId/revoke", component: () => <SuspenseRoute><AssetImageAcceptanceFormPage action="revoke" /></SuspenseRoute> });
const cluster_deployment_actionRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "deployments/$did/actions/$action", component: () => <SuspenseRoute><DeploymentActionFormPage /></SuspenseRoute> });
const cluster_findings_fidRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "findings/$fid", component: () => (<SuspenseRoute><FindingDetailPage /></SuspenseRoute>) });
const cluster_finding_acceptRoute = createRoute({getParentRoute:()=>app_clusters_idRoute,path:"findings/$fid/accept-risk",component:()=><SuspenseRoute><FindingAcceptRiskFormPage /></SuspenseRoute>});
const cluster_finding_suppressRoute = createRoute({getParentRoute:()=>app_clusters_idRoute,path:"findings/$fid/suppress",component:()=><SuspenseRoute><FindingSuppressFormPage /></SuspenseRoute>});
const cluster_finding_commentRoute = createRoute({getParentRoute:()=>app_clusters_idRoute,path:"findings/$fid/comments/new",component:()=><SuspenseRoute><FindingCommentFormPage /></SuspenseRoute>});
const cluster_cve_cveIdRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "cve/$cveId", component: () => (<SuspenseRoute><CVEDetailPage /></SuspenseRoute>) });
const cluster_nodesRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "nodes", component: () => (<SuspenseRoute><NodesPage /></SuspenseRoute>) });
const cluster_hosts_splatRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "hosts/$", beforeLoad: aliasRedirect({ to: "nodes", cluster: true, from: "hosts" }) });
const cluster_containersRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "containers", component: () => (<SuspenseRoute><ContainersPage /></SuspenseRoute>) });
const cluster_nodes_nodeNameRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "nodes/$nodeName", component: () => (<SuspenseRoute><NodeDetailPage /></SuspenseRoute>) });
const cluster_imagesRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "images", component: () => (<SuspenseRoute><ImageScansPage /></SuspenseRoute>) });
const cluster_images_resultIdRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "images/$resultId", component: () => (<SuspenseRoute><ImageScanDetailPage /></SuspenseRoute>) });
const cluster_serverlessRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "serverless", component: () => (<SuspenseRoute><ServerlessFunctionsPage /></SuspenseRoute>) });
const cluster_serverless_functionIdRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "serverless/$functionId", component: () => (<SuspenseRoute><ServerlessFunctionDetailPage /></SuspenseRoute>) });
const cluster_repositoriesRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "repositories", component: () => (<SuspenseRoute><RepositoryScansPage /></SuspenseRoute>) });
const cluster_assetsRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "assets", component: () => (<SuspenseRoute><AssetsPage /></SuspenseRoute>) });
const cluster_assets_aidRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "assets/$aid", component: () => (<SuspenseRoute><AssetDetailPage /></SuspenseRoute>) });
const cluster_deploymentsRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "deployments", component: () => (<SuspenseRoute><DeploymentsPage /></SuspenseRoute>) });
const cluster_services_splatRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "services/$", beforeLoad: aliasRedirect({ to: "deployments", cluster: true, from: "services" }) });
const cluster_workloads_splatRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "workloads/$", beforeLoad: aliasRedirect({ to: "deployments", cluster: true, from: "workloads" }) });
const cluster_deployments_didRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "deployments/$did", component: () => (<SuspenseRoute><DeploymentDetailPage /></SuspenseRoute>) });
const cluster_complianceRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "compliance", component: () => (<SuspenseRoute><CompliancePage /></SuspenseRoute>) });
const cluster_registriesRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "registries", component: () => (<SuspenseRoute><RegistriesPage /></SuspenseRoute>) });
const cluster_registries_newRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "registries/new", component: () => (<SuspenseRoute><RegistryFormPage /></SuspenseRoute>) });
const cluster_registries_editRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "registries/$regId/edit", component: () => (<SuspenseRoute><RegistryFormPage /></SuspenseRoute>) });
const cluster_registry_splatRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "registry/$", beforeLoad: aliasRedirect({ to: "registries", cluster: true, from: "registry" }) });
const cluster_registries_regIdRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "registries/$regId", component: () => (<SuspenseRoute><RegistryImagesPage /></SuspenseRoute>) });
const cluster_exceptionsRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "exceptions", component: () => (<SuspenseRoute><VulnerabilityExceptionsPage /></SuspenseRoute>) });
const cluster_runtimeRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "runtime", component: () => (<SuspenseRoute><RuntimePage /></SuspenseRoute>) });
const cluster_runtime_baselinesRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "runtime/baselines", component: () => (<SuspenseRoute><BaselinesPage /></SuspenseRoute>) });
const cluster_runtime_baselines_baselineIdRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "runtime/baselines/$baselineId", component: () => (<SuspenseRoute><BaselineDetailPage /></SuspenseRoute>) });
const cluster_runtime_baseline_rule_newRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "runtime/baselines/$baselineId/rules/new", component: () => (<SuspenseRoute><BaselineRuleFormPage /></SuspenseRoute>) });
const cluster_runtime_baseline_rule_editRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "runtime/baselines/$baselineId/rules/$ruleId/edit", component: () => (<SuspenseRoute><BaselineRuleFormPage /></SuspenseRoute>) });
const cluster_runtime_baseline_actionRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "runtime/baselines/$baselineId/actions/$action", component: () => (<SuspenseRoute><BaselineActionFormPage /></SuspenseRoute>) });
const cluster_responseRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "response", component: () => (<SuspenseRoute><ResponsePage /></SuspenseRoute>) });
const cluster_response_rulesRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "response-rules", component: () => (<SuspenseRoute><ResponseRulesPage /></SuspenseRoute>) });
const cluster_response_rules_newRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "response-rules/new", component: () => (<SuspenseRoute><ResponseRuleFormPage /></SuspenseRoute>) });
const cluster_response_rules_ruleIdRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "response-rules/$ruleId", component: () => (<SuspenseRoute><ResponseRuleFormPage /></SuspenseRoute>) });
const cluster_vuln_profilesRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "vuln-profiles", component: () => (<SuspenseRoute><VulnProfilePage /></SuspenseRoute>) });
const cluster_vulnerability_profilesRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "vulnerability-profiles", beforeLoad: aliasRedirect({ to: "vuln-profiles", cluster: true }) });
const cluster_vuln_profile_newRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "vuln-profiles/new", component: () => (<SuspenseRoute><VulnProfileFormPage /></SuspenseRoute>) });
const cluster_vuln_profile_editRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "vuln-profiles/$profileId/edit", component: () => (<SuspenseRoute><VulnProfileFormPage /></SuspenseRoute>) });
const cluster_response_catalog_editRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "response/$ruleId/edit", component: () => (<SuspenseRoute><ResponseCatalogOverrideFormPage /></SuspenseRoute>) });
const cluster_compliance_exemption_newRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "compliance/exemptions/new", component: () => (<SuspenseRoute><ComplianceExemptionFormPage /></SuspenseRoute>) });
const cluster_compliance_schedule_newRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "compliance/schedules/new", component: () => (<SuspenseRoute><ComplianceScheduleFormPage /></SuspenseRoute>) });
const cluster_groupsRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "groups", component: () => (<SuspenseRoute><GroupsPage /></SuspenseRoute>) });
const cluster_groups_settingsRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "groups/settings", component: () => (<SuspenseRoute><GroupSettingsPage /></SuspenseRoute>) });
const cluster_groups_newRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "groups/new", component: () => (<SuspenseRoute><GroupFormPage /></SuspenseRoute>) });
const cluster_groups_editRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "groups/$groupId/edit", component: () => (<SuspenseRoute><GroupFormPage /></SuspenseRoute>) });
const cluster_dlp_scope_newRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "runtime-dlp/scope/new", component: () => (<SuspenseRoute><DPIGroupBindingFormPage kind="dlp" /></SuspenseRoute>) });
const cluster_waf_scope_newRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "runtime-signatures/scope/new", component: () => (<SuspenseRoute><DPIGroupBindingFormPage kind="waf" /></SuspenseRoute>) });
const cluster_groups_groupIdRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "groups/$groupId", component: () => (<SuspenseRoute><GroupDetailPage /></SuspenseRoute>) });
const cluster_file_monitorRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "file-monitor", component: () => (<SuspenseRoute><FileMonitorPage /></SuspenseRoute>) });
const cluster_file_monitor_newRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "file-monitor/new", component: () => (<SuspenseRoute><FileMonitorFormPage /></SuspenseRoute>) });
const cluster_file_monitor_ruleIdRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "file-monitor/$ruleId", component: () => (<SuspenseRoute><FileMonitorFormPage /></SuspenseRoute>) });
const cluster_timelineRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "timeline", component: () => (<SuspenseRoute><TimelinePage /></SuspenseRoute>) });
const cluster_eventsRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "events", beforeLoad: aliasRedirect({ to: "timeline", cluster: true }) });
const cluster_activityRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "activity", beforeLoad: aliasRedirect({ to: "timeline", cluster: true }) });
const cluster_incidentsRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "incidents", beforeLoad: aliasRedirect({ to: "timeline?tab=incident", cluster: true }) });
const cluster_security_eventsRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "security-events", beforeLoad: aliasRedirect({ to: "timeline", cluster: true }) });
const cluster_networkRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "network", component: () => (<SuspenseRoute><NetworkMapPage /></SuspenseRoute>) });
const cluster_network_activityRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "network-activity", beforeLoad: aliasRedirect({ to: "network", cluster: true }) });
const cluster_network_rulesRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "network-rules", component: () => (<SuspenseRoute><NetworkRulesPage /></SuspenseRoute>) });
const cluster_network_rules_newRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "network-rules/new", component: () => (<SuspenseRoute><NetworkRuleFormPage /></SuspenseRoute>) });
const cluster_network_rules_editRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "network-rules/$ruleId/edit", component: () => (<SuspenseRoute><NetworkRuleFormPage /></SuspenseRoute>) });
const cluster_waf_splatRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "waf/$", beforeLoad: aliasRedirect({ to: "runtime-signatures", cluster: true, from: "waf" }) });
const cluster_dlp_splatRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "dlp/$", beforeLoad: aliasRedirect({ to: "runtime-dlp", cluster: true, from: "dlp" }) });
const cluster_runtime_policiesRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "runtime-policies", component: () => (<SuspenseRoute><RuntimePoliciesPage /></SuspenseRoute>) });
const cluster_runtime_policies_newRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "runtime-policies/new", component: () => (<SuspenseRoute><RuntimePolicyFormPage /></SuspenseRoute>) });
const cluster_runtime_policies_policyIdRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "runtime-policies/$policyId", component: () => (<SuspenseRoute><RuntimePolicyFormPage /></SuspenseRoute>) });
const cluster_runtime_dlpRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "runtime-dlp", component: () => (<SuspenseRoute><RuntimeDLPPage /></SuspenseRoute>) });
const cluster_runtime_dlp_newRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "runtime-dlp/new", component: () => (<SuspenseRoute><RuntimeDLPFormPage /></SuspenseRoute>) });
const cluster_runtime_dlp_ruleIdRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "runtime-dlp/$ruleId", component: () => (<SuspenseRoute><RuntimeDLPFormPage /></SuspenseRoute>) });
const cluster_runtime_signaturesRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "runtime-signatures", component: () => (<SuspenseRoute><RuntimeSignaturesPage /></SuspenseRoute>) });
const cluster_runtime_signatures_newRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "runtime-signatures/new", component: () => (<SuspenseRoute><RuntimeSignatureFormPage /></SuspenseRoute>) });
const cluster_runtime_signatures_sigIdRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "runtime-signatures/$sigId", component: () => (<SuspenseRoute><RuntimeSignatureFormPage /></SuspenseRoute>) });
const cluster_admissionRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "admission", component: () => (<SuspenseRoute><AdmissionPage /></SuspenseRoute>) });
const cluster_admission_control_splatRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "admission-control/$", beforeLoad: aliasRedirect({ to: "admission", cluster: true, from: "admission-control" }) });
const cluster_admission_settingsRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "admission/settings", component: () => (<SuspenseRoute><AdmissionSettingsPage /></SuspenseRoute>) });
const cluster_admission_importRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "admission/import", component: () => (<SuspenseRoute><AdmissionProfileImportPage /></SuspenseRoute>) });
const cluster_admission_newRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "admission/new", component: () => (<SuspenseRoute><AdmissionRuleFormPage /></SuspenseRoute>) });
const cluster_policyRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "policy", component: () => (<SuspenseRoute><PolicyCenterPage /></SuspenseRoute>) });
const cluster_policiesRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "policies", component: () => (<SuspenseRoute><PoliciesPage /></SuspenseRoute>) });
const cluster_policies_newRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "policies/new", component: () => (<SuspenseRoute><PolicyWizardPage /></SuspenseRoute>) });
const cluster_policies_policyIdRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "policies/$policyId", component: () => (<SuspenseRoute><PolicyFormPage /></SuspenseRoute>) });
const cluster_auditRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "audit", component: () => (<SuspenseRoute><AuditPage /></SuspenseRoute>) });
const cluster_audit_logRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "audit-log", beforeLoad: aliasRedirect({ to: "audit", cluster: true }) });
const cluster_componentsRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "components", component: () => (<SuspenseRoute><ComponentsPage /></SuspenseRoute>) });
const cluster_controllersRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "controllers", beforeLoad: aliasRedirect({ to: "components?role=controller", cluster: true }) });
const cluster_enforcersRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "enforcers", beforeLoad: aliasRedirect({ to: "components?role=enforcer", cluster: true }) });
const cluster_agentsRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "agents", beforeLoad: aliasRedirect({ to: "components?role=enforcer", cluster: true }) });
const cluster_scannersRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "scanners", beforeLoad: aliasRedirect({ to: "components?role=scanner", cluster: true }) });
const cluster_vulndbRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "vulndb", beforeLoad: aliasRedirect({ to: "/settings/scanner" }) });
const cluster_cve_sourcesRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "cve-sources", beforeLoad: aliasRedirect({ to: "/settings/scanner" }) });
const cluster_notificationsRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "notifications", beforeLoad: aliasRedirect({ to: "/settings/integrations" }) });
const cluster_system_configRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "system-config", beforeLoad: aliasRedirect({ to: "/settings/effective-config" }) });
const cluster_sysconfigRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "sysconfig", beforeLoad: aliasRedirect({ to: "/settings/effective-config" }) });
const cluster_risk_entityType_entityIdRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "risk/$entityType/$entityId", component: () => (<SuspenseRoute><RiskDetailPage /></SuspenseRoute>) });
const cluster_healthRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "health", component: () => (<SuspenseRoute><ClusterHealthPage /></SuspenseRoute>) });
const cluster_system_healthRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "system-health", beforeLoad: aliasRedirect({ to: "/settings/health" }) });
const cluster_settingsRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "settings", beforeLoad: aliasRedirect({ to: "/settings" }) });
const cluster_tokens_splatRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "tokens/$", beforeLoad: aliasRedirect({ to: "/settings/api-tokens", cluster: true, from: "tokens" }) });
const cluster_attestation_trust_splatRoute = createRoute({ getParentRoute: () => app_clusters_idRoute, path: "attestation-trust/$", beforeLoad: aliasRedirect({ to: "/settings/attestation-trust", cluster: true, from: "attestation-trust" }) });
const app_cveRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "cve", component: () => (<SuspenseRoute><CVEPage /></SuspenseRoute>) });
const app_cve_idRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "cve/$id", component: () => (<SuspenseRoute><CVEDetailPage /></SuspenseRoute>) });
const app_federationRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "federation", component: () => (<SuspenseRoute><FederationPage /></SuspenseRoute>) });
const app_federation_newRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "federation/new", component: () => (<SuspenseRoute><FederationPeerFormPage /></SuspenseRoute>) });
const app_postureRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "posture", component: () => (<SuspenseRoute><CoveragePage /></SuspenseRoute>) });
const app_coverageRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "coverage", beforeLoad: aliasRedirect({ to: "/posture" }) });
const app_system_healthRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "system-health", beforeLoad: aliasRedirect({ to: "/settings/health" }) });
const app_access_control_splatRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "access-control/$", beforeLoad: aliasRedirect({ to: "/settings/access", from: "access-control" }) });
const app_system_configRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "system-config", beforeLoad: aliasRedirect({ to: "/settings/effective-config" }) });
const app_sysconfigRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "sysconfig", beforeLoad: aliasRedirect({ to: "/settings/effective-config" }) });
const app_vulndbRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "vulndb", beforeLoad: aliasRedirect({ to: "/settings/scanner" }) });
const app_cve_sourcesRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "cve-sources", beforeLoad: aliasRedirect({ to: "/settings/scanner" }) });
const app_notificationsRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "notifications", beforeLoad: aliasRedirect({ to: "/settings/integrations" }) });
const app_integrations_splatRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "integrations/$", beforeLoad: aliasRedirect({ to: "/settings/integrations", from: "integrations" }) });
const app_tokens_splatRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "tokens/$", beforeLoad: aliasRedirect({ to: "/settings/api-tokens", from: "tokens" }) });
const app_attestation_trust_splatRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "attestation-trust/$", beforeLoad: aliasRedirect({ to: "/settings/attestation-trust", from: "attestation-trust" }) });
const app_attestation_splatRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "attestation/$", beforeLoad: aliasRedirect({ to: "/settings/attestation-trust", from: "attestation" }) });
const app_settingsRoute = createRoute({ getParentRoute: () => authenticatedRoute, path: "settings", component: () => (<SuspenseRoute><SettingsShell /></SuspenseRoute>) });
const settings_indexRoute = createRoute({ getParentRoute: () => app_settingsRoute, path: "/", component: () => (<SuspenseRoute><SettingsLanding /></SuspenseRoute>) });
const settings_system_healthRoute = createRoute({ getParentRoute: () => app_settingsRoute, path: "system-health", beforeLoad: aliasRedirect({ to: "/settings/health" }) });
const settings_tokens_splatRoute = createRoute({ getParentRoute: () => app_settingsRoute, path: "tokens/$", beforeLoad: aliasRedirect({ to: "/settings/api-tokens", from: "settings/tokens" }) });
const settings_attestation_splatRoute = createRoute({ getParentRoute: () => app_settingsRoute, path: "attestation/$", beforeLoad: aliasRedirect({ to: "/settings/attestation-trust", from: "settings/attestation" }) });
const settings_access_control_splatRoute = createRoute({ getParentRoute: () => app_settingsRoute, path: "access-control/$", beforeLoad: aliasRedirect({ to: "/settings/access", from: "settings/access-control" }) });
const settings_notifications_splatRoute = createRoute({ getParentRoute: () => app_settingsRoute, path: "notifications/$", beforeLoad: aliasRedirect({ to: "/settings/integrations", from: "settings/notifications" }) });
const settings_clusters_newRoute = createRoute({ getParentRoute: () => app_settingsRoute, path: "clusters/new", component: () => (<SuspenseRoute><RegisterClusterPage /></SuspenseRoute>) });
const settings_cluster_bundle_rotateRoute = createRoute({ getParentRoute: () => app_settingsRoute, path: "clusters/bundles/$bundleId/rotate", component: () => (<SuspenseRoute><RegisterClusterPage /></SuspenseRoute>) });
const settings_accessRoute = createRoute({ getParentRoute: () => app_settingsRoute, path: "access", component: () => (<SuspenseRoute><AccessControlPage /></SuspenseRoute>) });
const settings_access_bindings_newRoute = createRoute({ getParentRoute: () => app_settingsRoute, path: "access/bindings/new", component: () => (<SuspenseRoute><RoleBindingFormPage /></SuspenseRoute>) });
const settings_access_service_accounts_newRoute = createRoute({ getParentRoute: () => app_settingsRoute, path: "access/service-accounts/new", component: () => (<SuspenseRoute><ServiceAccountFormPage /></SuspenseRoute>) });
const settings_access_users_newRoute = createRoute({ getParentRoute: () => app_settingsRoute, path: "access/users/new", component: () => (<SuspenseRoute><LocalUserFormPage /></SuspenseRoute>) });
const settings_access_roles_newRoute = createRoute({ getParentRoute: () => app_settingsRoute, path: "access/roles/new", component: () => (<SuspenseRoute><CustomRoleFormPage /></SuspenseRoute>) });
const settings_access_sso_newRoute = createRoute({ getParentRoute: () => app_settingsRoute, path: "access/sso/new", component: () => (<SuspenseRoute><AuthProviderFormPage /></SuspenseRoute>) });
const settings_access_sso_idRoute = createRoute({ getParentRoute: () => app_settingsRoute, path: "access/sso/$id", component: () => (<SuspenseRoute><AuthProviderFormPage /></SuspenseRoute>) });
const settings_api_tokensRoute = createRoute({ getParentRoute: () => app_settingsRoute, path: "api-tokens", component: () => (<SuspenseRoute><ApiTokensPage /></SuspenseRoute>) });
const settings_api_tokens_newRoute = createRoute({ getParentRoute: () => app_settingsRoute, path: "api-tokens/new", component: () => (<SuspenseRoute><ApiTokenCreatePage /></SuspenseRoute>) });
const settings_security_policyRoute = createRoute({ getParentRoute: () => app_settingsRoute, path: "security-policy", component: () => (<SuspenseRoute><SecurityPolicyPage /></SuspenseRoute>) });
const settings_attestation_trustRoute = createRoute({ getParentRoute: () => app_settingsRoute, path: "attestation-trust", component: () => (<SuspenseRoute><AttestationTrustPage /></SuspenseRoute>) });
const settings_attestation_trust_newRoute = createRoute({ getParentRoute: () => app_settingsRoute, path: "attestation-trust/new", component: () => (<SuspenseRoute><AttestationPolicyFormPage /></SuspenseRoute>) });
const settings_attestation_trust_idRoute = createRoute({ getParentRoute: () => app_settingsRoute, path: "attestation-trust/$id", component: () => (<SuspenseRoute><AttestationPolicyFormPage /></SuspenseRoute>) });
const settings_healthRoute = createRoute({ getParentRoute: () => app_settingsRoute, path: "health", component: () => (<SuspenseRoute><SystemHealthPage /></SuspenseRoute>) });
const settings_scannerRoute = createRoute({ getParentRoute: () => app_settingsRoute, path: "scanner", component: () => (<SuspenseRoute><ScannerSourcesPage /></SuspenseRoute>) });
const settings_scanner_nvdRoute = createRoute({ getParentRoute: () => app_settingsRoute, path: "scanner/nvd", component: () => (<SuspenseRoute><NvdConfigPage /></SuspenseRoute>) });
const settings_networkRoute = createRoute({ getParentRoute: () => app_settingsRoute, path: "network", component: () => (<SuspenseRoute><NetworkProxyPage /></SuspenseRoute>) });
const settings_effective_configRoute = createRoute({ getParentRoute: () => app_settingsRoute, path: "effective-config", component: () => (<SuspenseRoute><EffectiveConfigPage /></SuspenseRoute>) });
const settings_retentionRoute = createRoute({ getParentRoute: () => app_settingsRoute, path: "retention", component: () => (<SuspenseRoute><DataRetentionPage /></SuspenseRoute>) });
const settings_backupRoute = createRoute({ getParentRoute: () => app_settingsRoute, path: "backup", component: () => (<SuspenseRoute><BackupPage /></SuspenseRoute>) });
const settings_backup_destinationRoute = createRoute({ getParentRoute: () => app_settingsRoute, path: "backup/destination", component: () => (<SuspenseRoute><BackupDestinationPage /></SuspenseRoute>) });
const settings_backup_scheduleRoute = createRoute({ getParentRoute: () => app_settingsRoute, path: "backup/schedule", component: () => (<SuspenseRoute><BackupSchedulePage /></SuspenseRoute>) });
const settings_backup_restoreRoute = createRoute({ getParentRoute: () => app_settingsRoute, path: "backup/restore", component: () => (<SuspenseRoute><BackupRestorePage /></SuspenseRoute>) });
const settings_integrationsRoute = createRoute({ getParentRoute: () => app_settingsRoute, path: "integrations", component: () => (<SuspenseRoute><IntegrationsPage /></SuspenseRoute>) });
const settings_integrations_routes_newRoute = createRoute({ getParentRoute: () => app_settingsRoute, path: "integrations/routes/new", component: () => (<SuspenseRoute><RoutingRuleFormPage /></SuspenseRoute>) });
const settings_integrations_routes_editRoute = createRoute({ getParentRoute: () => app_settingsRoute, path: "integrations/routes/$routeIndex/edit", component: () => (<SuspenseRoute><RoutingRuleFormPage /></SuspenseRoute>) });
const settings_integrations_routing_editRoute = createRoute({ getParentRoute: () => app_settingsRoute, path: "integrations/routing/edit", component: () => (<SuspenseRoute><RoutingConfigFormPage /></SuspenseRoute>) });
const settings_integrations_smtp_editRoute = createRoute({ getParentRoute: () => app_settingsRoute, path: "integrations/smtp/edit", component: () => (<SuspenseRoute><SmtpSettingsFormPage /></SuspenseRoute>) });
const settings_integrations_receivers_newRoute = createRoute({ getParentRoute: () => app_settingsRoute, path: "integrations/receivers/new", component: () => (<SuspenseRoute><ReceiverFormPage /></SuspenseRoute>) });
const settings_integrations_receivers_idRoute = createRoute({ getParentRoute: () => app_settingsRoute, path: "integrations/receivers/$id", component: () => (<SuspenseRoute><ReceiverFormPage /></SuspenseRoute>) });
const settings_connectorsRoute = createRoute({ getParentRoute: () => app_settingsRoute, path: "connectors", component: () => (<SuspenseRoute><ConnectorCoveragePage /></SuspenseRoute>) });
const settings_connectors_newRoute = createRoute({ getParentRoute: () => app_settingsRoute, path: "connectors/new", component: () => (<SuspenseRoute><ConnectorFormPage /></SuspenseRoute>) });
const settings_connectors_scan_newRoute = createRoute({ getParentRoute: () => app_settingsRoute, path: "connectors/scan/new", component: () => (<SuspenseRoute><QueueScanPage /></SuspenseRoute>) });
const settings_connectors_idRoute = createRoute({ getParentRoute: () => app_settingsRoute, path: "connectors/$id", component: () => (<SuspenseRoute><ConnectorFormPage /></SuspenseRoute>) });
const settings_migrationRoute = createRoute({ getParentRoute: () => app_settingsRoute, path: "migration", component: () => (<SuspenseRoute><MigrationPage /></SuspenseRoute>) });
const settings_vulndbRoute = createRoute({ getParentRoute: () => app_settingsRoute, path: "vulndb", beforeLoad: aliasRedirect({ to: "/settings/scanner" }) });

export const routeTree = rootRoute.addChildren([
public__loginRoute,
public__auth_loginRoute,
authenticatedRoute.addChildren([
  app_indexRoute,
  app_dashboardRoute,
  app_findings_splatRoute,
  app_nodes_splatRoute,
  app_hosts_splatRoute,
  app_containersRoute,
  app_images_splatRoute,
  app_serverless_splatRoute,
  app_repositoriesRoute,
  app_assets_splatRoute,
  app_deployments_splatRoute,
  app_services_splatRoute,
  app_workloads_splatRoute,
  app_complianceRoute,
  app_registries_splatRoute,
  app_registry_splatRoute,
  app_exceptions_splatRoute,
  app_runtime_splatRoute,
  app_responseRoute,
  app_response_rules_splatRoute,
  app_vuln_profilesRoute,
  app_vulnerability_profilesRoute,
  app_groups_splatRoute,
  app_file_monitor_splatRoute,
  app_timelineRoute,
  app_eventsRoute,
  app_activityRoute,
  app_incidentsRoute,
  app_security_eventsRoute,
  app_networkRoute,
  app_network_activityRoute,
  app_network_rules_splatRoute,
  app_neuvectorRoute,
  app_waf_splatRoute,
  app_dlp_splatRoute,
  app_runtime_policies_splatRoute,
  app_runtime_dlp_splatRoute,
  app_runtime_signatures_splatRoute,
  app_admission_splatRoute,
  app_admission_control_splatRoute,
  app_policyRoute,
  app_policies_splatRoute,
  app_auditRoute,
  app_audit_logRoute,
  app_componentsRoute,
  app_controllersRoute,
  app_enforcersRoute,
  app_agentsRoute,
  app_scannersRoute,
  app_risk_splatRoute,
  app_healthRoute,
  app_clustersRoute,
  app_clusters_idRoute.addChildren([
  cluster_indexRoute,
  cluster_dashboardRoute,
  cluster_neuvectorRoute,
  cluster_findingsRoute,
  cluster_network_actionRoute,
  cluster_findings_savedViewRoute,
  cluster_timeline_savedViewRoute,
  cluster_network_savedViewRoute,
  cluster_network_importViewsRoute,
  cluster_network_pcap_newRoute,
  cluster_asset_acceptance_newRoute,
  cluster_asset_acceptance_revokeRoute,
  cluster_deployment_actionRoute,
  cluster_findings_fidRoute,
  cluster_finding_acceptRoute,
  cluster_finding_suppressRoute,
  cluster_finding_commentRoute,
  cluster_cve_cveIdRoute,
  cluster_nodesRoute,
  cluster_hosts_splatRoute,
  cluster_containersRoute,
  cluster_nodes_nodeNameRoute,
  cluster_imagesRoute,
  cluster_images_resultIdRoute,
  cluster_serverlessRoute,
  cluster_serverless_functionIdRoute,
  cluster_repositoriesRoute,
  cluster_assetsRoute,
  cluster_assets_aidRoute,
  cluster_deploymentsRoute,
  cluster_services_splatRoute,
  cluster_workloads_splatRoute,
  cluster_deployments_didRoute,
  cluster_complianceRoute,
  cluster_registriesRoute,
  cluster_registries_newRoute,
  cluster_registries_editRoute,
  cluster_registry_splatRoute,
  cluster_registries_regIdRoute,
  cluster_exceptionsRoute,
  cluster_runtimeRoute,
  cluster_runtime_baselinesRoute,
  cluster_runtime_baselines_baselineIdRoute,
  cluster_runtime_baseline_rule_newRoute,
  cluster_runtime_baseline_rule_editRoute,
  cluster_runtime_baseline_actionRoute,
  cluster_responseRoute,
  cluster_response_rulesRoute,
  cluster_response_rules_newRoute,
  cluster_response_rules_ruleIdRoute,
  cluster_vuln_profilesRoute,
  cluster_vulnerability_profilesRoute,
  cluster_vuln_profile_newRoute,
  cluster_vuln_profile_editRoute,
  cluster_response_catalog_editRoute,
  cluster_compliance_exemption_newRoute,
  cluster_compliance_schedule_newRoute,
  cluster_groupsRoute,
  cluster_groups_settingsRoute,
  cluster_groups_newRoute,
  cluster_groups_editRoute,
  cluster_dlp_scope_newRoute,
  cluster_waf_scope_newRoute,
  cluster_groups_groupIdRoute,
  cluster_file_monitorRoute,
  cluster_file_monitor_newRoute,
  cluster_file_monitor_ruleIdRoute,
  cluster_timelineRoute,
  cluster_eventsRoute,
  cluster_activityRoute,
  cluster_incidentsRoute,
  cluster_security_eventsRoute,
  cluster_networkRoute,
  cluster_network_activityRoute,
  cluster_network_rulesRoute,
  cluster_network_rules_newRoute,
  cluster_network_rules_editRoute,
  cluster_waf_splatRoute,
  cluster_dlp_splatRoute,
  cluster_runtime_policiesRoute,
  cluster_runtime_policies_newRoute,
  cluster_runtime_policies_policyIdRoute,
  cluster_runtime_dlpRoute,
  cluster_runtime_dlp_newRoute,
  cluster_runtime_dlp_ruleIdRoute,
  cluster_runtime_signaturesRoute,
  cluster_runtime_signatures_newRoute,
  cluster_runtime_signatures_sigIdRoute,
  cluster_admissionRoute,
  cluster_admission_control_splatRoute,
  cluster_admission_newRoute,
  cluster_admission_settingsRoute,
  cluster_admission_importRoute,
  cluster_policyRoute,
  cluster_policiesRoute,
  cluster_policies_newRoute,
  cluster_policies_policyIdRoute,
  cluster_auditRoute,
  cluster_audit_logRoute,
  cluster_componentsRoute,
  cluster_controllersRoute,
  cluster_enforcersRoute,
  cluster_agentsRoute,
  cluster_scannersRoute,
  cluster_vulndbRoute,
  cluster_cve_sourcesRoute,
  cluster_notificationsRoute,
  cluster_system_configRoute,
  cluster_sysconfigRoute,
  cluster_risk_entityType_entityIdRoute,
  cluster_healthRoute,
  cluster_system_healthRoute,
  cluster_settingsRoute,
  cluster_tokens_splatRoute,
  cluster_attestation_trust_splatRoute
]),
  app_cveRoute,
  app_cve_idRoute,
  app_federationRoute,
  app_federation_newRoute,
  app_postureRoute,
  app_coverageRoute,
  app_system_healthRoute,
  app_access_control_splatRoute,
  app_system_configRoute,
  app_sysconfigRoute,
  app_vulndbRoute,
  app_cve_sourcesRoute,
  app_notificationsRoute,
  app_integrations_splatRoute,
  app_tokens_splatRoute,
  app_attestation_trust_splatRoute,
  app_attestation_splatRoute,
  app_settingsRoute.addChildren([
  settings_indexRoute,
  settings_system_healthRoute,
  settings_tokens_splatRoute,
  settings_attestation_splatRoute,
  settings_access_control_splatRoute,
  settings_notifications_splatRoute,
  settings_clusters_newRoute,
  settings_cluster_bundle_rotateRoute,
  settings_accessRoute,
  settings_access_bindings_newRoute,
  settings_access_service_accounts_newRoute,
  settings_access_users_newRoute,
  settings_access_roles_newRoute,
  settings_access_sso_newRoute,
  settings_access_sso_idRoute,
  settings_api_tokensRoute,
  settings_api_tokens_newRoute,
  settings_security_policyRoute,
  settings_attestation_trustRoute,
  settings_attestation_trust_newRoute,
  settings_attestation_trust_idRoute,
  settings_healthRoute,
  settings_scannerRoute,
  settings_scanner_nvdRoute,
  settings_networkRoute,
  settings_effective_configRoute,
  settings_retentionRoute,
  settings_backupRoute,
  settings_backup_destinationRoute,
  settings_backup_scheduleRoute,
  settings_backup_restoreRoute,
  settings_integrationsRoute,
  settings_integrations_routes_newRoute,
  settings_integrations_routes_editRoute,
  settings_integrations_routing_editRoute,
  settings_integrations_smtp_editRoute,

  settings_integrations_receivers_newRoute,
  settings_integrations_receivers_idRoute,
  settings_connectorsRoute,
  settings_connectors_newRoute,
  settings_connectors_scan_newRoute,
  settings_connectors_idRoute,
  settings_migrationRoute,
  settings_vulndbRoute
])
])
]);

export function createAppRouter(history?: RouterHistory) {
  return createRouter({ routeTree, history, parseSearch: parseURLSearch, stringifySearch: stringifyURLSearch, defaultPreload: false, scrollRestoration: true });
}

export const router = createAppRouter();
declare module "@tanstack/react-router" { interface Register { router: typeof router } }
