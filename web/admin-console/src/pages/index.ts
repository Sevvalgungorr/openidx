import { lazy } from 'react'

// This file exports all page components for the admin console

// Core Pages
export const Dashboard = lazy(() => import('./dashboard').then((m) => ({ default: m.DashboardPage })))
export const Users = lazy(() => import('./users').then((m) => ({ default: m.UsersPage })))
export const AccessReviews = lazy(() => import('./access-reviews').then((m) => ({ default: m.AccessReviewsPage })))
export const Policies = lazy(() => import('./policies').then((m) => ({ default: m.PoliciesPage })))
export const AuditLogs = lazy(() => import('./audit-logs').then((m) => ({ default: m.AuditLogsPage })))
export const Settings = lazy(() => import('./settings').then((m) => ({ default: m.SettingsPage })))

// Identity & Access
export const Groups = lazy(() => import('./groups').then((m) => ({ default: m.GroupsPage })))
export const Roles = lazy(() => import('./roles').then((m) => ({ default: m.RolesPage })))
export const Directories = lazy(() => import('./directories').then((m) => ({ default: m.DirectoriesPage })))
export const ServiceAccounts = lazy(() => import('./service-accounts').then((m) => ({ default: m.ServiceAccountsPage })))
export const IdentityProviders = lazy(() => import('./identity-providers').then((m) => ({ default: m.IdentityProvidersPage })))

// Applications
export const Applications = lazy(() => import('./applications').then((m) => ({ default: m.ApplicationsPage })))
export const AppLauncher = lazy(() => import('./app-launcher').then((m) => ({ default: m.AppLauncherPage })))
export const QuickLinks = lazy(() => import('./quick-links').then((m) => ({ default: m.QuickLinksPage })))
export const QuickLinksAdmin = lazy(() => import('./quick-links-admin').then((m) => ({ default: m.QuickLinksAdminPage })))
export const AppPublish = lazy(() => import('./app-publish').then((m) => ({ default: m.AppPublishPage })))
export const ZeroTrust = lazy(() => import('./zero-trust').then((m) => ({ default: m.ZeroTrustPage })))
export const ProvisioningRules = lazy(() => import('./provisioning-rules').then((m) => ({ default: m.ProvisioningRulesPage })))
export const LifecycleWorkflows = lazy(() => import('./lifecycle-workflows').then((m) => ({ default: m.LifecycleWorkflowsPage })))
export const FederationConfig = lazy(() => import('./federation-config').then((m) => ({ default: m.FederationConfigPage })))
export const SocialProviders = lazy(() => import('./social-providers').then((m) => ({ default: m.SocialProvidersPage })))

// Network & Access
export const ProxyRoutes = lazy(() => import('./proxy-routes').then((m) => ({ default: m.ProxyRoutesPage })))
export const ZitiSetup = lazy(() => import('./ziti-setup').then((m) => ({ default: m.ZitiSetupPage })))
export const ZitiNetwork = lazy(() => import('./ziti-network').then((m) => ({ default: m.ZitiNetworkPage })))
export const NetworkTopology = lazy(() => import('./network-topology').then((m) => ({ default: m.NetworkTopologyPage })))
export const OpsCockpit = lazy(() => import('./ops-cockpit').then((m) => ({ default: m.OpsCockpitPage })))
export const ZitiDiscovery = lazy(() => import('./ziti-discovery').then((m) => ({ default: m.ZitiDiscoveryPage })))
export const ZitiAIInsights = lazy(() => import('./ziti-ai-insights').then((m) => ({ default: m.ZitiAIInsightsPage })))
export const BrowzerManagement = lazy(() => import('./browzer-management').then((m) => ({ default: m.BrowZerManagementPage })))
export const Certificates = lazy(() => import('./certificates').then((m) => ({ default: m.CertificatesPage })))
export const Devices = lazy(() => import('./devices').then((m) => ({ default: m.DevicesPage })))
export const AgentFleet = lazy(() => import('./agent-fleet').then((m) => ({ default: m.AgentFleetPage })))
export const KioskPolicies = lazy(() => import('./kiosk-policies').then((m) => ({ default: m.KioskPoliciesPage })))
export const RemoteSupport = lazy(() => import('./remote-support').then((m) => ({ default: m.RemoteSupportPage })))
export const RemoteSupportPopout = lazy(() => import('./remote-support-popout').then((m) => ({ default: m.RemoteSupportPopout })))

// Governance
export const ApprovalPolicies = lazy(() => import('./approval-policies').then((m) => ({ default: m.ApprovalPoliciesPage })))
export const CertificationCampaigns = lazy(() => import('./certification-campaigns').then((m) => ({ default: m.CertificationCampaignsPage })))
export const Entitlements = lazy(() => import('./entitlements').then((m) => ({ default: m.EntitlementsPage })))
export const ABACPolicies = lazy(() => import('./abac-policies').then((m) => ({ default: m.ABACPoliciesPage })))
export const SessionsAdmin = lazy(() => import('./sessions-admin').then((m) => ({ default: m.SessionsAdminPage })))
export const SecurityAlerts = lazy(() => import('./security-alerts').then((m) => ({ default: m.SecurityAlertsPage })))
export const PrivacyDashboard = lazy(() => import('./privacy-dashboard').then((m) => ({ default: m.PrivacyDashboardPage })))
export const ConsentManagement = lazy(() => import('./consent-management').then((m) => ({ default: m.ConsentManagementPage })))

// Security & MFA
export const MFAManagement = lazy(() => import('./mfa-management'))
export const RiskPolicies = lazy(() => import('./risk-policies').then((m) => ({ default: m.RiskPoliciesPage })))
export const LoginAnomalies = lazy(() => import('./login-anomalies'))
export const HardwareTokens = lazy(() => import('./hardware-tokens').then((m) => ({ default: m.HardwareTokensPage })))
export const DeviceTrustApproval = lazy(() => import('./device-trust-approval').then((m) => ({ default: m.DeviceTrustApprovalPage })))
export const MFABypassCodes = lazy(() => import('./mfa-bypass-codes').then((m) => ({ default: m.MFABypassCodesPage })))
export const PasswordlessSettings = lazy(() => import('./passwordless-settings').then((m) => ({ default: m.PasswordlessSettingsPage })))
export const SecurityKeys = lazy(() => import('./security-keys').then((m) => ({ default: m.SecurityKeysPage })))
export const PushDevices = lazy(() => import('./push-devices').then((m) => ({ default: m.PushDevicesPage })))

// Audit & Reports
export const AuditDashboard = lazy(() => import('./audit').then((m) => ({ default: m.AuditDashboard })))
export const UnifiedAudit = lazy(() => import('./unified-audit').then((m) => ({ default: m.UnifiedAuditPage })))
export const AdminAuditLog = lazy(() => import('./admin-audit-log').then((m) => ({ default: m.AdminAuditLogPage })))
export const LoginAnalytics = lazy(() => import('./login-analytics').then((m) => ({ default: m.LoginAnalyticsPage })))
export const AuthAnalytics = lazy(() => import('./auth-analytics').then((m) => ({ default: m.AuthAnalyticsPage })))
export const UsageAnalytics = lazy(() => import('./usage-analytics').then((m) => ({ default: m.UsageAnalyticsPage })))
export const RiskDashboard = lazy(() => import('./risk-dashboard').then((m) => ({ default: m.RiskDashboardPage })))
export const ComplianceReports = lazy(() => import('./compliance-reports').then((m) => ({ default: m.ComplianceReportsPage })))
export const ComplianceDashboard = lazy(() => import('./compliance-dashboard').then((m) => ({ default: m.ComplianceDashboardPage })))
export const Reports = lazy(() => import('./reports').then((m) => ({ default: m.ReportsPage })))

// AI & Intelligence
export const AIAgents = lazy(() => import('./ai-agents').then((m) => ({ default: m.AIAgentsPage })))
export const ISPMDashboard = lazy(() => import('./ispm-dashboard').then((m) => ({ default: m.ISPMDashboardPage })))
export const AIRecommendations = lazy(() => import('./ai-recommendations').then((m) => ({ default: m.AIRecommendationsPage })))
export const PredictiveAnalytics = lazy(() => import('./predictive-analytics').then((m) => ({ default: m.PredictiveAnalyticsPage })))

// Enterprise
export const SAMLServiceProviders = lazy(() => import('./saml-service-providers').then((m) => ({ default: m.SAMLServiceProvidersPage })))
export const BulkOperations = lazy(() => import('./bulk-operations').then((m) => ({ default: m.BulkOperationsPage })))
export const EmailTemplates = lazy(() => import('./email-templates').then((m) => ({ default: m.EmailTemplatesPage })))
export const LifecyclePolicies = lazy(() => import('./lifecycle-policies').then((m) => ({ default: m.LifecyclePoliciesPage })))
export const AttestationCampaigns = lazy(() => import('./attestation-campaigns').then((m) => ({ default: m.AttestationCampaignsPage })))
export const AuditArchival = lazy(() => import('./audit-archival').then((m) => ({ default: m.AuditArchivalPage })))
export const VaultSecrets = lazy(() => import('./vault-secrets').then((m) => ({ default: m.VaultSecretsPage })))
export const RotationPolicies = lazy(() => import('./rotation-policies').then((m) => ({ default: m.RotationPoliciesPage })))
export const GuacamoleSessions = lazy(() => import('./guacamole-sessions').then((m) => ({ default: m.GuacamoleSessionsPage })))
export const PAMDashboard = lazy(() => import('./pam-dashboard').then((m) => ({ default: m.PAMDashboardPage })))
export const PamConnections = lazy(() => import('./pam-connections').then((m) => ({ default: m.PamConnectionsPage })))
export const WindowsApps = lazy(() => import('./windows-apps').then((m) => ({ default: m.WindowsAppsPage })))
export const MyWindowsApps = lazy(() => import('./my-windows-apps').then((m) => ({ default: m.MyWindowsAppsPage })))

// Developer
export const APIExplorer = lazy(() => import('./api-explorer').then((m) => ({ default: m.ApiExplorerPage })))
export const OAuthPlayground = lazy(() => import('./oauth-playground').then((m) => ({ default: m.OAuthPlaygroundPage })))
export const DeveloperSettings = lazy(() => import('./developer-settings').then((m) => ({ default: m.DeveloperSettingsPage })))
export const ErrorCatalog = lazy(() => import('./error-catalog').then((m) => ({ default: m.ErrorCatalogPage })))
export const APIDocs = lazy(() => import('./api-docs').then((m) => ({ default: m.ApiDocsPage })))

// System
export const SystemHealth = lazy(() => import('./system-health').then((m) => ({ default: m.SystemHealthPage })))
export const Organizations = lazy(() => import('./organizations').then((m) => ({ default: m.OrganizationsPage })))
export const Branding = lazy(() => import('./branding').then((m) => ({ default: m.BrandingPage })))
export const Delegations = lazy(() => import('./delegations').then((m) => ({ default: m.DelegationsPage })))
export const Webhooks = lazy(() => import('./webhooks').then((m) => ({ default: m.WebhooksPage })))
export const TenantManagement = lazy(() => import('./tenant-management').then((m) => ({ default: m.TenantManagementPage })))
export const NotificationAdmin = lazy(() => import('./notification-admin').then((m) => ({ default: m.NotificationAdminPage })))

// User-facing pages
export const Login = lazy(() => import('./login').then((m) => ({ default: m.LoginPage })))
export const Landing = lazy(() => import('./landing').then((m) => ({ default: m.LandingPage })))
export const ForgotPassword = lazy(() => import('./forgot-password').then((m) => ({ default: m.ForgotPasswordPage })))
export const ResetPassword = lazy(() => import('./reset-password').then((m) => ({ default: m.ResetPasswordPage })))
export const MagicLinkVerify = lazy(() => import('./magic-link-verify').then((m) => ({ default: m.MagicLinkVerifyPage })))

// My Pages
export const UserProfile = lazy(() => import('./user-profile').then((m) => ({ default: m.UserProfilePage })))
export const MyAccess = lazy(() => import('./my-access').then((m) => ({ default: m.MyAccessPage })))
export const MyPrivilegedAccess = lazy(() => import('./my-privileged-access').then((m) => ({ default: m.MyPrivilegedAccessPage })))
export const MyDevices = lazy(() => import('./my-devices').then((m) => ({ default: m.MyDevicesPage })))
export const AddDevice = lazy(() => import('./add-device').then((m) => ({ default: m.AddDevicePage })))
export const MyNetwork = lazy(() => import('./my-network').then((m) => ({ default: m.MyNetworkPage })))
export const MySecurity = lazy(() => import('./my-security').then((m) => ({ default: m.MySecurityPage })))
export const AIIdentityIntelligence = lazy(() => import('./ai-identity-intelligence').then((m) => ({ default: m.AIIdentityIntelligencePage })))
export const TrustedBrowsers = lazy(() => import('./trusted-browsers').then((m) => ({ default: m.TrustedBrowsersPage })))
export const DeviceAuthorization = lazy(() => import('./device-authorization').then((m) => ({ default: m.DeviceAuthorizationPage })))
export const AccessRequests = lazy(() => import('./access-requests').then((m) => ({ default: m.AccessRequestsPage })))
export const NotificationCenter = lazy(() => import('./notification-center').then((m) => ({ default: m.NotificationCenterPage })))
export const NotificationPreferences = lazy(() => import('./notification-preferences').then((m) => ({ default: m.NotificationPreferencesPage })))

// Other pages
export const ReviewDetail = lazy(() => import('./review-detail').then((m) => ({ default: m.ReviewDetailPage })))
export const UserAccess360 = lazy(() => import('./user-access-360').then((m) => ({ default: m.UserAccess360Page })))
