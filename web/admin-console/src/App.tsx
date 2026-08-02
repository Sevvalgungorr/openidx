import { useEffect, Suspense } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { Layout } from '@/components/layout'
import { LoadingSpinner } from '@/components/ui/loading-spinner'
import {
  Dashboard,
  Users,
  Groups,
  Roles,
  Directories,
  ServiceAccounts,
  AccessReviews,
  Policies,
  ApprovalPolicies,
  CertificationCampaigns,
  Entitlements,
  ABACPolicies,
  SessionsAdmin,
  SecurityAlerts,
  PrivacyDashboard,
  ConsentManagement,
  AuditLogs,
  AuditDashboard,
  UnifiedAudit,
  AdminAuditLog,
  LoginAnalytics,
  AuthAnalytics,
  UsageAnalytics,
  RiskDashboard,
  ComplianceReports,
  ComplianceDashboard,
  Reports,
  Settings,
  Applications,
  AppLauncher,
  QuickLinks,
  QuickLinksAdmin,
  AppPublish,
  ZeroTrust,
  IdentityProviders,
  ProvisioningRules,
  LifecycleWorkflows,
  FederationConfig,
  SocialProviders,
  ProxyRoutes,
  ZitiSetup,
  ZitiNetwork,
  ZitiDiscovery,
  ZitiAIInsights,
  BrowzerManagement,
  Certificates,
  Devices,
  AgentFleet,
  KioskPolicies,
  RemoteSupport,
  RemoteSupportPopout,
  MFAManagement,
  RiskPolicies,
  LoginAnomalies,
  HardwareTokens,
  DeviceTrustApproval,
  MFABypassCodes,
  PasswordlessSettings,
  SecurityKeys,
  PushDevices,
  AIAgents,
  ISPMDashboard,
  AIRecommendations,
  AIIdentityIntelligence,
  MySecurity,
  PredictiveAnalytics,
  SAMLServiceProviders,
  BulkOperations,
  EmailTemplates,
  LifecyclePolicies,
  AttestationCampaigns,
  AuditArchival,
  VaultSecrets,
  APIExplorer,
  OAuthPlayground,
  DeveloperSettings,
  ErrorCatalog,
  APIDocs,
  SystemHealth,
  Organizations,
  Branding,
  Delegations,
  Webhooks,
  TenantManagement,
  NotificationAdmin,
  Login,
  Landing,
  ForgotPassword,
  ResetPassword,
  MagicLinkVerify,
  UserProfile,
  MyAccess,
  MyDevices,
  TrustedBrowsers,
  DeviceAuthorization,
  AccessRequests,
  NotificationCenter,
  NotificationPreferences,
  ReviewDetail,
  UserAccess360,
  RotationPolicies,
  GuacamoleSessions,
  PAMDashboard,
  PamConnections,
  WindowsApps,
  MyWindowsApps,
  MyPrivilegedAccess,
} from '@/pages'
import { useAppStore } from '@/lib/store'
import { useAuth } from '@/lib/auth'

// ProtectedRoute wrapper component that checks authentication before rendering
// This prevents admin URLs from being accessible without proper authentication
interface ProtectedRouteProps {
  children: React.ReactNode
}

function ProtectedRoute({ children }: ProtectedRouteProps) {
  const { isAuthenticated, isLoading } = useAuth()

  // Show loading state while checking authentication
  if (isLoading) {
    return (
      <div className="flex h-screen items-center justify-center bg-gray-50">
        <div className="text-center">
          <div className="h-12 w-12 animate-spin rounded-full border-4 border-blue-600 border-t-transparent mx-auto" />
          <p className="mt-4 text-gray-600">Verifying authentication...</p>
        </div>
      </div>
    )
  }

  // Redirect to login if not authenticated
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />
  }

  return <>{children}</>
}

// AdminRoute wrapper for pages that must never render for non-admins.
// The backend still enforces authorization (403) — this guard just keeps
// admin-only consoles from mounting client-side for regular users.
function AdminRoute({ children }: ProtectedRouteProps) {
  const { hasRole } = useAuth()

  if (!hasRole('admin')) {
    return <Navigate to="/dashboard" replace />
  }

  return <>{children}</>
}

function App() {
  const { theme } = useAppStore()
  const { isAuthenticated, isLoading } = useAuth()

  // Apply theme
  useEffect(() => {
    const root = document.documentElement
    const isDark =
      theme === 'dark' ||
      (theme === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches)

    root.classList.toggle('dark', isDark)
  }, [theme])

  // Loading state
  if (isLoading) {
    return (
      <div className="flex h-screen items-center justify-center bg-gray-50">
        <div className="text-center">
          <div className="h-12 w-12 animate-spin rounded-full border-4 border-blue-600 border-t-transparent mx-auto" />
          <p className="mt-4 text-gray-600">Loading...</p>
        </div>
      </div>
    )
  }

  return (
    <Suspense
      fallback={
        <div className="flex h-screen items-center justify-center">
          <LoadingSpinner size="lg" />
        </div>
      }
    >
      <Routes>
        {/* Public routes */}
      <Route path="/login" element={<Login />} />
      <Route path="/landing" element={<Landing />} />
      <Route path="/forgot-password" element={<ForgotPassword />} />
      <Route path="/reset-password" element={<ResetPassword />} />
      <Route path="/magic-link-verify" element={<MagicLinkVerify />} />

      {/* Standalone pop-out viewer: protected but chrome-less (no sidebar), so
          a relay session can live in its own window / second monitor. */}
      <Route
        path="/remote-support/live"
        element={
          <ProtectedRoute>
            <RemoteSupportPopout />
          </ProtectedRoute>
        }
      />

      {/* Protected routes with auth guard */}
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <Layout />
          </ProtectedRoute>
        }
      >
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={<Dashboard />} />

        {/* My Pages (user-facing) */}
        <Route path="profile" element={<UserProfile />} />
        <Route path="app-launcher" element={<AppLauncher />} />
        <Route path="quick-links" element={<QuickLinks />} />
        <Route path="quick-links-admin" element={<AdminRoute><QuickLinksAdmin /></AdminRoute>} />
        <Route path="my-access" element={<MyAccess />} />
        <Route path="my-privileged-access" element={<MyPrivilegedAccess />} />
        <Route path="my-devices" element={<MyDevices />} />
        <Route path="my-security" element={<MySecurity />} />
        <Route path="trusted-browsers" element={<TrustedBrowsers />} />
        {/* RFC 8628 verification page. The path must stay "/device": it is what
            deviceVerificationURI prints on the device's screen, and a user
            reading it off a television cannot correct a mismatch. */}
        <Route path="device" element={<DeviceAuthorization />} />
        <Route path="access-requests" element={<AccessRequests />} />
        <Route path="notification-center" element={<NotificationCenter />} />

        {/* Identity Management - Admin Protected */}
        <Route path="users" element={<Users />} />
        <Route path="groups" element={<Groups />} />
        <Route path="roles" element={<Roles />} />
        <Route path="directories" element={<Directories />} />
        <Route path="service-accounts" element={<ServiceAccounts />} />

        {/* Applications - Admin Protected */}
        <Route path="applications" element={<Applications />} />
        <Route path="identity-providers" element={<IdentityProviders />} />
        <Route path="provisioning-rules" element={<ProvisioningRules />} />
        <Route path="lifecycle-workflows" element={<LifecycleWorkflows />} />
        <Route path="social-providers" element={<SocialProviders />} />
        <Route path="federation-config" element={<FederationConfig />} />

        {/* Network & Access - Admin Protected */}
        <Route path="zero-trust" element={<ZeroTrust />} />
        <Route path="proxy-routes" element={<ProxyRoutes />} />
        <Route path="ziti-setup" element={<ZitiSetup />} />
        <Route path="ziti-network" element={<ZitiNetwork />} />
        <Route path="ziti-discovery" element={<ZitiDiscovery />} />
        <Route path="ziti-ai-insights" element={<ZitiAIInsights />} />
        <Route path="browzer-management" element={<BrowzerManagement />} />
        <Route path="app-publish" element={<AppPublish />} />
        <Route path="certificates" element={<Certificates />} />
        <Route path="devices" element={<Devices />} />
        <Route path="agent-fleet" element={<AgentFleet />} />
        <Route path="kiosk-policies" element={<KioskPolicies />} />
        <Route path="remote-support" element={<RemoteSupport />} />

        {/* Governance - Admin Protected */}
        <Route path="policies" element={<Policies />} />
        <Route path="approval-policies" element={<ApprovalPolicies />} />
        <Route path="access-reviews" element={<AccessReviews />} />
        <Route path="certification-campaigns" element={<CertificationCampaigns />} />
        <Route path="entitlements" element={<Entitlements />} />
        <Route path="abac-policies" element={<ABACPolicies />} />
        <Route path="sessions" element={<SessionsAdmin />} />
        <Route path="security-alerts" element={<SecurityAlerts />} />
        <Route path="privacy-dashboard" element={<PrivacyDashboard />} />
        <Route path="consent-management" element={<ConsentManagement />} />

        {/* Security & MFA - Admin Protected */}
        <Route path="mfa-management" element={<MFAManagement />} />
        <Route path="risk-policies" element={<RiskPolicies />} />
        <Route path="login-anomalies" element={<LoginAnomalies />} />
        <Route path="hardware-tokens" element={<HardwareTokens />} />
        <Route path="device-trust-approval" element={<DeviceTrustApproval />} />
        <Route path="mfa-bypass-codes" element={<MFABypassCodes />} />
        <Route path="passwordless-settings" element={<PasswordlessSettings />} />
        <Route path="security-keys" element={<SecurityKeys />} />
        <Route path="push-devices" element={<PushDevices />} />

        {/* Audit & Reports - Admin Protected */}
        <Route path="audit-logs" element={<AuditLogs />} />
        <Route path="audit/dashboard" element={<AuditDashboard />} />
        <Route path="unified-audit" element={<UnifiedAudit />} />
        <Route path="admin-audit-log" element={<AdminAuditLog />} />
        <Route path="login-analytics" element={<LoginAnalytics />} />
        <Route path="auth-analytics" element={<AuthAnalytics />} />
        <Route path="usage-analytics" element={<UsageAnalytics />} />
        <Route path="risk-dashboard" element={<RiskDashboard />} />
        <Route path="compliance-reports" element={<ComplianceReports />} />
        <Route path="compliance-dashboard" element={<ComplianceDashboard />} />
        <Route path="reports" element={<Reports />} />

        {/* AI & Intelligence - Admin Protected */}
        <Route path="ai-agents" element={<AIAgents />} />
        <Route path="ispm" element={<ISPMDashboard />} />
        <Route path="ai-recommendations" element={<AIRecommendations />} />
        <Route path="ai-intelligence" element={<AIIdentityIntelligence />} />
        <Route path="predictive-analytics" element={<PredictiveAnalytics />} />

        {/* Enterprise - Admin Protected */}
        <Route path="saml-service-providers" element={<SAMLServiceProviders />} />
        <Route path="bulk-operations" element={<BulkOperations />} />
        <Route path="email-templates" element={<EmailTemplates />} />
        <Route path="lifecycle-policies" element={<LifecyclePolicies />} />
        <Route path="attestation-campaigns" element={<AttestationCampaigns />} />
        <Route path="audit-archival" element={<AuditArchival />} />

        {/* Privileged Access - Admin Protected */}
        <Route path="pam-dashboard" element={<AdminRoute><PAMDashboard /></AdminRoute>} />
        <Route path="pam-connections" element={<PamConnections />} />
        <Route path="windows-apps" element={<WindowsApps />} />
        <Route path="my-apps" element={<MyWindowsApps />} />
        <Route path="vault-secrets" element={<AdminRoute><VaultSecrets /></AdminRoute>} />
        <Route path="rotation-policies" element={<AdminRoute><RotationPolicies /></AdminRoute>} />
        <Route path="guacamole-sessions" element={<AdminRoute><GuacamoleSessions /></AdminRoute>} />

        {/* Developer - Admin Protected */}
        <Route path="api-explorer" element={<APIExplorer />} />
        <Route path="oauth-playground" element={<OAuthPlayground />} />
        <Route path="developer-settings" element={<DeveloperSettings />} />
        <Route path="error-catalog" element={<ErrorCatalog />} />
        <Route path="api-docs" element={<APIDocs />} />

        {/* System - Admin Protected */}
        <Route path="system-health" element={<SystemHealth />} />
        <Route path="organizations" element={<Organizations />} />
        <Route path="branding" element={<Branding />} />
        <Route path="delegations" element={<Delegations />} />
        <Route path="webhooks" element={<Webhooks />} />
        <Route path="settings" element={<Settings />} />
        <Route path="tenant-management" element={<TenantManagement />} />
        <Route path="notification-admin" element={<NotificationAdmin />} />

        {/* Additional Routes */}
        <Route path="notification-preferences" element={<NotificationPreferences />} />
        <Route path="reviews/:id" element={<ReviewDetail />} />
        <Route path="users/:id/access-360" element={<AdminRoute><UserAccess360 /></AdminRoute>} />

        {/* Catch all - redirect to dashboard */}
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Route>

      {/* Root redirect */}
      <Route path="*" element={<Navigate to={isAuthenticated ? "/dashboard" : "/login"} replace />} />
    </Routes>
    </Suspense>
  )
}

export default App
