// Single source of truth for the admin-console navigation.
//
// To add a menu item: add one entry to the right section below (and make sure
// App.tsx has a matching <Route>). navigation.test.ts cross-checks every href
// against App.tsx routes, so a typo or a forgotten route fails CI instead of
// shipping an unreachable page.
//
// Visibility is role-driven and mirrors the backend hierarchy
// (internal/auth/roles.go): super_admin > admin > operator > auditor > user.
// compliance_reader unlocks only the audit domain (see lib/roles.ts).
import {
  LayoutDashboard,
  Users,
  Users2,
  AppWindow,
  ClipboardCheck,
  FileText,
  Settings,
  Shield,
  Scale,
  ShieldCheck,
  ClipboardList,
  Key as KeyIcon,
  User,
  Workflow,
  Network,
  FolderSync,
  Smartphone,
  Bell,
  GitPullRequest,
  ShieldAlert,
  Monitor,
  Building2,
  BarChart3,
  Rocket,
  Eye,
  Fingerprint,
  KeyRound,
  ShieldOff,
  Link2,
  Activity,
  Search,
  Layers,
  Globe,
  FileKey,
  Upload,
  BookOpen,
  Target,
  Package,
  Gauge,
  UserCheck,
  Filter,
  Code2,
  Play,
  HeartPulse,
  AlertTriangle,
  ScrollText,
  TrendingUp,
  PieChart,
  Bot,
  Lightbulb,
  Mail,
  UserMinus,
  ClipboardSignature,
  ArchiveRestore,
  FileCheck,
  Send,
  Video,
  Lock,
  RefreshCw,
  MonitorPlay,
  Radio,
  Palette,
  Brain,
  Server,
  Home,
} from 'lucide-react'
import { hasMinRole, type MinRole } from '@/lib/roles'

export type NavIcon = React.ComponentType<{ className?: string }>

// Top-level product domains. IAM, Ziti (zero-trust network) and PAM are the
// three pillars of the platform; audit feeds the reporter persona.
export type NavDomain = 'home' | 'iam' | 'ziti' | 'pam' | 'audit' | 'ai' | 'platform'

// Console lens: admins can narrow the console to the operator ("management")
// or auditor ("reporting") slice; lower roles are capped to their own level.
export type ViewMode = 'admin' | 'management' | 'reporting'

export interface NavItem {
  name: string
  href: string
  icon: NavIcon
  /** Minimum role that should see this entry (hierarchical). */
  minRole: MinRole
  /** Extra terms the sidebar quick-search matches besides the name. */
  keywords?: string[]
}

export interface NavSection {
  /** Sub-heading inside a domain. Empty label = no heading rendered. */
  label: string
  items: NavItem[]
}

export interface NavDomainGroup {
  id: NavDomain
  /** Domain heading. Empty for the personal (home) group. */
  label: string
  icon: NavIcon
  sections: NavSection[]
}

export const navigation: NavDomainGroup[] = [
  {
    id: 'home',
    label: '',
    icon: Home,
    sections: [
      {
        label: '',
        items: [
          { name: 'Dashboard', href: '/dashboard', icon: LayoutDashboard, minRole: 'user', keywords: ['overview', 'home'] },
          { name: 'My Profile', href: '/profile', icon: User, minRole: 'user', keywords: ['account', 'password'] },
          { name: 'My Apps', href: '/app-launcher', icon: Rocket, minRole: 'user', keywords: ['launcher', 'portal'] },
          { name: 'My Windows Apps', href: '/my-apps', icon: AppWindow, minRole: 'user', keywords: ['remoteapp', 'ssms', 'published', 'rds', 'windows', 'launch', 'desktop app'] },
          { name: 'Quick Links', href: '/quick-links', icon: Link2, minRole: 'user', keywords: ['support', 'shortcuts', 'teams', 'zoom', 'launcher', 'connect'] },
          { name: 'My Access', href: '/my-access', icon: Eye, minRole: 'user', keywords: ['entitlements', 'permissions'] },
          { name: 'My Privileged Access', href: '/my-privileged-access', icon: KeyRound, minRole: 'user', keywords: ['pam', 'my secrets', 'checkout', 'privileged'] },
          { name: 'My Devices', href: '/my-devices', icon: Smartphone, minRole: 'user', keywords: ['phone', 'enrollment'] },
          { name: 'My Sessions', href: '/sessions', icon: Monitor, minRole: 'user', keywords: ['active sessions', 'sign out', 'devices', 'logged in'] },
          { name: 'My Security', href: '/my-security', icon: ShieldCheck, minRole: 'user', keywords: ['security score', 'risk', 'insights', 'mfa'] },
          { name: 'Trusted Browsers', href: '/trusted-browsers', icon: Monitor, minRole: 'user', keywords: ['remembered'] },
          { name: 'Access Requests', href: '/access-requests', icon: GitPullRequest, minRole: 'user', keywords: ['request access', 'approvals'] },
          { name: 'Notifications', href: '/notification-center', icon: Bell, minRole: 'user', keywords: ['inbox', 'alerts'] },
        ],
      },
    ],
  },
  {
    id: 'iam',
    label: 'Identity & Access (IAM)',
    icon: Fingerprint,
    sections: [
      {
        label: 'Identity',
        items: [
          { name: 'Users', href: '/users', icon: Users, minRole: 'operator', keywords: ['people', 'accounts', 'iam'] },
          { name: 'Groups', href: '/groups', icon: Users2, minRole: 'operator', keywords: ['teams', 'membership'] },
          { name: 'Roles', href: '/roles', icon: ShieldCheck, minRole: 'admin', keywords: ['rbac', 'permissions'] },
          { name: 'Directories', href: '/directories', icon: FolderSync, minRole: 'admin', keywords: ['ldap', 'active directory', 'sync'] },
          { name: 'Service Accounts', href: '/service-accounts', icon: KeyIcon, minRole: 'admin', keywords: ['machine', 'api accounts'] },
          { name: 'Bulk Operations', href: '/bulk-operations', icon: Layers, minRole: 'operator', keywords: ['import', 'export', 'csv'] },
        ],
      },
      {
        label: 'Applications & Federation',
        items: [
          { name: 'Applications', href: '/applications', icon: AppWindow, minRole: 'admin', keywords: ['oauth', 'clients', 'sso'] },
          { name: 'Identity Providers', href: '/identity-providers', icon: KeyIcon, minRole: 'admin', keywords: ['idp', 'oidc', 'saml'] },
          { name: 'SAML Providers', href: '/saml-service-providers', icon: Fingerprint, minRole: 'admin', keywords: ['saml', 'service provider', 'federation'] },
          { name: 'Social Providers', href: '/social-providers', icon: Globe, minRole: 'admin', keywords: ['google', 'github', 'social login'] },
          { name: 'Federation', href: '/federation-config', icon: Link2, minRole: 'admin', keywords: ['trust', 'external idp'] },
          { name: 'Provisioning Rules', href: '/provisioning-rules', icon: Workflow, minRole: 'admin', keywords: ['scim', 'sync rules'] },
          { name: 'Lifecycle Workflows', href: '/lifecycle-workflows', icon: Workflow, minRole: 'admin', keywords: ['joiner', 'mover', 'leaver', 'onboarding'] },
        ],
      },
      {
        label: 'Governance',
        items: [
          { name: 'Policies', href: '/policies', icon: Scale, minRole: 'operator', keywords: ['opa', 'rules'] },
          { name: 'Approval Policies', href: '/approval-policies', icon: ShieldCheck, minRole: 'admin', keywords: ['workflow', 'approvers'] },
          { name: 'Access Reviews', href: '/access-reviews', icon: ClipboardCheck, minRole: 'operator', keywords: ['recertification', 'review'] },
          { name: 'Cert Campaigns', href: '/certification-campaigns', icon: Target, minRole: 'admin', keywords: ['certification', 'campaign'] },
          { name: 'Attestation', href: '/attestation-campaigns', icon: ClipboardSignature, minRole: 'admin', keywords: ['attest', 'campaign'] },
          { name: 'Entitlements', href: '/entitlements', icon: Package, minRole: 'admin', keywords: ['grants', 'catalog'] },
          { name: 'ABAC Policies', href: '/abac-policies', icon: Filter, minRole: 'admin', keywords: ['attribute', 'context'] },
          { name: 'Lifecycle Policies', href: '/lifecycle-policies', icon: UserMinus, minRole: 'admin', keywords: ['deprovision', 'dormant', 'offboarding'] },
          { name: 'Sessions', href: '/sessions', icon: Monitor, minRole: 'operator', keywords: ['active sessions', 'revoke'] },
          { name: 'Delegations', href: '/delegations', icon: UserCheck, minRole: 'admin', keywords: ['delegate', 'admin rights'] },
          { name: 'Privacy Dashboard', href: '/privacy-dashboard', icon: Shield, minRole: 'admin', keywords: ['gdpr', 'data subject'] },
          { name: 'Consent Mgmt', href: '/consent-management', icon: FileCheck, minRole: 'admin', keywords: ['consent', 'gdpr'] },
        ],
      },
      {
        label: 'Security & MFA',
        items: [
          { name: 'MFA Management', href: '/mfa-management', icon: Shield, minRole: 'operator', keywords: ['totp', 'factors', 'reset mfa'] },
          { name: 'Risk Policies', href: '/risk-policies', icon: Activity, minRole: 'admin', keywords: ['adaptive', 'conditional access'] },
          { name: 'Login Anomalies', href: '/login-anomalies', icon: AlertTriangle, minRole: 'operator', keywords: ['impossible travel', 'suspicious'] },
          { name: 'Security Alerts', href: '/security-alerts', icon: ShieldAlert, minRole: 'operator', keywords: ['incidents', 'threats'] },
          { name: 'Hardware Tokens', href: '/hardware-tokens', icon: KeyRound, minRole: 'operator', keywords: ['yubikey', 'otp'] },
          { name: 'Device Trust Approval', href: '/device-trust-approval', icon: Fingerprint, minRole: 'operator', keywords: ['device approval'] },
          { name: 'MFA Bypass Codes', href: '/mfa-bypass-codes', icon: ShieldOff, minRole: 'admin', keywords: ['recovery', 'backup codes'] },
          { name: 'Passwordless', href: '/passwordless-settings', icon: Link2, minRole: 'admin', keywords: ['magic link', 'webauthn'] },
          { name: 'Security Keys', href: '/security-keys', icon: KeyRound, minRole: 'admin', keywords: ['webauthn', 'fido2', 'passkey'] },
          { name: 'Push Devices', href: '/push-devices', icon: Bell, minRole: 'admin', keywords: ['push mfa', 'mobile'] },
        ],
      },
    ],
  },
  {
    id: 'ziti',
    label: 'Zero Trust Network (Ziti)',
    icon: Network,
    sections: [
      {
        label: 'Network Access',
        items: [
          { name: 'Zero Trust Access', href: '/zero-trust', icon: Shield, minRole: 'admin', keywords: ['ztna', 'ziti', 'services'] },
          { name: 'Proxy Routes', href: '/proxy-routes', icon: Network, minRole: 'admin', keywords: ['reverse proxy', 'gateway', 'vhost'] },
          { name: 'Network Setup', href: '/ziti-setup', icon: Server, minRole: 'admin', keywords: ['ziti setup', 'controller', 'router'] },
          { name: 'Ziti Network', href: '/ziti-network', icon: Globe, minRole: 'admin', keywords: ['openziti', 'identities', 'edge routers'] },
          { name: 'Ziti Discovery', href: '/ziti-discovery', icon: Search, minRole: 'admin', keywords: ['scan', 'discover services'] },
          { name: 'AI Insights', href: '/ziti-ai-insights', icon: Brain, minRole: 'admin', keywords: ['anomaly', 'risk score', 'quarantine', 'ai'] },
          { name: 'BrowZer', href: '/browzer-management', icon: Play, minRole: 'admin', keywords: ['browser access', 'clientless'] },
          { name: 'App Publish', href: '/app-publish', icon: Upload, minRole: 'admin', keywords: ['publish application', 'expose'] },
          { name: 'Certificates', href: '/certificates', icon: FileKey, minRole: 'admin', keywords: ['tls', 'pki', 'ca'] },
        ],
      },
      {
        label: 'Devices & Endpoints',
        items: [
          { name: 'Devices', href: '/devices', icon: Smartphone, minRole: 'operator', keywords: ['endpoints', 'posture'] },
          { name: 'Agent Fleet', href: '/agent-fleet', icon: Radio, minRole: 'operator', keywords: ['agents', 'tunneler', 'fleet'] },
          { name: 'Kiosk Policies', href: '/kiosk-policies', icon: Lock, minRole: 'admin', keywords: ['kiosk', 'shared device'] },
          { name: 'Remote Support', href: '/remote-support', icon: Video, minRole: 'operator', keywords: ['screen share', 'assist'] },
        ],
      },
    ],
  },
  {
    id: 'pam',
    label: 'Privileged Access (PAM)',
    icon: KeyRound,
    sections: [
      {
        label: '',
        items: [
          { name: 'PAM Dashboard', href: '/pam-dashboard', icon: Gauge, minRole: 'admin', keywords: ['pam overview', 'privileged access', 'summary'] },
          { name: 'Connections', href: '/pam-connections', icon: Server, minRole: 'operator', keywords: ['rdm', 'remote desktop manager', 'devolutions', 'rdp', 'ssh', 'vnc', 'connection manager', 'passwordless', 'launch'] },
          { name: 'Windows Apps', href: '/windows-apps', icon: AppWindow, minRole: 'operator', keywords: ['remoteapp', 'ssms', 'published applications', 'rds', 'app catalog', 'windows', 'single app', 'seamless'] },
          { name: 'Quick Links', href: '/quick-links-admin', icon: Link2, minRole: 'admin', keywords: ['support', 'shortcuts', 'launcher', 'teams', 'zoom', 'curate', 'links'] },
          { name: 'Vault Secrets', href: '/vault-secrets', icon: KeyRound, minRole: 'admin', keywords: ['pam', 'secrets', 'credentials', 'vault'] },
          { name: 'Rotation Policies', href: '/rotation-policies', icon: RefreshCw, minRole: 'admin', keywords: ['password rotation', 'rotate'] },
          { name: 'Privileged Sessions', href: '/guacamole-sessions', icon: MonitorPlay, minRole: 'operator', keywords: ['rdp', 'ssh', 'vnc', 'session recording', 'guacamole'] },
        ],
      },
    ],
  },
  {
    id: 'audit',
    label: 'Audit & Reporting',
    icon: FileText,
    sections: [
      {
        label: 'Audit Trail',
        items: [
          { name: 'Audit Logs', href: '/audit-logs', icon: FileText, minRole: 'auditor', keywords: ['events', 'trail', 'reporter'] },
          { name: 'Live Audit Stream', href: '/audit/dashboard', icon: Radio, minRole: 'auditor', keywords: ['realtime', 'websocket', 'stream'] },
          { name: 'Unified Audit', href: '/unified-audit', icon: Layers, minRole: 'auditor', keywords: ['combined', 'all services'] },
          { name: 'Admin Audit Log', href: '/admin-audit-log', icon: ScrollText, minRole: 'auditor', keywords: ['admin actions', 'changes'] },
          { name: 'Audit Archival', href: '/audit-archival', icon: ArchiveRestore, minRole: 'admin', keywords: ['retention', 'archive', 'export'] },
        ],
      },
      {
        label: 'Analytics & Reports',
        items: [
          { name: 'Login Analytics', href: '/login-analytics', icon: Activity, minRole: 'auditor', keywords: ['sign-in', 'trends'] },
          { name: 'Auth Analytics', href: '/auth-analytics', icon: TrendingUp, minRole: 'auditor', keywords: ['authentication', 'mfa usage'] },
          { name: 'Usage Analytics', href: '/usage-analytics', icon: PieChart, minRole: 'auditor', keywords: ['adoption', 'activity'] },
          { name: 'Risk Dashboard', href: '/risk-dashboard', icon: AlertTriangle, minRole: 'auditor', keywords: ['risk score', 'threats'] },
          { name: 'Compliance', href: '/compliance-reports', icon: ClipboardList, minRole: 'auditor', keywords: ['soc2', 'iso', 'gdpr', 'reports'] },
          { name: 'Compliance Posture', href: '/compliance-dashboard', icon: Gauge, minRole: 'auditor', keywords: ['posture', 'controls'] },
          { name: 'Reports', href: '/reports', icon: BarChart3, minRole: 'auditor', keywords: ['scheduled', 'export', 'reporter'] },
        ],
      },
    ],
  },
  {
    id: 'ai',
    label: 'AI & Intelligence',
    icon: Brain,
    sections: [
      {
        label: '',
        items: [
          { name: 'AI Agents', href: '/ai-agents', icon: Bot, minRole: 'admin', keywords: ['assistant', 'automation'] },
          { name: 'Security Posture', href: '/ispm', icon: ShieldCheck, minRole: 'admin', keywords: ['ispm', 'posture management'] },
          { name: 'Identity Intelligence', href: '/ai-intelligence', icon: Brain, minRole: 'admin', keywords: ['fusion', 'copilot', 'briefing', 'local ai', 'llm'] },
          { name: 'Recommendations', href: '/ai-recommendations', icon: Lightbulb, minRole: 'admin', keywords: ['suggestions', 'insights'] },
          { name: 'Predictions', href: '/predictive-analytics', icon: TrendingUp, minRole: 'admin', keywords: ['forecast', 'ml'] },
        ],
      },
    ],
  },
  {
    id: 'platform',
    label: 'Platform',
    icon: Settings,
    sections: [
      {
        label: 'System',
        items: [
          { name: 'System Health', href: '/system-health', icon: HeartPulse, minRole: 'operator', keywords: ['status', 'services', 'uptime'] },
          { name: 'Organizations', href: '/organizations', icon: Building2, minRole: 'admin', keywords: ['orgs', 'multi-tenant'] },
          { name: 'Tenant Mgmt', href: '/tenant-management', icon: Building2, minRole: 'super_admin', keywords: ['tenants', 'platform admin'] },
          { name: 'Branding', href: '/branding', icon: Palette, minRole: 'admin', keywords: ['logo', 'theme', 'colors', 'white label'] },
          { name: 'Email Templates', href: '/email-templates', icon: Mail, minRole: 'admin', keywords: ['mail', 'templates'] },
          { name: 'Notification Mgmt', href: '/notification-admin', icon: Send, minRole: 'admin', keywords: ['broadcast', 'announcements'] },
          { name: 'Webhooks', href: '/webhooks', icon: Bell, minRole: 'admin', keywords: ['events', 'integrations', 'callbacks'] },
          { name: 'Settings', href: '/settings', icon: Settings, minRole: 'admin', keywords: ['configuration', 'system settings'] },
        ],
      },
      {
        label: 'Developer',
        items: [
          { name: 'API Explorer', href: '/api-explorer', icon: Code2, minRole: 'admin', keywords: ['rest', 'try api'] },
          { name: 'OAuth Playground', href: '/oauth-playground', icon: Play, minRole: 'admin', keywords: ['token', 'flows', 'debug'] },
          { name: 'API Docs', href: '/api-docs', icon: BookOpen, minRole: 'admin', keywords: ['swagger', 'openapi', 'reference'] },
          { name: 'Developer Settings', href: '/developer-settings', icon: Settings, minRole: 'admin', keywords: ['api keys', 'sdk'] },
          { name: 'Error Catalog', href: '/error-catalog', icon: AlertTriangle, minRole: 'admin', keywords: ['error codes', 'troubleshooting'] },
        ],
      },
    ],
  },
]

// View modes cap the effective role level so the same config powers the
// admin / management (operator) / reporting (auditor) lenses.
const VIEW_MODE_CAP: Record<ViewMode, MinRole> = {
  admin: 'super_admin',
  management: 'operator',
  reporting: 'auditor',
}

const LEVEL: Record<MinRole, number> = {
  user: 0,
  auditor: 1,
  operator: 2,
  admin: 3,
  super_admin: 4,
}

export interface NavFilter {
  roles: string[]
  viewMode: ViewMode
  query?: string
}

function itemVisible(item: NavItem, domain: NavDomain, filter: NavFilter): boolean {
  const cap = LEVEL[VIEW_MODE_CAP[filter.viewMode]]
  if (LEVEL[item.minRole] > cap) return false
  // Reporting lens focuses the console on personal + audit content.
  if (filter.viewMode === 'reporting' && domain !== 'audit' && domain !== 'home') return false
  return hasMinRole(filter.roles, item.minRole, domain === 'audit')
}

function itemMatches(item: NavItem, sectionLabel: string, domainLabel: string, query: string): boolean {
  const q = query.trim().toLowerCase()
  if (!q) return true
  const haystack = [item.name, item.href, sectionLabel, domainLabel, ...(item.keywords ?? [])]
    .join(' ')
    .toLowerCase()
  return q.split(/\s+/).every((term) => haystack.includes(term))
}

/**
 * Applies role, view-mode and search filtering. Returns only domains/sections
 * that still contain at least one visible item.
 */
export function filterNavigation(filter: NavFilter, groups: NavDomainGroup[] = navigation): NavDomainGroup[] {
  return groups
    .map((group) => ({
      ...group,
      sections: group.sections
        .map((section) => ({
          ...section,
          items: section.items.filter(
            (item) =>
              itemVisible(item, group.id, filter) &&
              itemMatches(item, section.label, group.label, filter.query ?? '')
          ),
        }))
        .filter((section) => section.items.length > 0),
    }))
    .filter((group) => group.sections.length > 0)
}

/** All hrefs declared in the navigation config (used by consistency tests). */
export function allNavHrefs(groups: NavDomainGroup[] = navigation): string[] {
  return groups.flatMap((g) => g.sections.flatMap((s) => s.items.map((i) => i.href)))
}

/** A nav item flattened with its domain label — the row shape the command palette renders. */
export interface FlatNavItem extends NavItem {
  domainLabel: string
}

/**
 * Flatten domain groups into a single ordered list, carrying each item's
 * domain label. Pass the already-role-filtered groups (from filterNavigation)
 * so the command palette only ever offers pages the user can actually open.
 */
export function flattenNavItems(groups: NavDomainGroup[] = navigation): FlatNavItem[] {
  const out: FlatNavItem[] = []
  for (const g of groups) {
    for (const s of g.sections) {
      for (const item of s.items) {
        out.push({ ...item, domainLabel: g.label || 'Home' })
      }
    }
  }
  return out
}

/**
 * Rank a flattened item against a lowercased query for the command palette.
 * Higher is better; <= 0 means "no match". Name matches beat keyword matches,
 * and a prefix/word-start match beats a mid-string one, so "use" surfaces
 * "Users" above a page that merely lists "users" as a keyword.
 */
export function scoreNavItem(item: FlatNavItem, q: string): number {
  if (!q) return 1
  const name = item.name.toLowerCase()
  if (name === q) return 100
  if (name.startsWith(q)) return 80
  if (new RegExp(`\\b${escapeRegExp(q)}`).test(name)) return 60
  if (name.includes(q)) return 40
  if (item.domainLabel.toLowerCase().includes(q)) return 20
  for (const kw of item.keywords ?? []) {
    if (kw.toLowerCase().includes(q)) return 15
  }
  if (item.href.toLowerCase().includes(q)) return 10
  return 0
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}
