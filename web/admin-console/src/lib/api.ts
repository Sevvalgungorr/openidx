import axios, { AxiosError, AxiosRequestConfig } from 'axios'

export interface UserProfile {
  id: string
  username: string
  email: string
  firstName: string
  lastName: string
  enabled: boolean
  emailVerified: boolean
  createdAt: string
  mfaEnabled: boolean
  mfaMethods: string[]
}

export interface MFASetupResponse {
  secret: string
  qrCodeUrl: string
}

export interface MFAEnableResponse {
  status: string
  backupCodes: string[]
}

export interface IdentityProvider {
  id: string;
  name: string;
  provider_type: 'oidc' | 'saml';
  issuer_url: string;
  client_id: string;
  client_secret: string;
  scopes: string[];
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface RuleCondition {
  field: string
  operator: string
  value: string
}

export interface RuleAction {
  type: string
  target: string
  parameters?: Record<string, unknown>
}

export interface ProvisioningRule {
  id: string
  name: string
  description: string
  trigger: string
  conditions: RuleCondition[]
  actions: RuleAction[]
  enabled: boolean
  priority: number
  created_at: string
  updated_at: string
}

export interface VaultSecretMeta {
  id: string
  name: string
  type: string
  description?: string
  current_version: number
  created_at: string
  updated_at: string
}

export interface VaultVersion {
  version: number
  key_id: number
  created_by?: string
  created_at: string
}

export interface VaultSecretDetail extends VaultSecretMeta {
  versions: VaultVersion[]
}

export interface VaultGrant {
  id: string
  secret_id: string
  principal_type: string
  principal_id: string
  actions: string[]
  expires_at?: string
  granted_by?: string
}

export interface VaultCheckout {
  id: string
  secret_version: number
  principal_id?: string
  mode: string
  reason?: string
  leased_at: string
  expires_at?: string
  status: string
}

export interface VaultGenerationPolicy {
  length: number
  upper: boolean
  lower: boolean
  digits: boolean
  symbols: boolean
}

export interface VaultRotationPolicy {
  id: string
  org_id: string
  secret_id: string
  connector_type: string
  connector_config: Record<string, unknown>
  generation_policy: VaultGenerationPolicy
  interval_seconds: number
  rotate_on_checkout: boolean
  enabled: boolean
  next_run_at?: string
  last_run_at?: string
  last_status?: string
  created_at: string
  updated_at: string
}

export interface VaultRotationPolicyInput {
  secret_id: string
  connector_type: string
  connector_config: Record<string, unknown>
  generation_policy: VaultGenerationPolicy
  interval_seconds: number
  rotate_on_checkout: boolean
  enabled: boolean | null
}

export interface VaultRotationRun {
  id: string
  status: string
  trigger: string
  connector_type: string
  version_from?: number
  version_to?: number
  error_message?: string
  started_at?: string
  completed_at?: string
}

// Get API base URL based on environment
const getAPIBaseURL = (): string => {
  const envURL = import.meta.env.VITE_API_URL || import.meta.env.VITE_API_BASE_URL
  if (envURL) {
    return envURL
  }

  // In production, use the current origin
  if (import.meta.env.PROD && window.location.origin !== 'http://localhost:3000') {
    return window.location.origin
  }

  return 'http://localhost:8005'
}

export const baseURL = getAPIBaseURL()

// Get OAuth URL based on environment
// Export as function for use in auth.tsx
export function getOAuthURL(): string {
  return import.meta.env.VITE_OAUTH_URL || baseURL
}

const axiosInstance = axios.create({
  baseURL,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Request interceptor to add auth token + tenant selection
axiosInstance.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  // Multi-tenancy: when a platform admin has selected an org, scope every
  // request to it via X-Org-Slug (the signal the backend tenant resolver
  // honors first). Regular admins never set this — their token's org applies.
  const orgSlug = localStorage.getItem('selected_org_slug')
  if (orgSlug) {
    config.headers['X-Org-Slug'] = orgSlug
  }
  return config
})

// Exported for auth.tsx to signal when auth init is complete (kept for potential future use)
// eslint-disable-next-line @typescript-eslint/no-unused-vars
export const setAuthInitializing = (_value: boolean) => {
  // Currently not used - 401 handling moved to auth context
}

// Response interceptor for error handling
axiosInstance.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    if (error.response?.status === 401) {
      // Log 401 errors but don't auto-redirect - let the auth context handle session state
      // This prevents redirect loops when the backend rejects tokens during auth flow
      console.warn('[API] 401 Unauthorized:', error.config?.url)
    }

    // 503 temporarily_unavailable: the backend returns this (with a Retry-After
    // header) during a transient dependency brownout — e.g. a database failover
    // (see internal/oauth/unavailable.go). It is meant to be RETRIED, not shown
    // to the user as a hard failure. Retry idempotent requests a bounded number
    // of times, honoring Retry-After, so a brief DB blip stays invisible.
    const config = error.config as (AxiosRequestConfig & { _ha503Retries?: number }) | undefined
    const method = (config?.method || 'get').toLowerCase()
    const isIdempotent = method === 'get' || method === 'head' || method === 'options'
    if (error.response?.status === 503 && config && isIdempotent) {
      const attempts = config._ha503Retries ?? 0
      const MAX_503_RETRIES = 3
      if (attempts < MAX_503_RETRIES) {
        config._ha503Retries = attempts + 1
        // Honor Retry-After (seconds); default to a short capped backoff.
        const retryAfterHeader = error.response.headers?.['retry-after']
        const retryAfterSec = retryAfterHeader ? parseInt(String(retryAfterHeader), 10) : NaN
        const delayMs = Number.isFinite(retryAfterSec)
          ? Math.min(retryAfterSec * 1000, 10000)
          : Math.min(500 * 2 ** attempts, 4000)
        console.warn(`[API] 503 temporarily_unavailable on ${config.url} — retry ${config._ha503Retries}/${MAX_503_RETRIES} in ${delayMs}ms`)
        await new Promise((resolve) => setTimeout(resolve, delayMs))
        return axiosInstance(config)
      }
    }

    return Promise.reject(error)
  }
)

export const api = {
  get: async <T>(url: string, config?: AxiosRequestConfig): Promise<T> => {
    const response = await axiosInstance.get<T>(url, config)
    return response.data
  },

  getWithHeaders: async <T>(url: string, config?: AxiosRequestConfig): Promise<{ data: T; headers: Record<string, string> }> => {
    const response = await axiosInstance.get<T>(url, config)
    const headers: Record<string, string> = {}
    if (response.headers) {
      Object.entries(response.headers).forEach(([key, value]) => {
        if (typeof value === 'string') headers[key] = value
      })
    }
    return { data: response.data, headers }
  },

  post: async <T>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<T> => {
    const response = await axiosInstance.post<T>(url, data, config)
    return response.data
  },

  put: async <T>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<T> => {
    const response = await axiosInstance.put<T>(url, data, config)
    return response.data
  },

  patch: async <T>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<T> => {
    const response = await axiosInstance.patch<T>(url, data, config)
    return response.data
  },

  delete: async <T>(url: string, config?: AxiosRequestConfig): Promise<T> => {
    const response = await axiosInstance.delete<T>(url, config)
    return response.data
  },

  // Identity Providers API
  getIdentityProviders: async (): Promise<IdentityProvider[]> => {
    const response = await api.get<IdentityProvider[]>('/api/v1/identity/providers');
    return response;
  },

  createIdentityProvider: async (data: Omit<IdentityProvider, 'id' | 'created_at' | 'updated_at'>): Promise<IdentityProvider> => {
    const response = await api.post<IdentityProvider>('/api/v1/identity/providers', data);
    return response;
  },

  getIdentityProvider: async (id: string): Promise<IdentityProvider> => {
    const response = await api.get<IdentityProvider>(`/api/v1/identity/providers/${id}`);
    return response;
  },

  updateIdentityProvider: async (id: string, data: Partial<IdentityProvider>): Promise<IdentityProvider> => {
    const response = await api.put<IdentityProvider>(`/api/v1/identity/providers/${id}`, data);
    return response;
  },

  deleteIdentityProvider: async (id: string): Promise<void> => {
    await api.delete<void>(`/api/v1/identity/providers/${id}`);
  },

  // Provisioning Rules API
  getProvisioningRules: async (): Promise<ProvisioningRule[]> => {
    return api.get<ProvisioningRule[]>('/api/v1/provisioning/rules')
  },

  createProvisioningRule: async (data: Omit<ProvisioningRule, 'id' | 'created_at' | 'updated_at'>): Promise<ProvisioningRule> => {
    return api.post<ProvisioningRule>('/api/v1/provisioning/rules', data)
  },

  updateProvisioningRule: async (id: string, data: Partial<ProvisioningRule>): Promise<ProvisioningRule> => {
    return api.put<ProvisioningRule>(`/api/v1/provisioning/rules/${id}`, data)
  },

  deleteProvisioningRule: async (id: string): Promise<void> => {
    await api.delete<void>(`/api/v1/provisioning/rules/${id}`)
  },

  postFormData: async <T>(url: string, formData: FormData): Promise<T> => {
    const response = await axiosInstance.post<T>(url, formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
    return response.data
  },

  // WebAuthn API
  getWebAuthnCredentials: async (): Promise<WebAuthnCredential[]> => {
    return api.get<WebAuthnCredential[]>('/api/v1/identity/mfa/webauthn/credentials')
  },

  beginWebAuthnRegistration: async (): Promise<unknown> => {
    return api.post<unknown>('/api/v1/identity/mfa/webauthn/register/begin')
  },

  finishWebAuthnRegistration: async (data: unknown): Promise<WebAuthnCredential> => {
    return api.post<WebAuthnCredential>('/api/v1/identity/mfa/webauthn/register/finish', data)
  },

  deleteWebAuthnCredential: async (credentialId: string): Promise<void> => {
    await api.delete<void>(`/api/v1/identity/mfa/webauthn/credentials/${credentialId}`)
  },

  // Push MFA API
  getPushDevices: async (): Promise<PushMFADevice[]> => {
    return api.get<PushMFADevice[]>('/api/v1/identity/mfa/push/devices')
  },

  registerPushDevice: async (data: PushMFAEnrollment): Promise<PushMFADevice> => {
    return api.post<PushMFADevice>('/api/v1/identity/mfa/push/devices', data)
  },

  // startPushEnrollment mints a QR enrollment ticket so an authenticator app can
  // scan and bind itself as a push device (Google/MS-Authenticator style).
  startPushEnrollment: async (): Promise<PushEnrollmentTicket> => {
    return api.post<PushEnrollmentTicket>('/api/v1/identity/mfa/push/enroll/start')
  },

  deletePushDevice: async (deviceId: string): Promise<void> => {
    await api.delete<void>(`/api/v1/identity/mfa/push/devices/${deviceId}`)
  },

  // Audit stream WebSocket helpers
  createAuditStreamConnection: (options: {
    token?: string
    onMessage: (event: MessageEvent) => void
    onOpen?: () => void
    onError?: (error: Event) => void
    onClose?: (event: CloseEvent) => void
  }) => {
    const apiBase = import.meta.env.VITE_API_URL || import.meta.env.VITE_API_BASE_URL || ''
    let wsUrl: string

    if (apiBase) {
      // Convert HTTP to WebSocket protocol
      wsUrl = apiBase.replace(/^https?:\/\//, window.location.protocol === 'https:' ? 'wss://' : 'ws://')
    } else {
      // Default to current origin with WebSocket protocol
      wsUrl = window.location.protocol === 'https:'
        ? `wss://${window.location.host}`
        : `ws://${window.location.host}`
    }

    wsUrl = `${wsUrl}/api/v1/audit/stream`

    // Note: Origin header cannot be set manually in browser WebSocket API
    // The browser automatically sets it based on the current page origin
    // Origin validation happens server-side
    const protocols = []
    if (options.token) {
      // Use subprotocol for token (common pattern)
      protocols.push(`access_token_${options.token}`)
    }

    const ws = new WebSocket(wsUrl, protocols)

    ws.onopen = options.onOpen ?? null
    ws.onmessage = options.onMessage
    ws.onerror = options.onError ?? null
    ws.onclose = options.onClose ?? null

    return ws
  },

  getWebSocketUrl: (): string => {
    const apiBase = import.meta.env.VITE_API_URL || import.meta.env.VITE_API_BASE_URL || ''

    if (apiBase) {
      return apiBase.replace(/^https?:\/\//, window.location.protocol === 'https:' ? 'wss://' : 'ws://')
    }

    return window.location.protocol === 'https:'
      ? `wss://${window.location.host}`
      : `ws://${window.location.host}`
  },

  vault: {
    listSecrets: () => api.get<{ secrets: VaultSecretMeta[] | null }>('/api/v1/vault/secrets'),
    createSecret: (body: { name: string; type: string; description?: string; value: string; metadata?: Record<string, unknown> }) =>
      api.post<VaultSecretMeta>('/api/v1/vault/secrets', body),
    getSecret: (id: string) => api.get<VaultSecretDetail>(`/api/v1/vault/secrets/${id}`),
    newVersion: (id: string, value: string) =>
      api.put<{ version: number }>(`/api/v1/vault/secrets/${id}/version`, { value }),
    deleteSecret: (id: string) => api.delete<void>(`/api/v1/vault/secrets/${id}`),
    reveal: (id: string, reason: string) =>
      api.post<{ value: string }>(`/api/v1/vault/secrets/${id}/reveal`, { reason }),
    addGrant: (id: string, grant: { principal_type: string; principal_id: string; actions: string[]; expires_at?: string }) =>
      api.post<{ id: string }>(`/api/v1/vault/secrets/${id}/grants`, grant),
    removeGrant: (id: string, grantId: string) =>
      api.delete<void>(`/api/v1/vault/secrets/${id}/grants/${grantId}`),
    listGrants: (id: string) =>
      api.get<{ grants: VaultGrant[] | null }>(`/api/v1/vault/secrets/${id}/grants`),
    listCheckouts: (id: string) =>
      api.get<{ checkouts: VaultCheckout[] | null }>(`/api/v1/vault/secrets/${id}/checkouts`),
    listPolicies: () =>
      api.get<{ policies: VaultRotationPolicy[] | null }>('/api/v1/vault/rotation-policies'),
    createPolicy: (body: VaultRotationPolicyInput) =>
      api.post<VaultRotationPolicy>('/api/v1/vault/rotation-policies', body),
    getPolicy: (id: string) =>
      api.get<VaultRotationPolicy>(`/api/v1/vault/rotation-policies/${id}`),
    updatePolicy: (id: string, body: VaultRotationPolicyInput) =>
      api.put<VaultRotationPolicy>(`/api/v1/vault/rotation-policies/${id}`, body),
    deletePolicy: (id: string) =>
      api.delete<void>(`/api/v1/vault/rotation-policies/${id}`),
    rotateNow: (secretId: string) =>
      api.post<VaultRotationRun | { status: string }>(`/api/v1/vault/secrets/${secretId}/rotate`),
    listRotations: (secretId: string) =>
      api.get<{ rotations: VaultRotationRun[] | null }>(`/api/v1/vault/secrets/${secretId}/rotations`),
  },

  // PAM connection manager (Devolutions RDM parity). Sessions launch through
  // the access-service Guacamole broker with the credential injected
  // server-side; the browser only ever receives a connect URL.
  pam: {
    listEntryTypes: () =>
      api.get<{ types: PamEntryType[] }>('/api/v1/access/pam/entry-types'),
    listFolders: () =>
      api.get<{ folders: PamFolder[] }>('/api/v1/access/pam/folders'),
    createFolder: (body: { parent_id?: string; name: string; icon?: string; description?: string }) =>
      api.post<{ id: string }>('/api/v1/access/pam/folders', body),
    updateFolder: (id: string, body: { parent_id?: string; name: string; icon?: string; description?: string }) =>
      api.put<{ id: string }>(`/api/v1/access/pam/folders/${id}`, body),
    deleteFolder: (id: string) => api.delete<void>(`/api/v1/access/pam/folders/${id}`),
    listEntries: (params?: { folder_id?: string; type?: string; q?: string; favorites?: boolean }) => {
      const qs = new URLSearchParams()
      if (params?.folder_id) qs.set('folder_id', params.folder_id)
      if (params?.type) qs.set('type', params.type)
      if (params?.q) qs.set('q', params.q)
      if (params?.favorites) qs.set('favorites', 'true')
      const suffix = qs.toString() ? `?${qs.toString()}` : ''
      return api.get<{ entries: PamEntry[] }>(`/api/v1/access/pam/entries${suffix}`)
    },
    getEntry: (id: string) => api.get<PamEntry>(`/api/v1/access/pam/entries/${id}`),
    createEntry: (body: PamEntryInput) =>
      api.post<{ id: string }>('/api/v1/access/pam/entries', body),
    updateEntry: (id: string, body: PamEntryInput) =>
      api.put<{ id: string }>(`/api/v1/access/pam/entries/${id}`, body),
    deleteEntry: (id: string) => api.delete<void>(`/api/v1/access/pam/entries/${id}`),
    favorite: (id: string) => api.post<{ favorite: boolean }>(`/api/v1/access/pam/entries/${id}/favorite`),
    unfavorite: (id: string) => api.delete<{ favorite: boolean }>(`/api/v1/access/pam/entries/${id}/favorite`),
    connect: (id: string) => api.post<PamConnectResult>(`/api/v1/access/pam/entries/${id}/connect`),
    reveal: (id: string, reason: string) =>
      api.post<{ value: string }>(`/api/v1/access/pam/entries/${id}/reveal`, { reason }),
    requestAccess: (id: string, reason: string) =>
      api.post<{ request_id: string }>(`/api/v1/access/pam/entries/${id}/request`, { reason }),
    listGrants: (id: string) =>
      api.get<{ grants: PamEntryGrant[] }>(`/api/v1/access/pam/entries/${id}/grants`),
    addGrant: (id: string, grant: { principal_type: string; principal_id: string; actions: string[]; expires_at?: string }) =>
      api.post<{ id: string }>(`/api/v1/access/pam/entries/${id}/grants`, grant),
    removeGrant: (id: string, grantId: string) =>
      api.delete<void>(`/api/v1/access/pam/entries/${id}/grants/${grantId}`),
    listRequests: () =>
      api.get<{ requests: PamAccessRequest[] }>('/api/v1/access/pam/entry-requests'),
    approveRequest: (id: string) =>
      api.post<{ status: string }>(`/api/v1/access/pam/entry-requests/${id}/approve`),
    denyRequest: (id: string) =>
      api.post<{ status: string }>(`/api/v1/access/pam/entry-requests/${id}/deny`),
    listSessions: () =>
      api.get<{ sessions: PamEntrySession[] }>('/api/v1/access/pam/sessions'),
    importRDM: (data: string, folderId?: string) =>
      api.post<PamImportResult>('/api/v1/access/pam/import/rdm', { data, folder_id: folderId }),
    brokerStatus: () =>
      api.get<PamBrokerStatus>('/api/v1/access/pam/broker/status'),
    enableZiti: (id: string) =>
      api.post<{ reach_mode: string; ziti_service_name?: string; ziti_intercept_port?: number }>(`/api/v1/access/pam/entries/${id}/ziti/enable`),
    disableZiti: (id: string) =>
      api.post<{ reach_mode: string }>(`/api/v1/access/pam/entries/${id}/ziti/disable`),
  },
  windowsApps: {
    // Apps + pools + host posture, in one call so the catalog page renders in
    // a single round trip.
    list: () =>
      api.get<{
        apps: WindowsApp[]
        pools: WindowsAppPool[]
        host_state: WindowsAppHostState[]
        host_agents: WindowsAppHostAgent[]
      }>('/api/v1/access/pam/apps'),
    // End-user launchable-apps view for the portal tiles — only apps the caller
    // is permitted to launch (RBAC-filtered server-side).
    listMine: () => api.get<{ apps: MyWindowsApp[] }>('/api/v1/access/pam/my-apps'),
    create: (body: WindowsAppInput) =>
      api.post<{ id: string }>('/api/v1/access/pam/apps', body),
    update: (id: string, body: WindowsAppInput) =>
      api.put<{ id: string }>(`/api/v1/access/pam/apps/${id}`, body),
    remove: (id: string) => api.delete<void>(`/api/v1/access/pam/apps/${id}`),
    // Launch. On a placement conflict the server replies 409 with a
    // WindowsAppLaunchConflict body; pass replaceSessionId to a retry to
    // disconnect that session and take its slot.
    launch: (id: string, replaceSessionId?: string) => {
      const qs = replaceSessionId ? `?replace=${encodeURIComponent(replaceSessionId)}` : ''
      return api.post<WindowsAppLaunchResult>(`/api/v1/access/pam/apps/${id}/launch${qs}`)
    },
    iconURL: (id: string) => `/api/v1/access/pam/apps/${id}/icon`,
    // Pools
    listPools: () => api.get<{ pools: WindowsAppPool[] }>('/api/v1/access/pam/app-pools'),
    createPool: (body: { name: string; description?: string; placement?: string }) =>
      api.post<{ id: string }>('/api/v1/access/pam/app-pools', body),
    updatePool: (id: string, body: { name: string; description?: string; placement?: string }) =>
      api.put<{ id: string }>(`/api/v1/access/pam/app-pools/${id}`, body),
    removePool: (id: string) => api.delete<void>(`/api/v1/access/pam/app-pools/${id}`),
    addPoolMember: (poolId: string, body: { host_entry_id: string; max_sessions?: number }) =>
      api.post<{ id: string }>(`/api/v1/access/pam/app-pools/${poolId}/members`, body),
    removePoolMember: (poolId: string, memberId: string) =>
      api.delete<void>(`/api/v1/access/pam/app-pools/${poolId}/members/${memberId}`),
    // Discovery import: paste the PowerShell JSON output. Distinct path
    // (not /pam/apps/import) to avoid the /pam/apps/:id route collision.
    importDiscovery: (hostEntryId: string, data: string) =>
      api.post<{ apps_created: number; apps_updated: number; host_updated: boolean }>(
        `/api/v1/access/pam/app-import`, { host_entry_id: hostEntryId, data },
      ),
    // Bind / unbind an enrolled agent to a windows_app_host so its discovery
    // reports auto-sync the catalog (the alternative to pasting the JSON).
    linkAgent: (hostEntryId: string, agentId: string) =>
      api.post<{ host_entry_id: string; agent_id: string }>(
        `/api/v1/access/pam/app-hosts/${hostEntryId}/agent`, { agent_id: agentId },
      ),
    unlinkAgent: (hostEntryId: string) =>
      api.delete<void>(`/api/v1/access/pam/app-hosts/${hostEntryId}/agent`),
  },
  quickLinks: {
    listMine: () => api.get<{ quick_links: QuickLink[] }>('/api/v1/access/quick-links/my'),
    list: () => api.get<{ quick_links: QuickLink[] }>('/api/v1/access/quick-links'),
    create: (body: QuickLinkInput) => api.post<{ id: string }>('/api/v1/access/quick-links', body),
    update: (id: string, body: QuickLinkInput) => api.put<{ status: string }>(`/api/v1/access/quick-links/${id}`, body),
    remove: (id: string) => api.delete<void>(`/api/v1/access/quick-links/${id}`),
  },
}

export interface QuickLink {
  id: string
  title: string
  description: string
  category: string
  icon: string
  type: 'external' | 'pam'
  url?: string
  pam_entry_id?: string
  pam_renderer?: string
  min_role: string
  sort_order: number
  enabled: boolean
  open_in_new: boolean
}

export interface QuickLinkInput {
  title: string
  description?: string
  category?: string
  icon?: string
  type: 'external' | 'pam'
  url?: string
  pam_entry_id?: string
  min_role?: string
  sort_order?: number
  enabled?: boolean
  open_in_new?: boolean
}

export interface PamBrokerStatus {
  available: boolean
  reach_modes: string[]
  direct_broker?: boolean
  ziti_broker?: boolean
}

// PAM connection-manager types
export interface PamEntryType {
  type: string
  kind: 'session' | 'credential' | 'info'
  label: string
  protocol?: string
  secret_label?: string
}

export interface PamFolder {
  id: string
  parent_id?: string
  name: string
  icon?: string
  description?: string
  entry_count: number
  created_at: string
  updated_at: string
}

export interface PamEntry {
  id: string
  folder_id?: string
  name: string
  entry_type: string
  kind: string
  description?: string
  tags: string[]
  hostname?: string
  port?: number
  username?: string
  domain?: string
  url?: string
  settings: Record<string, unknown>
  has_secret: boolean
  credential_entry_id?: string
  credential_entry_name?: string
  allow_reveal: boolean
  require_approval: boolean
  record_session: boolean
  reach_mode: string
  renderer?: string
  ziti_enabled: boolean
  favorite: boolean
  last_connected_at?: string
  connect_count: number
  created_at: string
  updated_at: string
}

export interface PamEntryInput {
  folder_id?: string
  name: string
  entry_type: string
  description?: string
  tags?: string[]
  hostname?: string
  port?: number
  username?: string
  domain?: string
  url?: string
  settings?: Record<string, unknown>
  secret?: string
  credential_entry_id?: string
  allow_reveal?: boolean
  require_approval?: boolean
  record_session?: boolean
  renderer?: string
}

export interface PamConnectResult {
  launch_type: 'guacamole' | 'url'
  connect_url?: string
  url?: string
  entry_id: string
  session_id?: string
  credential_injected?: boolean
  recorded?: boolean
  approval_required?: boolean
}

export interface PamEntryGrant {
  id: string
  principal_type: string
  principal_id: string
  actions: string[]
  expires_at?: string
  granted_by?: string
  created_at: string
}

export interface PamAccessRequest {
  id: string
  entry_id: string
  entry_name: string
  entry_type: string
  requester_id: string
  reason?: string
  status: string
  approver_id?: string
  decided_at?: string
  expires_at?: string
  created_at: string
}

export interface PamEntrySession {
  id: string
  entry_id: string
  entry_name: string
  user_id?: string
  protocol?: string
  credential_injected: boolean
  recording_available: boolean
  started_at: string
  ended_at?: string
  status: string
}

export interface PamImportResult {
  folders_created: number
  entries_created: number
  secrets_stored: number
  by_type: Record<string, number>
  skipped: Array<{ name: string; reason: string }>
}

// ---- Windows application delivery ----

export interface WindowsApp {
  id: string
  host_entry_id?: string
  host_name?: string
  pool_id?: string
  pool_name?: string
  alias: string
  display_name: string
  exec_path?: string
  args?: string
  working_dir?: string
  has_icon: boolean
  source: 'manual' | 'discovered'
  verified: boolean // alias seen in the host's TSAppAllowList — published & launchable
  status: 'active' | 'inconsistent' | 'disabled'
  require_approval?: boolean | null
  record_session?: boolean | null
  created_at: string
  updated_at: string
}

export interface WindowsAppInput {
  host_entry_id?: string
  pool_id?: string
  alias: string
  display_name: string
  exec_path?: string
  args?: string
  working_dir?: string
  require_approval?: boolean | null
  record_session?: boolean | null
}

export interface WindowsAppPool {
  id: string
  name: string
  description?: string
  placement: 'least_loaded' | 'round_robin'
  members: WindowsAppPoolMember[]
  created_at: string
  updated_at: string
}

export interface WindowsAppPoolMember {
  id: string
  host_entry_id: string
  host_name: string
  max_sessions: number
  active_sessions: number
}

export interface WindowsAppHostState {
  host_entry_id: string
  os_edition?: string
  nla_enabled?: boolean
  allow_unlisted_remote_programs?: boolean
  allowlist_enforced?: boolean
  published_app_count?: number
  checked_at?: string
}

// The end-user portal view of a launchable app — just what a tile needs.
export interface MyWindowsApp {
  id: string
  display_name: string
  alias: string
  host_name?: string
  pool_name?: string
  has_icon: boolean
  require_approval: boolean
}

// Which enrolled agent (if any) is bound to a host entry, so the console can
// show whether discovery auto-syncs from an agent vs. needs a manual paste.
export interface WindowsAppHostAgent {
  host_entry_id: string
  agent_id: string
  agent_status?: string
  last_seen_at?: string
}

// A launch either succeeds (guacamole) or reports a placement conflict the
// user must resolve. Mirrors PamConnectResult on success.
export interface WindowsAppLaunchResult {
  launch_type: 'guacamole'
  connect_url: string
  app_id: string
  host_entry_id: string
  host_name: string
  session_id?: string
  recorded: boolean
}

export interface WindowsAppLaunchConflict {
  reason: 'no_capacity' | 'user_session_conflict'
  message: string
  conflicts: Array<{
    host_entry_id: string
    host_name: string
    session_id: string
    app_name?: string
    started_at: string
  }>
}

// WebAuthn types
export interface WebAuthnCredential {
  id: string
  user_id: string
  credential_id: string
  name: string
  aaguid: string
  sign_count: number
  created_at: string
  last_used_at?: string
}

// Push MFA types
export interface PushMFADevice {
  id: string
  user_id: string
  device_name: string
  platform: string
  device_model: string
  enabled: boolean
  trusted: boolean
  created_at: string
  last_used_at?: string
}

export interface PushMFAEnrollment {
  device_token: string
  platform: 'ios' | 'android' | 'web'
  device_name: string
  device_model?: string
}

export interface PushEnrollmentTicket {
  enrollment_token: string
  expires_in: number
  qr_payload: string
}

export default axiosInstance
