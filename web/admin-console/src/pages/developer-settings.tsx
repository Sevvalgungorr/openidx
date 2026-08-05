import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Save,
  Key,
  Webhook,
  Globe,
  Gauge,
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Textarea } from '../components/ui/textarea'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '../components/ui/card'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface DeveloperSettings {
  api_keys: {
    max_keys_per_user: number
    default_expiry_days: number
    allowed_scopes: string[]
  }
  webhooks: {
    ip_allowlist: string[]
    max_retries: number
    retry_delay_seconds: number
  }
  cors: {
    allowed_origins: string[]
  }
  rate_limits: {
    default_rate_limit: number
    burst_limit: number
  }
}

// ApiDeveloperSettings is the flat shape the backend actually serves
// (internal/admin/developer.go). The UI models the same data nested, so we
// adapt at the query/mutation boundary.
interface ApiDeveloperSettings {
  api_key_max_per_user: number
  api_key_default_expiry: string
  api_key_allowed_scopes: string[]
  webhook_ip_allowlist: string[]
  webhook_max_retries: number
  cors_allowed_origins: string[]
  rate_limit_default: number
  sandbox_enabled: boolean
}

// "90d" <-> 90. "0"/"" -> 0 (never expires).
function expiryToDays(v: string | undefined): number {
  if (!v) return 0
  const n = parseInt(v, 10)
  return Number.isFinite(n) ? n : 0
}
function daysToExpiry(days: number): string {
  return days > 0 ? `${days}d` : '0d'
}

function fromApi(a: ApiDeveloperSettings): DeveloperSettings {
  return {
    api_keys: {
      max_keys_per_user: a.api_key_max_per_user ?? 5,
      default_expiry_days: expiryToDays(a.api_key_default_expiry),
      allowed_scopes: a.api_key_allowed_scopes ?? [],
    },
    webhooks: {
      ip_allowlist: a.webhook_ip_allowlist ?? [],
      max_retries: a.webhook_max_retries ?? 3,
      retry_delay_seconds: 0, // not modeled by the backend
    },
    cors: { allowed_origins: a.cors_allowed_origins ?? [] },
    rate_limits: {
      default_rate_limit: a.rate_limit_default ?? 100,
      burst_limit: 0, // not modeled by the backend
    },
  }
}

function toApi(s: DeveloperSettings, sandboxEnabled: boolean): ApiDeveloperSettings {
  return {
    api_key_max_per_user: s.api_keys.max_keys_per_user,
    api_key_default_expiry: daysToExpiry(s.api_keys.default_expiry_days),
    api_key_allowed_scopes: s.api_keys.allowed_scopes,
    webhook_ip_allowlist: s.webhooks.ip_allowlist,
    webhook_max_retries: s.webhooks.max_retries,
    cors_allowed_origins: s.cors.allowed_origins,
    rate_limit_default: s.rate_limits.default_rate_limit,
    sandbox_enabled: sandboxEnabled,
  }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const ALL_SCOPES = [
  'read:users',
  'write:users',
  'read:groups',
  'write:groups',
  'read:applications',
  'write:applications',
  'read:audit',
  'read:governance',
  'write:governance',
  'read:provisioning',
  'write:provisioning',
] as const

const EXPIRY_OPTIONS = [
  { value: 30, label: '30 days' },
  { value: 60, label: '60 days' },
  { value: 90, label: '90 days' },
  { value: 180, label: '180 days' },
  { value: 365, label: '1 year' },
  { value: 0, label: 'Never expires' },
] as const

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function DeveloperSettingsPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [activeTab, setActiveTab] = useState<'api_keys' | 'webhooks' | 'cors' | 'rate_limits'>('api_keys')

  const { data: apiSettings, isLoading } = useQuery({
    queryKey: ['developer-settings'],
    queryFn: () => api.get<ApiDeveloperSettings>('/api/v1/developer/settings'),
  })
  const settings = apiSettings ? fromApi(apiSettings) : undefined

  const [formData, setFormData] = useState<DeveloperSettings | null>(null)

  useEffect(() => {
    if (settings && !formData) {
      setFormData(settings)
    }
  }, [settings]) // eslint-disable-line react-hooks/exhaustive-deps

  const updateMutation = useMutation({
    mutationFn: (data: DeveloperSettings) =>
      api.put('/api/v1/developer/settings', toApi(data, apiSettings?.sandbox_enabled ?? false)),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['developer-settings'] })
      toast({ title: 'Settings saved', description: 'Developer settings updated successfully.' })
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: error.message || 'Failed to save developer settings.',
        variant: 'destructive',
      })
    },
  })

  const handleSave = () => {
    if (formData) {
      updateMutation.mutate(formData)
    }
  }

  // Helpers to update nested state
  const updateApiKeys = (field: keyof DeveloperSettings['api_keys'], value: number | string[]) => {
    if (formData) {
      setFormData({
        ...formData,
        api_keys: { ...formData.api_keys, [field]: value },
      })
    }
  }

  const updateWebhooks = (field: keyof DeveloperSettings['webhooks'], value: number | string[]) => {
    if (formData) {
      setFormData({
        ...formData,
        webhooks: { ...formData.webhooks, [field]: value },
      })
    }
  }

  const updateCors = (field: keyof DeveloperSettings['cors'], value: string[]) => {
    if (formData) {
      setFormData({
        ...formData,
        cors: { ...formData.cors, [field]: value },
      })
    }
  }

  const updateRateLimits = (field: keyof DeveloperSettings['rate_limits'], value: number) => {
    if (formData) {
      setFormData({
        ...formData,
        rate_limits: { ...formData.rate_limits, [field]: value },
      })
    }
  }

  const toggleScope = (scope: string) => {
    if (!formData) return
    const current = formData.api_keys.allowed_scopes
    const next = current.includes(scope)
      ? current.filter((s) => s !== scope)
      : [...current, scope]
    updateApiKeys('allowed_scopes', next)
  }

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

  if (isLoading || !formData) {
    return (
      <div className="space-y-6">
        <h1 className="text-3xl font-bold tracking-tight">Developer Settings</h1>
        <p className="text-center py-8">Loading developer settings...</p>
      </div>
    )
  }

  const tabs = [
    { id: 'api_keys' as const, label: 'API Keys', icon: Key },
    { id: 'webhooks' as const, label: 'Webhooks', icon: Webhook },
    { id: 'cors' as const, label: 'CORS', icon: Globe },
    { id: 'rate_limits' as const, label: 'Rate Limits', icon: Gauge },
  ]

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Developer Settings</h1>
          <p className="text-muted-foreground">Configure API keys, webhooks, CORS, and rate limits</p>
        </div>
        <Button onClick={handleSave} disabled={updateMutation.isPending}>
          <Save className="mr-2 h-4 w-4" />
          {updateMutation.isPending ? 'Saving...' : 'Save Changes'}
        </Button>
      </div>

      <div className="flex gap-6">
        {/* Sidebar tabs */}
        <div className="w-48 space-y-1">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`w-full flex items-center gap-2 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                activeTab === tab.id
                  ? 'bg-gray-100 text-gray-900'
                  : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900'
              }`}
            >
              <tab.icon className="h-4 w-4" />
              {tab.label}
            </button>
          ))}
        </div>

        {/* Content */}
        <div className="flex-1">
          {/* API Keys Tab */}
          {activeTab === 'api_keys' && (
            <div className="space-y-6">
              <Card>
                <CardHeader>
                  <CardTitle>API Key Defaults</CardTitle>
                  <CardDescription>
                    Configure defaults for developer API key creation
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid gap-4 md:grid-cols-2">
                    <div className="space-y-2">
                      <label className="text-sm font-medium">Max Keys Per User</label>
                      <Input
                        type="number"
                        min={1}
                        max={50}
                        value={formData.api_keys.max_keys_per_user}
                        onChange={(e) =>
                          updateApiKeys('max_keys_per_user', parseInt(e.target.value) || 1)
                        }
                      />
                      <p className="text-xs text-muted-foreground">
                        Maximum number of API keys a single user can create
                      </p>
                    </div>
                    <div className="space-y-2">
                      <label className="text-sm font-medium">Default Expiry</label>
                      <select
                        value={formData.api_keys.default_expiry_days}
                        onChange={(e) =>
                          updateApiKeys('default_expiry_days', parseInt(e.target.value))
                        }
                        className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                      >
                        {EXPIRY_OPTIONS.map((opt) => (
                          <option key={opt.value} value={opt.value}>
                            {opt.label}
                          </option>
                        ))}
                      </select>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Allowed Scopes</CardTitle>
                  <CardDescription>
                    Select which scopes can be assigned to API keys
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="grid gap-2 md:grid-cols-2 lg:grid-cols-3">
                    {ALL_SCOPES.map((scope) => (
                      <label
                        key={scope}
                        className="flex items-center gap-2 p-2 border rounded hover:bg-muted/50 cursor-pointer"
                      >
                        <input
                          type="checkbox"
                          checked={formData.api_keys.allowed_scopes.includes(scope)}
                          onChange={() => toggleScope(scope)}
                          className="rounded"
                        />
                        <span className="text-sm font-mono">{scope}</span>
                      </label>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>
          )}

          {/* Webhooks Tab */}
          {activeTab === 'webhooks' && (
            <div className="space-y-6">
              <Card>
                <CardHeader>
                  <CardTitle>Webhook Configuration</CardTitle>
                  <CardDescription>
                    Configure webhook delivery settings and IP restrictions
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid gap-4 md:grid-cols-2">
                    <div className="space-y-2">
                      <label className="text-sm font-medium">Max Retries</label>
                      <Input
                        type="number"
                        min={0}
                        max={10}
                        value={formData.webhooks.max_retries}
                        onChange={(e) =>
                          updateWebhooks('max_retries', parseInt(e.target.value) || 0)
                        }
                      />
                      <p className="text-xs text-muted-foreground">
                        Number of retry attempts for failed webhook deliveries
                      </p>
                    </div>
                    <div className="space-y-2">
                      <label className="text-sm font-medium">Retry Delay (seconds)</label>
                      <Input
                        type="number"
                        min={1}
                        max={3600}
                        value={formData.webhooks.retry_delay_seconds}
                        onChange={(e) =>
                          updateWebhooks(
                            'retry_delay_seconds',
                            parseInt(e.target.value) || 1
                          )
                        }
                      />
                      <p className="text-xs text-muted-foreground">
                        Base delay between retry attempts (exponential backoff applied)
                      </p>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>IP Allowlist</CardTitle>
                  <CardDescription>
                    Restrict webhook delivery to specific IP addresses or CIDR ranges. Leave empty to allow all.
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-2">
                  <Textarea
                    className="font-mono text-sm min-h-[120px]"
                    placeholder={"10.0.0.0/8\n192.168.1.0/24\n203.0.113.50"}
                    value={(formData.webhooks.ip_allowlist || []).join('\n')}
                    onChange={(e) =>
                      updateWebhooks(
                        'ip_allowlist',
                        e.target.value
                          .split('\n')
                          .map((l) => l.trim())
                          .filter((l) => l.length > 0)
                      )
                    }
                  />
                  <p className="text-xs text-muted-foreground">
                    One IP address or CIDR range per line
                  </p>
                </CardContent>
              </Card>
            </div>
          )}

          {/* CORS Tab */}
          {activeTab === 'cors' && (
            <Card>
              <CardHeader>
                <CardTitle>CORS Configuration</CardTitle>
                <CardDescription>
                  Configure Cross-Origin Resource Sharing (CORS) allowed origins for API access
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium">Allowed Origins</label>
                  <Textarea
                    className="font-mono text-sm min-h-[160px]"
                    placeholder={"https://app.example.com\nhttps://staging.example.com\nhttp://localhost:3000"}
                    value={(formData.cors.allowed_origins || []).join('\n')}
                    onChange={(e) =>
                      updateCors(
                        'allowed_origins',
                        e.target.value
                          .split('\n')
                          .map((l) => l.trim())
                          .filter((l) => l.length > 0)
                      )
                    }
                  />
                  <p className="text-xs text-muted-foreground">
                    One origin per line. Use <code className="bg-muted px-1 rounded">*</code> to
                    allow all origins (not recommended for production).
                  </p>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Rate Limits Tab */}
          {activeTab === 'rate_limits' && (
            <Card>
              <CardHeader>
                <CardTitle>Rate Limit Configuration</CardTitle>
                <CardDescription>
                  Set default rate limits applied to API key authenticated requests
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid gap-4 md:grid-cols-2">
                  <div className="space-y-2">
                    <label className="text-sm font-medium">
                      Default Rate Limit (requests/minute)
                    </label>
                    <Input
                      type="number"
                      min={1}
                      max={100000}
                      value={formData.rate_limits.default_rate_limit}
                      onChange={(e) =>
                        updateRateLimits(
                          'default_rate_limit',
                          parseInt(e.target.value) || 60
                        )
                      }
                    />
                    <p className="text-xs text-muted-foreground">
                      The sustained request rate allowed per API key per minute
                    </p>
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm font-medium">
                      Burst Limit (requests)
                    </label>
                    <Input
                      type="number"
                      min={1}
                      max={10000}
                      value={formData.rate_limits.burst_limit}
                      onChange={(e) =>
                        updateRateLimits('burst_limit', parseInt(e.target.value) || 10)
                      }
                    />
                    <p className="text-xs text-muted-foreground">
                      Maximum number of requests allowed in a short burst above the sustained rate
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  )
}
