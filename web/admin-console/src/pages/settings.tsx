import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Save, Building, Shield, Key, Palette, X, Plus, Smartphone, Send } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

interface Settings {
  general: {
    organization_name: string
    support_email: string
    default_language: string
    default_timezone: string
  }
  security: {
    password_policy: {
      min_length: number
      require_uppercase: boolean
      require_lowercase: boolean
      require_numbers: boolean
      require_special: boolean
      max_age: number
      history: number
    }
    session_timeout: number
    max_failed_logins: number
    lockout_duration: number
    require_mfa: boolean
    allowed_ip_ranges: string[]
    blocked_countries: string[]
    idle_timeout: number
    absolute_timeout: number
    remember_me_duration: number
    reauth_interval: number
    bind_session_to_ip: boolean
    force_logout_on_password_change: boolean
    max_concurrent_sessions: number
    concurrent_session_strategy: string
  }
  authentication: {
    allow_registration: boolean
    require_email_verify: boolean
    allowed_domains: string[]
    social_providers: string[]
    mfa_methods: string[]
  }
  branding: {
    logo_url: string
    favicon_url: string
    primary_color: string
    secondary_color: string
    custom_css: string
    login_page_title: string
    login_page_message: string
  }
}

interface SMSSettings {
  enabled: boolean
  provider: string
  message_prefix: string
  otp_length: number
  otp_expiry: number
  max_attempts: number
  credentials: Record<string, string>
}

interface ProviderField {
  key: string
  label: string
  sensitive: boolean
  placeholder?: string
}

interface ProviderDef {
  id: string
  label: string
  fields: ProviderField[]
}

const SMS_PROVIDERS: ProviderDef[] = [
  { id: 'mock', label: 'Mock (Development)', fields: [] },
  { id: 'twilio', label: 'Twilio', fields: [
    { key: 'twilio_sid', label: 'Account SID', sensitive: false },
    { key: 'twilio_token', label: 'Auth Token', sensitive: true },
    { key: 'twilio_from', label: 'From Number', sensitive: false, placeholder: '+1234567890' },
  ]},
  { id: 'aws_sns', label: 'AWS SNS', fields: [
    { key: 'aws_region', label: 'Region', sensitive: false, placeholder: 'us-east-1' },
    { key: 'aws_access_key', label: 'Access Key', sensitive: false },
    { key: 'aws_secret_key', label: 'Secret Key', sensitive: true },
  ]},
  { id: 'netgsm', label: 'NetGSM', fields: [
    { key: 'netgsm_usercode', label: 'User Code', sensitive: false },
    { key: 'netgsm_password', label: 'Password', sensitive: true },
    { key: 'netgsm_header', label: 'Sender Header', sensitive: false },
  ]},
  { id: 'ileti_merkezi', label: 'Ileti Merkezi', fields: [
    { key: 'iletimerkezi_key', label: 'API Key', sensitive: false },
    { key: 'iletimerkezi_secret', label: 'API Secret', sensitive: true },
    { key: 'iletimerkezi_sender', label: 'Sender Name', sensitive: false },
  ]},
  { id: 'verimor', label: 'Verimor', fields: [
    { key: 'verimor_username', label: 'Username', sensitive: false, placeholder: '908501234567' },
    { key: 'verimor_password', label: 'Password', sensitive: true },
    { key: 'verimor_source_addr', label: 'Sender ID', sensitive: false },
  ]},
  { id: 'turkcell', label: 'Turkcell Mesajussu', fields: [
    { key: 'turkcell_username', label: 'Username', sensitive: false },
    { key: 'turkcell_password', label: 'Password', sensitive: true },
    { key: 'turkcell_sender', label: 'Sender Name', sensitive: false },
  ]},
  { id: 'vodafone', label: 'Vodafone', fields: [
    { key: 'vodafone_api_key', label: 'API Key', sensitive: false },
    { key: 'vodafone_secret', label: 'API Secret', sensitive: true },
    { key: 'vodafone_sender', label: 'Sender Address', sensitive: false },
  ]},
  { id: 'turk_telekom', label: 'Turk Telekom', fields: [
    { key: 'turktelekom_api_key', label: 'API Key', sensitive: false },
    { key: 'turktelekom_secret', label: 'API Secret', sensitive: true },
    { key: 'turktelekom_sender', label: 'Sender Name', sensitive: false },
  ]},
  { id: 'mutlucell', label: 'Mutlucell', fields: [
    { key: 'mutlucell_username', label: 'Username', sensitive: false },
    { key: 'mutlucell_password', label: 'Password', sensitive: true },
    { key: 'mutlucell_api_key', label: 'API Key', sensitive: true },
    { key: 'mutlucell_sender', label: 'Sender Name', sensitive: false },
  ]},
  { id: 'webhook', label: 'Custom Webhook', fields: [
    { key: 'webhook_url', label: 'Webhook URL', sensitive: false, placeholder: 'https://...' },
    { key: 'webhook_api_key', label: 'API Key', sensitive: true },
  ]},
]

export function SettingsPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [activeTab, setActiveTab] = useState<'general' | 'security' | 'authentication' | 'sms' | 'branding'>('general')

  const { data: settings, isLoading, isError, error } = useQuery({
    queryKey: ['settings'],
    queryFn: () => api.get<Settings>('/api/v1/settings'),
  })

  const [formData, setFormData] = useState<Settings | null>(null)
  const [newDomain, setNewDomain] = useState('')
  const [newCountry, setNewCountry] = useState('')

  // SMS settings (separate query/state)
  const { data: smsSettingsData } = useQuery({
    queryKey: ['sms-settings'],
    queryFn: () => api.get<SMSSettings>('/api/v1/settings/sms'),
  })

  const [smsFormData, setSmsFormData] = useState<SMSSettings | null>(null)
  const [testPhone, setTestPhone] = useState('')

  // Initialize form data when settings load
  useEffect(() => {
    if (settings && !formData) {
      setFormData(settings)
    }
  }, [settings]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (smsSettingsData && !smsFormData) {
      setSmsFormData(smsSettingsData)
    }
  }, [smsSettingsData]) // eslint-disable-line react-hooks/exhaustive-deps

  const updateMutation = useMutation({
    mutationFn: (data: Settings) => api.put('/api/v1/settings', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['settings'] })
      toast({ title: 'Settings saved', description: 'Your changes have been saved successfully.' })
    },
    onError: (error: Error) => {
      toast({ title: 'Error', description: error.message || 'Failed to save settings.', variant: 'destructive' })
    },
  })

  const updateSMSMutation = useMutation({
    mutationFn: (data: SMSSettings) => api.put<SMSSettings>('/api/v1/settings/sms', data),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['sms-settings'] })
      setSmsFormData(data)
      toast({ title: 'SMS settings saved', description: 'Configuration will take effect within 30 seconds.' })
    },
    onError: (error: Error) => {
      toast({ title: 'Error', description: error.message || 'Failed to save SMS settings.', variant: 'destructive' })
    },
  })

  const testSMSMutation = useMutation({
    mutationFn: (req: { phone_number: string; settings: SMSSettings }) =>
      api.post<{ success: boolean; message: string }>('/api/v1/settings/sms/test', req),
    onSuccess: () => {
      toast({ title: 'Test SMS sent', description: 'Check the target phone for the message.' })
    },
    onError: (error: Error) => {
      toast({ title: 'Test failed', description: error.message || 'Failed to send test SMS.', variant: 'destructive' })
    },
  })

  const handleSave = () => {
    if (activeTab === 'sms' && smsFormData) {
      updateSMSMutation.mutate(smsFormData)
    } else if (formData) {
      updateMutation.mutate(formData)
    }
  }

  const isSaving = activeTab === 'sms' ? updateSMSMutation.isPending : updateMutation.isPending

  const updateGeneral = (field: keyof Settings['general'], value: string) => {
    if (formData) {
      setFormData({
        ...formData,
        general: { ...formData.general, [field]: value }
      })
    }
  }

  const updateSecurity = (field: keyof Settings['security'], value: number | boolean | string) => {
    if (formData) {
      setFormData({
        ...formData,
        security: { ...formData.security, [field]: value }
      })
    }
  }

  const updatePasswordPolicy = (field: keyof Settings['security']['password_policy'], value: number | boolean) => {
    if (formData) {
      setFormData({
        ...formData,
        security: {
          ...formData.security,
          password_policy: { ...formData.security.password_policy, [field]: value }
        }
      })
    }
  }

  const updateAuthentication = (field: keyof Settings['authentication'], value: boolean | string[]) => {
    if (formData) {
      setFormData({
        ...formData,
        authentication: { ...formData.authentication, [field]: value }
      })
    }
  }

  const updateBranding = (field: keyof Settings['branding'], value: string) => {
    if (formData) {
      setFormData({
        ...formData,
        branding: { ...formData.branding, [field]: value }
      })
    }
  }

  if (isError) {
    return (
      <div className="space-y-6">
        <h1 className="text-3xl font-bold tracking-tight">Settings</h1>
        <QueryError error={error} resource="settings" />
      </div>
    )
  }

  if (isLoading || !formData) {
    return (
      <div className="space-y-6">
        <h1 className="text-3xl font-bold tracking-tight">Settings</h1>
        <p className="text-center py-8">Loading settings...</p>
      </div>
    )
  }

  const tabs = [
    { id: 'general', label: 'General', icon: Building },
    { id: 'security', label: 'Security', icon: Shield },
    { id: 'authentication', label: 'Authentication', icon: Key },
    { id: 'sms', label: 'SMS / OTP', icon: Smartphone },
    { id: 'branding', label: 'Branding', icon: Palette },
  ] as const

  const currentProvider = SMS_PROVIDERS.find(p => p.id === smsFormData?.provider) || SMS_PROVIDERS[0]

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Settings</h1>
          <p className="text-muted-foreground">Configure system settings</p>
        </div>
        <Button onClick={handleSave} disabled={isSaving}>
          <Save className="mr-2 h-4 w-4" />
          {isSaving ? 'Saving...' : 'Save Changes'}
        </Button>
      </div>

      <div className="flex gap-6">
        <div className="w-48 space-y-1">
          {tabs.map(tab => (
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

        <div className="flex-1">
          {activeTab === 'general' && (
            <Card>
              <CardHeader>
                <CardTitle>General Settings</CardTitle>
                <CardDescription>Basic organization and system configuration</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid gap-4 md:grid-cols-2">
                  <div className="space-y-2">
                    <label className="text-sm font-medium">Organization Name</label>
                    <Input
                      value={formData.general.organization_name}
                      onChange={(e) => updateGeneral('organization_name', e.target.value)}
                    />
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm font-medium">Support Email</label>
                    <Input
                      type="email"
                      value={formData.general.support_email}
                      onChange={(e) => updateGeneral('support_email', e.target.value)}
                    />
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm font-medium">Default Language</label>
                    <select
                      value={formData.general.default_language}
                      onChange={(e) => updateGeneral('default_language', e.target.value)}
                      className="w-full border rounded-md px-3 py-2"
                    >
                      <option value="en">English</option>
                      <option value="es">Spanish</option>
                      <option value="fr">French</option>
                      <option value="de">German</option>
                      <option value="tr">Turkish</option>
                    </select>
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm font-medium">Default Timezone</label>
                    <select
                      value={formData.general.default_timezone}
                      onChange={(e) => updateGeneral('default_timezone', e.target.value)}
                      className="w-full border rounded-md px-3 py-2"
                    >
                      <option value="UTC">UTC</option>
                      <option value="America/New_York">Eastern Time</option>
                      <option value="America/Chicago">Central Time</option>
                      <option value="America/Denver">Mountain Time</option>
                      <option value="America/Los_Angeles">Pacific Time</option>
                      <option value="Europe/Istanbul">Turkey (Istanbul)</option>
                      <option value="Europe/London">London</option>
                      <option value="Europe/Berlin">Berlin</option>
                    </select>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {activeTab === 'security' && (
            <div className="space-y-6">
              <Card>
                <CardHeader>
                  <CardTitle>Password Policy</CardTitle>
                  <CardDescription>Configure password requirements</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid gap-4 md:grid-cols-2">
                    <div className="space-y-2">
                      <label className="text-sm font-medium">Minimum Length</label>
                      <Input
                        type="number"
                        min={8}
                        max={32}
                        value={formData.security.password_policy.min_length}
                        onChange={(e) => updatePasswordPolicy('min_length', parseInt(e.target.value))}
                      />
                    </div>
                    <div className="space-y-2">
                      <label className="text-sm font-medium">Password Max Age (days)</label>
                      <Input
                        type="number"
                        min={0}
                        max={365}
                        value={formData.security.password_policy.max_age}
                        onChange={(e) => updatePasswordPolicy('max_age', parseInt(e.target.value))}
                      />
                    </div>
                    <div className="space-y-2">
                      <label className="text-sm font-medium">Password History</label>
                      <Input
                        type="number"
                        min={0}
                        max={24}
                        value={formData.security.password_policy.history}
                        onChange={(e) => updatePasswordPolicy('history', parseInt(e.target.value))}
                      />
                    </div>
                  </div>
                  <div className="grid gap-4 md:grid-cols-2">
                    <label className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={formData.security.password_policy.require_uppercase}
                        onChange={(e) => updatePasswordPolicy('require_uppercase', e.target.checked)}
                        className="rounded"
                      />
                      <span className="text-sm">Require Uppercase</span>
                    </label>
                    <label className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={formData.security.password_policy.require_lowercase}
                        onChange={(e) => updatePasswordPolicy('require_lowercase', e.target.checked)}
                        className="rounded"
                      />
                      <span className="text-sm">Require Lowercase</span>
                    </label>
                    <label className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={formData.security.password_policy.require_numbers}
                        onChange={(e) => updatePasswordPolicy('require_numbers', e.target.checked)}
                        className="rounded"
                      />
                      <span className="text-sm">Require Numbers</span>
                    </label>
                    <label className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={formData.security.password_policy.require_special}
                        onChange={(e) => updatePasswordPolicy('require_special', e.target.checked)}
                        className="rounded"
                      />
                      <span className="text-sm">Require Special Characters</span>
                    </label>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Session & Lockout</CardTitle>
                  <CardDescription>Configure session and lockout policies</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid gap-4 md:grid-cols-3">
                    <div className="space-y-2">
                      <label className="text-sm font-medium">Session Timeout (minutes)</label>
                      <Input
                        type="number"
                        min={5}
                        max={1440}
                        value={formData.security.session_timeout}
                        onChange={(e) => updateSecurity('session_timeout', parseInt(e.target.value))}
                      />
                    </div>
                    <div className="space-y-2">
                      <label className="text-sm font-medium">Max Failed Logins</label>
                      <Input
                        type="number"
                        min={1}
                        max={20}
                        value={formData.security.max_failed_logins}
                        onChange={(e) => updateSecurity('max_failed_logins', parseInt(e.target.value))}
                      />
                    </div>
                    <div className="space-y-2">
                      <label className="text-sm font-medium">Lockout Duration (minutes)</label>
                      <Input
                        type="number"
                        min={1}
                        max={1440}
                        value={formData.security.lockout_duration}
                        onChange={(e) => updateSecurity('lockout_duration', parseInt(e.target.value))}
                      />
                    </div>
                  </div>
                  <label className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={formData.security.require_mfa}
                      onChange={(e) => updateSecurity('require_mfa', e.target.checked)}
                      className="rounded"
                    />
                    <span className="text-sm font-medium">Require MFA for all users</span>
                  </label>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Session Policies</CardTitle>
                  <CardDescription>Configure advanced session management policies</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid gap-4 md:grid-cols-3">
                    <div className="space-y-2">
                      <label className="text-sm font-medium">Idle Timeout (seconds)</label>
                      <Input
                        type="number"
                        min={0}
                        max={86400}
                        value={formData.security.idle_timeout ?? 1800}
                        onChange={(e) => updateSecurity('idle_timeout', parseInt(e.target.value) || 0)}
                      />
                      <p className="text-xs text-muted-foreground">0 = disabled. Default: 1800 (30 min)</p>
                    </div>
                    <div className="space-y-2">
                      <label className="text-sm font-medium">Absolute Timeout (seconds)</label>
                      <Input
                        type="number"
                        min={0}
                        max={604800}
                        value={formData.security.absolute_timeout ?? 86400}
                        onChange={(e) => updateSecurity('absolute_timeout', parseInt(e.target.value) || 0)}
                      />
                      <p className="text-xs text-muted-foreground">0 = disabled. Default: 86400 (24h)</p>
                    </div>
                    <div className="space-y-2">
                      <label className="text-sm font-medium">Remember Me Duration (seconds)</label>
                      <Input
                        type="number"
                        min={0}
                        max={7776000}
                        value={formData.security.remember_me_duration ?? 2592000}
                        onChange={(e) => updateSecurity('remember_me_duration', parseInt(e.target.value) || 0)}
                      />
                      <p className="text-xs text-muted-foreground">Default: 2592000 (30 days)</p>
                    </div>
                  </div>
                  <div className="grid gap-4 md:grid-cols-2">
                    <div className="space-y-2">
                      <label className="text-sm font-medium">Max Concurrent Sessions</label>
                      <Input
                        type="number"
                        min={0}
                        max={100}
                        value={formData.security.max_concurrent_sessions ?? 0}
                        onChange={(e) => updateSecurity('max_concurrent_sessions', parseInt(e.target.value) || 0)}
                      />
                      <p className="text-xs text-muted-foreground">0 = unlimited</p>
                    </div>
                    <div className="space-y-2">
                      <label className="text-sm font-medium">Concurrent Session Strategy</label>
                      <select
                        className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                        value={formData.security.concurrent_session_strategy ?? 'deny_new'}
                        onChange={(e) => updateSecurity('concurrent_session_strategy', e.target.value)}
                      >
                        <option value="deny_new">Deny New Login</option>
                        <option value="terminate_oldest">Terminate Oldest Session</option>
                        <option value="prompt_user">Ask User to Choose</option>
                      </select>
                    </div>
                  </div>
                  <div className="space-y-3">
                    <label className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={formData.security.bind_session_to_ip ?? false}
                        onChange={(e) => updateSecurity('bind_session_to_ip', e.target.checked)}
                        className="rounded"
                      />
                      <span className="text-sm font-medium">Bind sessions to IP address</span>
                    </label>
                    <label className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={formData.security.force_logout_on_password_change ?? true}
                        onChange={(e) => updateSecurity('force_logout_on_password_change', e.target.checked)}
                        className="rounded"
                      />
                      <span className="text-sm font-medium">Force logout on password change</span>
                    </label>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Country-Based Access Control</CardTitle>
                  <CardDescription>Block login attempts from specific countries (ISO 3166-1 alpha-2 codes)</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-2">
                    <label className="text-sm font-medium">Blocked Countries</label>
                    <div className="flex gap-2">
                      <Input
                        placeholder="e.g. CN, RU, KP"
                        value={newCountry}
                        onChange={(e) => setNewCountry(e.target.value.toUpperCase().slice(0, 2))}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') {
                            e.preventDefault()
                            if (newCountry.length === 2 && !formData.security.blocked_countries?.includes(newCountry)) {
                              setFormData({
                                ...formData,
                                security: {
                                  ...formData.security,
                                  blocked_countries: [...(formData.security.blocked_countries || []), newCountry],
                                },
                              })
                              setNewCountry('')
                            }
                          }
                        }}
                        className="w-32"
                      />
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => {
                          if (newCountry.length === 2 && !formData.security.blocked_countries?.includes(newCountry)) {
                            setFormData({
                              ...formData,
                              security: {
                                ...formData.security,
                                blocked_countries: [...(formData.security.blocked_countries || []), newCountry],
                              },
                            })
                            setNewCountry('')
                          }
                        }}
                      >
                        <Plus className="h-4 w-4" />
                      </Button>
                    </div>
                    <div className="flex flex-wrap gap-2 mt-2">
                      {(formData.security.blocked_countries || []).map((country) => (
                        <div
                          key={country}
                          className="flex items-center gap-1 bg-red-50 border border-red-200 px-2 py-1 rounded text-sm text-red-700"
                        >
                          <span>{country}</span>
                          <button
                            onClick={() => {
                              setFormData({
                                ...formData,
                                security: {
                                  ...formData.security,
                                  blocked_countries: formData.security.blocked_countries.filter((c) => c !== country),
                                },
                              })
                            }}
                            className="text-red-400 hover:text-red-600"
                          >
                            <X className="h-3 w-3" />
                          </button>
                        </div>
                      ))}
                    </div>
                    {(!formData.security.blocked_countries || formData.security.blocked_countries.length === 0) && (
                      <p className="text-xs text-muted-foreground">No countries blocked. Users can log in from any location.</p>
                    )}
                  </div>
                </CardContent>
              </Card>
            </div>
          )}

          {activeTab === 'authentication' && (
            <div className="space-y-6">
              <Card>
                <CardHeader>
                  <CardTitle>Authentication Settings</CardTitle>
                  <CardDescription>Configure authentication methods and restrictions</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-4">
                    <label className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={formData.authentication.allow_registration}
                        onChange={(e) => updateAuthentication('allow_registration', e.target.checked)}
                        className="rounded"
                      />
                      <span className="text-sm font-medium">Allow Self Registration</span>
                    </label>
                    <label className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={formData.authentication.require_email_verify}
                        onChange={(e) => updateAuthentication('require_email_verify', e.target.checked)}
                        className="rounded"
                      />
                      <span className="text-sm font-medium">Require Email Verification</span>
                    </label>
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm font-medium">MFA Methods</label>
                    <div className="flex gap-4">
                      {['totp', 'webauthn', 'sms'].map(method => (
                        <label key={method} className="flex items-center gap-2">
                          <input
                            type="checkbox"
                            checked={formData.authentication.mfa_methods.includes(method)}
                            onChange={(e) => {
                              const methods = e.target.checked
                                ? [...formData.authentication.mfa_methods, method]
                                : formData.authentication.mfa_methods.filter(m => m !== method)
                              updateAuthentication('mfa_methods', methods)
                            }}
                            className="rounded"
                          />
                          <span className="text-sm uppercase">{method}</span>
                        </label>
                      ))}
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Allowed Domains</CardTitle>
                  <CardDescription>Restrict registration to specific email domains</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="flex gap-2">
                    <Input
                      value={newDomain}
                      onChange={(e) => setNewDomain(e.target.value)}
                      placeholder="e.g., example.com"
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') {
                          e.preventDefault()
                          const domain = newDomain.trim().toLowerCase()
                          if (domain && !formData.authentication.allowed_domains.includes(domain)) {
                            updateAuthentication('allowed_domains', [...formData.authentication.allowed_domains, domain])
                            setNewDomain('')
                          }
                        }
                      }}
                    />
                    <Button
                      type="button"
                      variant="outline"
                      onClick={() => {
                        const domain = newDomain.trim().toLowerCase()
                        if (domain && !formData.authentication.allowed_domains.includes(domain)) {
                          updateAuthentication('allowed_domains', [...formData.authentication.allowed_domains, domain])
                          setNewDomain('')
                        }
                      }}
                    >
                      <Plus className="h-4 w-4 mr-1" /> Add
                    </Button>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {(formData.authentication.allowed_domains || []).length === 0 ? (
                      <p className="text-sm text-gray-500">No domain restrictions. All domains are allowed.</p>
                    ) : (
                      formData.authentication.allowed_domains.map(domain => (
                        <span
                          key={domain}
                          className="inline-flex items-center gap-1 px-3 py-1 rounded-full bg-blue-100 text-blue-800 text-sm"
                        >
                          {domain}
                          <button
                            type="button"
                            onClick={() => updateAuthentication('allowed_domains', formData.authentication.allowed_domains.filter(d => d !== domain))}
                            className="hover:text-blue-600"
                          >
                            <X className="h-3 w-3" />
                          </button>
                        </span>
                      ))
                    )}
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Social Providers</CardTitle>
                  <CardDescription>Enable social login providers for user authentication</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="grid gap-3 md:grid-cols-2">
                    {[
                      { id: 'google', label: 'Google' },
                      { id: 'github', label: 'GitHub' },
                      { id: 'microsoft', label: 'Microsoft' },
                      { id: 'apple', label: 'Apple' },
                      { id: 'facebook', label: 'Facebook' },
                    ].map(provider => (
                      <label key={provider.id} className="flex items-center gap-3 p-3 border rounded-lg hover:bg-gray-50 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={(formData.authentication.social_providers || []).includes(provider.id)}
                          onChange={(e) => {
                            const providers = e.target.checked
                              ? [...(formData.authentication.social_providers || []), provider.id]
                              : (formData.authentication.social_providers || []).filter(p => p !== provider.id)
                            updateAuthentication('social_providers', providers)
                          }}
                          className="rounded h-4 w-4"
                        />
                        <span className="text-sm font-medium">{provider.label}</span>
                      </label>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>
          )}

          {activeTab === 'sms' && smsFormData && (
            <div className="space-y-6">
              <Card>
                <CardHeader>
                  <CardTitle>SMS Provider</CardTitle>
                  <CardDescription>Configure the SMS gateway for OTP delivery</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <label className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={smsFormData.enabled}
                      onChange={(e) => setSmsFormData({ ...smsFormData, enabled: e.target.checked })}
                      className="rounded"
                    />
                    <span className="text-sm font-medium">Enable SMS OTP delivery</span>
                  </label>

                  <div className="space-y-2">
                    <label className="text-sm font-medium">Provider</label>
                    <select
                      value={smsFormData.provider}
                      onChange={(e) => setSmsFormData({
                        ...smsFormData,
                        provider: e.target.value,
                        credentials: {},
                      })}
                      className="w-full border rounded-md px-3 py-2"
                    >
                      {SMS_PROVIDERS.map(p => (
                        <option key={p.id} value={p.id}>{p.label}</option>
                      ))}
                    </select>
                  </div>

                  <div className="space-y-2">
                    <label className="text-sm font-medium">Message Prefix</label>
                    <Input
                      value={smsFormData.message_prefix}
                      onChange={(e) => setSmsFormData({ ...smsFormData, message_prefix: e.target.value })}
                      placeholder="OpenIDX"
                    />
                    <p className="text-xs text-muted-foreground">Appears at the start of OTP messages, e.g. &quot;OpenIDX: Your code is 123456&quot;</p>
                  </div>

                  {currentProvider.fields.length > 0 && (
                    <div className="border-t pt-4 mt-4">
                      <h4 className="text-sm font-medium mb-3">{currentProvider.label} Credentials</h4>
                      <div className="grid gap-4 md:grid-cols-2">
                        {currentProvider.fields.map(field => (
                          <div key={field.key} className="space-y-2">
                            <label className="text-sm font-medium">{field.label}</label>
                            <Input
                              type={field.sensitive ? 'password' : 'text'}
                              value={smsFormData.credentials[field.key] || ''}
                              placeholder={field.sensitive ? 'Enter new value to change' : field.placeholder || ''}
                              onChange={(e) => setSmsFormData({
                                ...smsFormData,
                                credentials: { ...smsFormData.credentials, [field.key]: e.target.value },
                              })}
                            />
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>OTP Settings</CardTitle>
                  <CardDescription>Configure one-time password behavior</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="grid gap-4 md:grid-cols-3">
                    <div className="space-y-2">
                      <label className="text-sm font-medium">Code Length</label>
                      <select
                        value={smsFormData.otp_length}
                        onChange={(e) => setSmsFormData({ ...smsFormData, otp_length: parseInt(e.target.value) })}
                        className="w-full border rounded-md px-3 py-2"
                      >
                        <option value={4}>4 digits</option>
                        <option value={6}>6 digits</option>
                        <option value={8}>8 digits</option>
                      </select>
                    </div>
                    <div className="space-y-2">
                      <label className="text-sm font-medium">Expiry (seconds)</label>
                      <Input
                        type="number"
                        min={60}
                        max={600}
                        value={smsFormData.otp_expiry}
                        onChange={(e) => setSmsFormData({ ...smsFormData, otp_expiry: parseInt(e.target.value) || 300 })}
                      />
                      <p className="text-xs text-muted-foreground">{Math.floor(smsFormData.otp_expiry / 60)}m {smsFormData.otp_expiry % 60}s</p>
                    </div>
                    <div className="space-y-2">
                      <label className="text-sm font-medium">Max Attempts</label>
                      <Input
                        type="number"
                        min={1}
                        max={10}
                        value={smsFormData.max_attempts}
                        onChange={(e) => setSmsFormData({ ...smsFormData, max_attempts: parseInt(e.target.value) || 3 })}
                      />
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Test SMS</CardTitle>
                  <CardDescription>Send a test message to verify your configuration works</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="flex gap-2">
                    <Input
                      value={testPhone}
                      onChange={(e) => setTestPhone(e.target.value)}
                      placeholder="+905551234567"
                      className="max-w-xs"
                    />
                    <Button
                      variant="outline"
                      onClick={() => {
                        if (testPhone && smsFormData) {
                          testSMSMutation.mutate({ phone_number: testPhone, settings: smsFormData })
                        }
                      }}
                      disabled={testSMSMutation.isPending || !testPhone}
                    >
                      <Send className="mr-2 h-4 w-4" />
                      {testSMSMutation.isPending ? 'Sending...' : 'Send Test SMS'}
                    </Button>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Save your settings first, then send a test to verify the provider is configured correctly.
                  </p>
                </CardContent>
              </Card>
            </div>
          )}

          {activeTab === 'sms' && !smsFormData && (
            <p className="text-center py-8">Loading SMS settings...</p>
          )}

          {activeTab === 'branding' && (
            <Card>
              <CardHeader>
                <CardTitle>Branding Settings</CardTitle>
                <CardDescription>Customize the look and feel of the login page</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid gap-4 md:grid-cols-2">
                  <div className="space-y-2">
                    <label className="text-sm font-medium">Logo URL</label>
                    <Input
                      value={formData.branding.logo_url}
                      onChange={(e) => updateBranding('logo_url', e.target.value)}
                      placeholder="https://example.com/logo.png"
                    />
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm font-medium">Favicon URL</label>
                    <Input
                      value={formData.branding.favicon_url}
                      onChange={(e) => updateBranding('favicon_url', e.target.value)}
                      placeholder="https://example.com/favicon.ico"
                    />
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm font-medium">Primary Color</label>
                    <div className="flex gap-2">
                      <input
                        type="color"
                        value={formData.branding.primary_color}
                        onChange={(e) => updateBranding('primary_color', e.target.value)}
                        className="h-10 w-14 rounded border cursor-pointer"
                      />
                      <Input
                        value={formData.branding.primary_color}
                        onChange={(e) => updateBranding('primary_color', e.target.value)}
                      />
                    </div>
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm font-medium">Secondary Color</label>
                    <div className="flex gap-2">
                      <input
                        type="color"
                        value={formData.branding.secondary_color}
                        onChange={(e) => updateBranding('secondary_color', e.target.value)}
                        className="h-10 w-14 rounded border cursor-pointer"
                      />
                      <Input
                        value={formData.branding.secondary_color}
                        onChange={(e) => updateBranding('secondary_color', e.target.value)}
                      />
                    </div>
                  </div>
                </div>
                <div className="space-y-2">
                  <label className="text-sm font-medium">Login Page Title</label>
                  <Input
                    value={formData.branding.login_page_title}
                    onChange={(e) => updateBranding('login_page_title', e.target.value)}
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-sm font-medium">Login Page Message</label>
                  <textarea
                    value={formData.branding.login_page_message}
                    onChange={(e) => updateBranding('login_page_message', e.target.value)}
                    className="w-full border rounded-md px-3 py-2 min-h-[80px]"
                  />
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  )
}
