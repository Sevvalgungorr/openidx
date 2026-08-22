import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link2, QrCode, Mail, Shield, Settings2, Users, CheckCircle2, XCircle } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Switch } from '../components/ui/switch'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogDescription,
} from '../components/ui/dialog'
import { Label } from '../components/ui/label'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'
import { QueryError } from '../components/query-error'

interface PasswordlessSettings {
  magic_link_enabled: boolean
  magic_link_expiry_minutes: number
  qr_login_enabled: boolean
  qr_session_expiry_minutes: number
  biometric_only_enabled: boolean
  allowed_domains: string[]
  require_device_trust: boolean
  max_magic_links_per_hour: number
}

interface PasswordlessStats {
  magic_links_today: number
  qr_logins_today: number
  biometric_only_users: number
  passwordless_adoption_rate: number
}

export function PasswordlessSettingsPage() {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [editDialog, setEditDialog] = useState(false)
  const [testMagicLinkDialog, setTestMagicLinkDialog] = useState(false)
  const [testEmail, setTestEmail] = useState('')

  // Fetch settings
  const { data: settingsData, isLoading: settingsLoading, isError: settingsError, error: settingsErrorObj } = useQuery({
    queryKey: ['passwordless-settings'],
    queryFn: async () => {
      return api.get<{ settings: PasswordlessSettings }>('/api/v1/identity/passwordless/settings')
    }
  })

  // Fall back to an all-DISABLED posture (never a fake "enabled" one) so that
  // if the settings ever fail to load we do not paint features as turned on.
  // On a real load error we render <QueryError> below instead of any toggles.
  const settings: PasswordlessSettings = settingsData?.settings || {
    magic_link_enabled: false,
    magic_link_expiry_minutes: 15,
    qr_login_enabled: false,
    qr_session_expiry_minutes: 5,
    biometric_only_enabled: false,
    allowed_domains: [],
    require_device_trust: false,
    max_magic_links_per_hour: 5
  }

  // Fetch stats
  const { data: statsData } = useQuery({
    queryKey: ['passwordless-stats'],
    queryFn: async () => {
      return api.get<{ stats: PasswordlessStats }>('/api/v1/identity/passwordless/stats')
    }
  })

  const stats: PasswordlessStats = statsData?.stats || {
    magic_links_today: 0,
    qr_logins_today: 0,
    biometric_only_users: 0,
    passwordless_adoption_rate: 0
  }

  // Form state
  const [editSettings, setEditSettings] = useState<PasswordlessSettings>(settings)

  // Mutations
  const updateSettingsMutation = useMutation({
    mutationFn: (data: PasswordlessSettings) =>
      api.put('/api/v1/identity/passwordless/settings', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['passwordless-settings'] })
      toast({ title: 'Settings Updated', description: 'Passwordless settings have been saved.' })
      setEditDialog(false)
    },
    onError: (error: Error) => {
      toast({ title: 'Error', description: error.message, variant: 'destructive' })
    }
  })

  const sendTestMagicLinkMutation = useMutation({
    mutationFn: (email: string) =>
      api.post('/api/v1/identity/passwordless/magic-link/test', { email }),
    onSuccess: () => {
      toast({ title: 'Test Sent', description: 'Test magic link has been sent.' })
      setTestMagicLinkDialog(false)
      setTestEmail('')
    },
    onError: (error: Error) => {
      toast({ title: 'Error', description: error.message, variant: 'destructive' })
    }
  })

  const toggleSettingMutation = useMutation({
    mutationFn: ({ key, value }: { key: keyof PasswordlessSettings; value: boolean }) =>
      api.patch('/api/v1/identity/passwordless/settings', { [key]: value }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['passwordless-settings'] })
    }
  })

  const openEditDialog = () => {
    setEditSettings(settings)
    setEditDialog(true)
  }

  if (settingsLoading) {
    return (
      <div className="flex justify-center py-12">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  // Do not render any toggle state until real settings load. Surfacing the error
  // (vs. showing default-on toggles) avoids painting a fake security posture.
  if (settingsError) {
    return <QueryError error={settingsErrorObj} resource="passwordless settings" />
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Passwordless Authentication</h1>
          <p className="text-muted-foreground">Configure magic links, QR login, and biometric-only access</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => setTestMagicLinkDialog(true)}>
            <Mail className="h-4 w-4 mr-2" />
            Test Magic Link
          </Button>
          <Button onClick={openEditDialog}>
            <Settings2 className="h-4 w-4 mr-2" />
            Edit Settings
          </Button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Magic Links Today</CardTitle>
            <Mail className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.magic_links_today}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">QR Logins Today</CardTitle>
            <QrCode className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.qr_logins_today}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Biometric-Only Users</CardTitle>
            <Users className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.biometric_only_users}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Adoption Rate</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.passwordless_adoption_rate}%</div>
          </CardContent>
        </Card>
      </div>

      {/* Feature Cards */}
      <div className="grid gap-6 md:grid-cols-3">
        {/* Magic Links */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Link2 className="h-5 w-5 text-primary" />
                <CardTitle>Magic Links</CardTitle>
              </div>
              <Switch
                checked={settings.magic_link_enabled}
                onCheckedChange={(checked) =>
                  toggleSettingMutation.mutate({ key: 'magic_link_enabled', value: checked })
                }
              />
            </div>
            <CardDescription>Email-based passwordless login</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">Status</span>
              {settings.magic_link_enabled ? (
                <Badge className="bg-green-100 text-green-800">
                  <CheckCircle2 className="h-3 w-3 mr-1" />Enabled
                </Badge>
              ) : (
                <Badge variant="secondary">
                  <XCircle className="h-3 w-3 mr-1" />Disabled
                </Badge>
              )}
            </div>
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">Link Expiry</span>
              <span>{settings.magic_link_expiry_minutes} minutes</span>
            </div>
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">Rate Limit</span>
              <span>{settings.max_magic_links_per_hour}/hour</span>
            </div>
          </CardContent>
        </Card>

        {/* QR Code Login */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <QrCode className="h-5 w-5 text-purple-600" />
                <CardTitle>QR Code Login</CardTitle>
              </div>
              <Switch
                checked={settings.qr_login_enabled}
                onCheckedChange={(checked) =>
                  toggleSettingMutation.mutate({ key: 'qr_login_enabled', value: checked })
                }
              />
            </div>
            <CardDescription>Scan QR code from mobile app</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">Status</span>
              {settings.qr_login_enabled ? (
                <Badge className="bg-green-100 text-green-800">
                  <CheckCircle2 className="h-3 w-3 mr-1" />Enabled
                </Badge>
              ) : (
                <Badge variant="secondary">
                  <XCircle className="h-3 w-3 mr-1" />Disabled
                </Badge>
              )}
            </div>
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">Session Expiry</span>
              <span>{settings.qr_session_expiry_minutes} minutes</span>
            </div>
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">Device Trust Required</span>
              <span>{settings.require_device_trust ? 'Yes' : 'No'}</span>
            </div>
          </CardContent>
        </Card>

        {/* Biometric Only */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Shield className="h-5 w-5 text-green-600" />
                <CardTitle>Biometric Only</CardTitle>
              </div>
              <Switch
                checked={settings.biometric_only_enabled}
                onCheckedChange={(checked) =>
                  toggleSettingMutation.mutate({ key: 'biometric_only_enabled', value: checked })
                }
              />
            </div>
            <CardDescription>WebAuthn-only login for users</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">Status</span>
              {settings.biometric_only_enabled ? (
                <Badge className="bg-green-100 text-green-800">
                  <CheckCircle2 className="h-3 w-3 mr-1" />Enabled
                </Badge>
              ) : (
                <Badge variant="secondary">
                  <XCircle className="h-3 w-3 mr-1" />Disabled
                </Badge>
              )}
            </div>
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">Enrolled Users</span>
              <span>{stats.biometric_only_users}</span>
            </div>
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">Requires WebAuthn</span>
              <span>Yes</span>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* How It Works */}
      <Card>
        <CardHeader>
          <CardTitle>How Passwordless Works</CardTitle>
          <CardDescription>Understanding the different passwordless authentication methods</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-6 md:grid-cols-3">
            <div className="space-y-2">
              <div className="flex items-center gap-2 text-primary">
                <Link2 className="h-5 w-5" />
                <h4 className="font-medium">Magic Links</h4>
              </div>
              <ol className="text-sm text-muted-foreground space-y-1 list-decimal list-inside">
                <li>User enters email on login page</li>
                <li>Receives email with secure link</li>
                <li>Clicks link to authenticate</li>
                <li>Session created automatically</li>
              </ol>
            </div>
            <div className="space-y-2">
              <div className="flex items-center gap-2 text-purple-600">
                <QrCode className="h-5 w-5" />
                <h4 className="font-medium">QR Code Login</h4>
              </div>
              <ol className="text-sm text-muted-foreground space-y-1 list-decimal list-inside">
                <li>QR code displayed on login page</li>
                <li>User scans with mobile app</li>
                <li>Approves login on phone</li>
                <li>Browser session activated</li>
              </ol>
            </div>
            <div className="space-y-2">
              <div className="flex items-center gap-2 text-green-600">
                <Shield className="h-5 w-5" />
                <h4 className="font-medium">Biometric Only</h4>
              </div>
              <ol className="text-sm text-muted-foreground space-y-1 list-decimal list-inside">
                <li>User registers WebAuthn credential</li>
                <li>Enables biometric-only mode</li>
                <li>Login uses Face ID/Touch ID</li>
                <li>Password completely bypassed</li>
              </ol>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Edit Settings Dialog */}
      <Dialog open={editDialog} onOpenChange={setEditDialog}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Edit Passwordless Settings</DialogTitle>
            <DialogDescription>Configure passwordless authentication options</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Magic Link Expiry (minutes)</Label>
              <Input
                type="number"
                value={editSettings.magic_link_expiry_minutes}
                onChange={(e) => setEditSettings({
                  ...editSettings,
                  magic_link_expiry_minutes: parseInt(e.target.value) || 15
                })}
                min={5}
                max={60}
              />
              <p className="text-xs text-muted-foreground">How long magic links remain valid (5-60 minutes)</p>
            </div>

            <div className="space-y-2">
              <Label>QR Session Expiry (minutes)</Label>
              <Input
                type="number"
                value={editSettings.qr_session_expiry_minutes}
                onChange={(e) => setEditSettings({
                  ...editSettings,
                  qr_session_expiry_minutes: parseInt(e.target.value) || 5
                })}
                min={1}
                max={15}
              />
              <p className="text-xs text-muted-foreground">How long QR login sessions remain valid (1-15 minutes)</p>
            </div>

            <div className="space-y-2">
              <Label>Max Magic Links Per Hour</Label>
              <Input
                type="number"
                value={editSettings.max_magic_links_per_hour}
                onChange={(e) => setEditSettings({
                  ...editSettings,
                  max_magic_links_per_hour: parseInt(e.target.value) || 5
                })}
                min={1}
                max={20}
              />
              <p className="text-xs text-muted-foreground">Rate limit for magic link requests per user</p>
            </div>

            <div className="flex items-center justify-between">
              <div>
                <Label>Require Device Trust for QR Login</Label>
                <p className="text-xs text-muted-foreground">Only allow QR login from trusted devices</p>
              </div>
              <Switch
                checked={editSettings.require_device_trust}
                onCheckedChange={(checked) => setEditSettings({
                  ...editSettings,
                  require_device_trust: checked
                })}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditDialog(false)}>Cancel</Button>
            <Button onClick={() => updateSettingsMutation.mutate(editSettings)}>
              Save Settings
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Test Magic Link Dialog */}
      <Dialog open={testMagicLinkDialog} onOpenChange={setTestMagicLinkDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Send Test Magic Link</DialogTitle>
            <DialogDescription>Send a test magic link to verify email delivery</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Email Address</Label>
              <Input
                type="email"
                value={testEmail}
                onChange={(e) => setTestEmail(e.target.value)}
                placeholder="user@example.com"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setTestMagicLinkDialog(false)}>Cancel</Button>
            <Button
              onClick={() => sendTestMagicLinkMutation.mutate(testEmail)}
              disabled={!testEmail}
            >
              <Mail className="h-4 w-4 mr-2" />
              Send Test
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
