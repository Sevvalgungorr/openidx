import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Label } from '../components/ui/label'
import { Switch } from '../components/ui/switch'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs'
import { Badge } from '../components/ui/badge'
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from '../components/ui/alert-dialog'
import { useToast } from '../hooks/use-toast'
import { api, UserProfile, MFASetupResponse, MFAEnableResponse } from '../lib/api'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { Checkbox } from '../components/ui/checkbox'
import { Shield, User, Key, Smartphone, Mail, Monitor, Phone, Globe, Trash2, Check, Plus, Copy, KeyRound, AppWindow, AlertTriangle } from 'lucide-react'
import { QRCodeSVG } from 'qrcode.react'

interface MFAMethod {
  method: string
  enabled: boolean
  verified: boolean
  enrolled_at?: string
}

interface TrustedBrowser {
  id: string
  name: string
  ip_address: string
  trusted_at: string
  expires_at: string
  last_used_at?: string
  revoked: boolean
  active: boolean
}

interface MFASetup extends MFASetupResponse {
  backupCodes: string[]
}

interface Session {
  id: string
  user_id: string
  client_id: string
  ip_address: string
  user_agent: string
  started_at: string
  last_seen_at: string
  expires_at: string
}

interface PersonalAccessToken {
  id: string
  name: string
  key_prefix: string
  scopes: string[]
  expires_at: string | null
  last_used_at: string | null
  status: string
  created_at: string
}

interface CreateTokenResponse {
  token: PersonalAccessToken
  raw_token: string
}

interface UserConsent {
  client_id: string
  client_name: string
  logo_uri?: string
  scopes: string[]
  authorized_at: string
  last_used_at: string
}

export function UserProfilePage() {
  const [firstName, setFirstName] = useState('')
  const [lastName, setLastName] = useState('')
  const [email, setEmail] = useState('')
  const [profileLoaded, setProfileLoaded] = useState(false)
  const [mfaSetup, setMfaSetup] = useState<MFASetup | null>(null)
  const [showBackupCodes, setShowBackupCodes] = useState(false)
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [mfaCode, setMfaCode] = useState('')

  // SMS MFA state
  const [smsEnrollStep, setSmsEnrollStep] = useState<'idle' | 'enter-phone' | 'verify'>('idle')
  const [phoneNumber, setPhoneNumber] = useState('')
  const [countryCode, setCountryCode] = useState('+1')
  const [smsVerifyCode, setSmsVerifyCode] = useState('')

  // Email OTP state
  const [emailOtpEnrollStep, setEmailOtpEnrollStep] = useState<'idle' | 'verify'>('idle')
  const [emailOtpCode, setEmailOtpCode] = useState('')

  // Access Tokens state
  const [showCreateToken, setShowCreateToken] = useState(false)
  const [newTokenName, setNewTokenName] = useState('')
  const [newTokenScopes, setNewTokenScopes] = useState<string[]>([])
  const [newTokenExpiry, setNewTokenExpiry] = useState('')
  const [createdRawToken, setCreatedRawToken] = useState<string | null>(null)

  // Authorized Apps state
  const [revokeConsentClientId, setRevokeConsentClientId] = useState<string | null>(null)

  const { toast } = useToast()
  const queryClient = useQueryClient()

  const { data: profile, isLoading, isError, error } = useQuery({
    queryKey: ['user-profile'],
    queryFn: () => api.get<UserProfile>('/api/v1/identity/users/me'),
    select: (data) => {
      if (!profileLoaded && data) {
        setFirstName(data.firstName)
        setLastName(data.lastName)
        setEmail(data.email)
        setProfileLoaded(true)
      }
      return data
    },
  })

  const updateProfileMutation = useMutation({
    mutationFn: (updates: Partial<UserProfile>) =>
      api.put<UserProfile>('/api/v1/identity/users/me', updates),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['user-profile'] })
      toast({ title: 'Success', description: 'Profile updated successfully' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to update profile', variant: 'destructive' })
    },
  })

  const setupMFAMutation = useMutation({
    mutationFn: () => api.post<MFASetupResponse>('/api/v1/identity/users/me/mfa/setup'),
    onSuccess: (response) => {
      setMfaSetup({ ...response, backupCodes: [] })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to setup MFA', variant: 'destructive' })
    },
  })

  const enableMFAMutation = useMutation({
    mutationFn: (code: string) =>
      api.post<MFAEnableResponse>('/api/v1/identity/users/me/mfa/enable', { code }),
    onSuccess: (response) => {
      queryClient.invalidateQueries({ queryKey: ['user-profile'] })
      setMfaSetup(prev => prev ? { ...prev, backupCodes: response.backupCodes || [] } : null)
      setShowBackupCodes(true)
      toast({ title: 'Success', description: 'MFA enabled successfully' })
    },
    onError: (e: unknown) => {
      // Surface the backend's real reason so the user can tell "expired setup,
      // start again" apart from "wrong code, try the next one".
      const msg = e instanceof Error ? e.message : ''
      const expired = /expired|not initiated|start setup/i.test(msg)
      toast({
        title: expired ? 'Setup expired' : 'Invalid verification code',
        description: expired
          ? 'The setup timed out. Click "Setup MFA" again, re-scan the new QR/secret, then enter a fresh code.'
          : 'That code was not accepted. Make sure your device clock is correct and enter the current 6-digit code (it changes every 30s).',
        variant: 'destructive',
      })
    },
  })

  const disableMFAMutation = useMutation({
    mutationFn: () => api.post<void>('/api/v1/identity/users/me/mfa/disable'),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['user-profile'] })
      toast({ title: 'Success', description: 'MFA disabled successfully' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to disable MFA', variant: 'destructive' })
    },
  })

  const { data: passwordInfo } = useQuery({
    queryKey: ['password-info'],
    queryFn: () => api.get<{ source: string; is_ldap: boolean; is_azure_ad: boolean; is_directory_managed: boolean; password_changed_at?: string; password_must_change: boolean }>('/api/v1/identity/users/me/password-info'),
  })

  const changePasswordMutation = useMutation({
    mutationFn: ({ currentPassword, newPassword }: { currentPassword: string; newPassword: string }) =>
      api.post<void>('/api/v1/identity/users/me/change-password', { currentPassword, newPassword }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['password-info'] })
      toast({ title: 'Success', description: passwordInfo?.is_ldap ? 'Active Directory password changed successfully' : 'Password changed successfully' })
    },
    onError: (error: Error & { response?: { data?: { error?: string } } }) => {
      const message = error?.response?.data?.error || 'Failed to change password'
      toast({ title: 'Error', description: message, variant: 'destructive' })
    },
  })

  // Use the self-service endpoint (id derived from the JWT). The admin
  // endpoint /users/:id/sessions returns 403 for non-admins, which the old
  // code silently rendered as "No active sessions".
  const { data: sessionsResp, isLoading: sessionsLoading } = useQuery({
    queryKey: ['my-sessions'],
    queryFn: () => api.get<{ sessions: Session[] }>('/api/v1/identity/users/me/sessions'),
  })
  const sessions = sessionsResp?.sessions

  // Fetch MFA methods
  const { data: mfaMethods } = useQuery({
    queryKey: ['mfa-methods'],
    queryFn: async () => {
      const response = await api.get<{ methods: Record<string, boolean>; enabled_count: number; mfa_enabled: boolean }>('/api/v1/identity/mfa/methods')
      // Transform the map response into the MFAMethod[] format the UI expects
      const methods = response?.methods || {}
      return Object.entries(methods).map(([method, enabled]) => ({
        method,
        enabled: !!enabled,
        verified: !!enabled,
      })) as MFAMethod[]
    },
  })

  // Fetch trusted browsers
  const { data: trustedBrowsers } = useQuery({
    queryKey: ['trusted-browsers'],
    queryFn: () => api.get<TrustedBrowser[]>('/api/v1/identity/trusted-browsers'),
  })

  // SMS MFA mutations
  const enrollSMSMutation = useMutation({
    mutationFn: (data: { phone_number: string; country_code: string }) =>
      api.post('/api/v1/identity/mfa/sms/enroll', data),
    onSuccess: () => {
      setSmsEnrollStep('verify')
      toast({ title: 'Code Sent', description: 'A verification code has been sent to your phone.' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to send verification code.', variant: 'destructive' })
    },
  })

  const verifySMSMutation = useMutation({
    mutationFn: (code: string) =>
      api.post('/api/v1/identity/mfa/sms/verify', { code }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['mfa-methods'] })
      setSmsEnrollStep('idle')
      setPhoneNumber('')
      setSmsVerifyCode('')
      toast({ title: 'SMS MFA Enabled', description: 'Your phone has been verified for SMS authentication.' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Invalid verification code.', variant: 'destructive' })
    },
  })

  const deleteSMSMutation = useMutation({
    mutationFn: () => api.delete('/api/v1/identity/mfa/sms'),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['mfa-methods'] })
      toast({ title: 'SMS MFA Disabled', description: 'SMS authentication has been removed.' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to disable SMS MFA.', variant: 'destructive' })
    },
  })

  // Email OTP mutations
  const enrollEmailOTPMutation = useMutation({
    mutationFn: () => api.post('/api/v1/identity/mfa/email/enroll'),
    onSuccess: () => {
      setEmailOtpEnrollStep('verify')
      toast({ title: 'Code Sent', description: 'A verification code has been sent to your email.' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to send verification code.', variant: 'destructive' })
    },
  })

  const verifyEmailOTPMutation = useMutation({
    mutationFn: (code: string) =>
      api.post('/api/v1/identity/mfa/email/verify', { code }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['mfa-methods'] })
      setEmailOtpEnrollStep('idle')
      setEmailOtpCode('')
      toast({ title: 'Email OTP Enabled', description: 'Your email has been verified for OTP authentication.' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Invalid verification code.', variant: 'destructive' })
    },
  })

  const deleteEmailOTPMutation = useMutation({
    mutationFn: () => api.delete('/api/v1/identity/mfa/email'),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['mfa-methods'] })
      toast({ title: 'Email OTP Disabled', description: 'Email OTP authentication has been removed.' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to disable Email OTP.', variant: 'destructive' })
    },
  })

  // Trusted browser mutations
  const revokeBrowserMutation = useMutation({
    mutationFn: (browserId: string) =>
      api.delete(`/api/v1/identity/trusted-browsers/${browserId}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['trusted-browsers'] })
      toast({ title: 'Browser Revoked', description: 'The trusted browser has been removed.' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to revoke browser.', variant: 'destructive' })
    },
  })

  const revokeAllBrowsersMutation = useMutation({
    mutationFn: () => api.delete('/api/v1/identity/trusted-browsers'),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['trusted-browsers'] })
      toast({ title: 'All Browsers Revoked', description: 'All trusted browsers have been removed.' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to revoke browsers.', variant: 'destructive' })
    },
  })

  // Access Tokens queries and mutations
  const { data: accessTokens, isLoading: tokensLoading } = useQuery({
    queryKey: ['access-tokens'],
    queryFn: () => api.get<PersonalAccessToken[]>('/api/v1/identity/users/me/tokens'),
  })

  const createTokenMutation = useMutation({
    mutationFn: (data: { name: string; scopes: string[]; expires_at?: string }) =>
      api.post<CreateTokenResponse>('/api/v1/identity/users/me/tokens', data),
    onSuccess: (response) => {
      setCreatedRawToken(response.raw_token)
      setShowCreateToken(false)
      setNewTokenName('')
      setNewTokenScopes([])
      setNewTokenExpiry('')
      queryClient.invalidateQueries({ queryKey: ['access-tokens'] })
      toast({ title: 'Token Created', description: 'Your new access token has been created.' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to create access token.', variant: 'destructive' })
    },
  })

  const revokeTokenMutation = useMutation({
    mutationFn: (tokenId: string) =>
      api.delete(`/api/v1/identity/users/me/tokens/${tokenId}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['access-tokens'] })
      toast({ title: 'Token Revoked', description: 'The access token has been revoked.' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to revoke token.', variant: 'destructive' })
    },
  })

  // Authorized Apps queries and mutations
  const { data: userConsents, isLoading: consentsLoading } = useQuery({
    queryKey: ['user-consents'],
    queryFn: () => api.get<UserConsent[]>('/api/v1/identity/users/me/consents'),
  })

  const revokeConsentMutation = useMutation({
    mutationFn: (clientId: string) =>
      api.delete(`/api/v1/identity/users/me/consents/${clientId}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['user-consents'] })
      setRevokeConsentClientId(null)
      toast({ title: 'Access Revoked', description: 'The application no longer has access to your account.' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to revoke application access.', variant: 'destructive' })
    },
  })

  const toggleTokenScope = (scope: string) => {
    setNewTokenScopes(prev =>
      prev.includes(scope) ? prev.filter(s => s !== scope) : [...prev, scope]
    )
  }

  // Helper to check if a method is enabled
  const isMethodEnabled = (method: string) => {
    return mfaMethods?.some(m => m.method === method && m.enabled && m.verified)
  }

  const revokeSessionMutation = useMutation({
    mutationFn: (sessionId: string) => api.delete(`/api/v1/identity/sessions/${sessionId}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sessions'] })
      toast({ title: 'Session revoked' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to revoke session', variant: 'destructive' })
    },
  })

  const logoutAllMutation = useMutation({
    mutationFn: async () => {
      const token = localStorage.getItem('token')
      const response = await fetch(`${import.meta.env.VITE_OAUTH_URL || 'http://localhost:8006'}/oauth/logout-all`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` },
      })
      if (!response.ok) {
        throw new Error('Failed to sign out everywhere')
      }
    },
    onSuccess: () => {
      toast({ title: 'Signed out everywhere', description: 'All sessions have been revoked. You will be redirected to sign in.' })
      queryClient.invalidateQueries({ queryKey: ['sessions'] })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to sign out of all devices', variant: 'destructive' })
    },
  })

  if (isLoading) {
    return (
      <div className="flex h-96 items-center justify-center">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  if (isError) {
    return <QueryError error={error} resource="your profile" />
  }

  if (!profile) {
    return (
      <div className="text-center py-8">
        <p className="text-muted-foreground">Failed to load profile</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">My Profile</h1>
          <p className="text-muted-foreground">Manage your account settings and security preferences</p>
        </div>
      </div>

      <Tabs defaultValue="profile" className="space-y-4">
        <TabsList>
          <TabsTrigger value="profile" className="flex items-center gap-2">
            <User className="h-4 w-4" />
            Profile
          </TabsTrigger>
          <TabsTrigger value="security" className="flex items-center gap-2">
            <Shield className="h-4 w-4" />
            Security
          </TabsTrigger>
          <TabsTrigger value="sessions" className="flex items-center gap-2">
            <Monitor className="h-4 w-4" />
            Sessions
            {sessions && sessions.length > 0 && (
              <Badge variant="secondary" className="ml-1">{sessions.length}</Badge>
            )}
          </TabsTrigger>
          <TabsTrigger value="access-tokens" className="flex items-center gap-2">
            <KeyRound className="h-4 w-4" />
            Access Tokens
          </TabsTrigger>
          <TabsTrigger value="authorized-apps" className="flex items-center gap-2">
            <AppWindow className="h-4 w-4" />
            Authorized Apps
          </TabsTrigger>
        </TabsList>

        <TabsContent value="profile" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Personal Information</CardTitle>
              <CardDescription>Update your personal details</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="firstName">First Name</Label>
                  <Input
                    id="firstName"
                    value={firstName}
                    onChange={(e) => setFirstName(e.target.value)}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="lastName">Last Name</Label>
                  <Input
                    id="lastName"
                    value={lastName}
                    onChange={(e) => setLastName(e.target.value)}
                  />
                </div>
              </div>
              <div className="space-y-2">
                <Label htmlFor="email">Email</Label>
                <div className="flex items-center gap-2">
                  <Input
                    id="email"
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                  />
                  {profile.emailVerified && (
                    <Badge variant="secondary" className="flex items-center gap-1">
                      <Mail className="h-3 w-3" />
                      Verified
                    </Badge>
                  )}
                </div>
              </div>
              <div className="flex items-center space-x-2">
                <Switch
                  id="email-notifications"
                  checked={profile.enabled}
                  onCheckedChange={(checked) => updateProfileMutation.mutate({ enabled: checked })}
                />
                <Label htmlFor="email-notifications">Account Enabled</Label>
              </div>
              <Button
                onClick={() => updateProfileMutation.mutate({
                  firstName,
                  lastName,
                  email,
                })}
                disabled={updateProfileMutation.isPending}
              >
                {updateProfileMutation.isPending ? <LoadingSpinner size="sm" /> : null}
                Update Profile
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="security" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Multi-Factor Authentication</CardTitle>
              <CardDescription>Add an extra layer of security to your account</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Smartphone className="h-5 w-5" />
                  <div>
                    <p className="font-medium">Authenticator App</p>
                    <p className="text-sm text-muted-foreground">
                      Use an authenticator app to generate verification codes
                    </p>
                  </div>
                </div>
                {profile.mfaEnabled ? (
                  <Badge variant="secondary" className="flex items-center gap-1">
                    <Shield className="h-3 w-3" />
                    Enabled
                  </Badge>
                ) : (
                  <Button onClick={() => setupMFAMutation.mutate()} variant="outline" disabled={setupMFAMutation.isPending}>
                    <Key className="h-4 w-4 mr-2" />
                    Setup MFA
                  </Button>
                )}
              </div>

              {profile.mfaEnabled && (
                <AlertDialog>
                  <AlertDialogTrigger asChild>
                    <Button variant="destructive" disabled={disableMFAMutation.isPending}>
                      Disable MFA
                    </Button>
                  </AlertDialogTrigger>
                  <AlertDialogContent>
                    <AlertDialogHeader>
                      <AlertDialogTitle>Disable Multi-Factor Authentication?</AlertDialogTitle>
                      <AlertDialogDescription>
                        This will remove the extra security layer from your account. Are you sure you want to continue?
                      </AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                      <AlertDialogCancel>Cancel</AlertDialogCancel>
                      <AlertDialogAction onClick={() => disableMFAMutation.mutate()}>Disable MFA</AlertDialogAction>
                    </AlertDialogFooter>
                  </AlertDialogContent>
                </AlertDialog>
              )}

              {mfaSetup && (
                <Card className="border-orange-200">
                  <CardHeader>
                    <CardTitle className="text-orange-900">Setup Authenticator</CardTitle>
                    <CardDescription>Scan QR code or enter secret manually</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-6">
                    <div className="flex justify-center bg-white p-8 rounded-lg border">
                      <QRCodeSVG
                        value={mfaSetup.qrCodeUrl}
                        size={320}
                        level="H"
                        includeMargin={true}
                      />
                    </div>

                    <div className="space-y-2">
                      <Label className="text-base font-semibold">Or Enter Secret Manually:</Label>
                      <div className="bg-muted p-4 rounded-lg">
                        <code className="text-sm break-all font-mono select-all cursor-pointer" onClick={(e) => {
                          const text = (e.currentTarget as HTMLElement).textContent
                          navigator.clipboard.writeText(text || '')
                        }}>
                          {mfaSetup.secret}
                        </code>
                        <p className="text-xs text-muted-foreground mt-2">Click to copy</p>
                      </div>
                      <p className="text-sm text-muted-foreground">
                        If QR code scanning fails, open your authenticator app and choose "Enter setup key" or "Manual entry", then paste this secret.
                      </p>
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="mfa-code">Verification Code</Label>
                      <Input
                        id="mfa-code"
                        placeholder="Enter 6-digit code"
                        type="text"
                        maxLength={6}
                        pattern="\d*"
                        inputMode="numeric"
                        value={mfaCode}
                        onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                        className="text-center text-2xl tracking-widest"
                        onKeyDown={(e) => {
                          if (e.key === 'Enter' && mfaCode.length === 6) {
                            enableMFAMutation.mutate(mfaCode)
                          }
                        }}
                      />
                    </div>
                    <Button
                      onClick={() => {
                        if (mfaCode.length === 6) {
                          enableMFAMutation.mutate(mfaCode)
                        } else {
                          toast({
                            title: 'Invalid Code',
                            description: 'Please enter a 6-digit verification code',
                            variant: 'destructive'
                          })
                        }
                      }}
                      className="w-full"
                      size="lg"
                      disabled={enableMFAMutation.isPending}
                    >
                      Verify & Enable MFA
                    </Button>
                  </CardContent>
                </Card>
              )}

              {showBackupCodes && mfaSetup?.backupCodes && (
                <Card className="border-blue-200">
                  <CardHeader>
                    <CardTitle className="text-blue-900">Backup Codes</CardTitle>
                    <CardDescription>Save these codes in a safe place</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-2 gap-2 font-mono text-sm">
                      {mfaSetup.backupCodes.map((code, index) => (
                        <div key={index} className="bg-muted p-2 rounded text-center">
                          {code}
                        </div>
                      ))}
                    </div>
                    <Button
                      onClick={() => {
                        setShowBackupCodes(false)
                        setMfaSetup(null)
                      }}
                      className="w-full mt-4"
                    >
                      I've Saved My Backup Codes
                    </Button>
                  </CardContent>
                </Card>
              )}

              {/* SMS MFA Section */}
              <div className="border-t pt-4 mt-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <Phone className="h-5 w-5" />
                    <div>
                      <p className="font-medium">SMS Authentication</p>
                      <p className="text-sm text-muted-foreground">
                        Receive verification codes via text message
                      </p>
                    </div>
                  </div>
                  {isMethodEnabled('sms') ? (
                    <div className="flex items-center gap-2">
                      <Badge variant="secondary" className="flex items-center gap-1">
                        <Check className="h-3 w-3" />
                        Enabled
                      </Badge>
                      <AlertDialog>
                        <AlertDialogTrigger asChild>
                          <Button variant="destructive" size="sm">Remove</Button>
                        </AlertDialogTrigger>
                        <AlertDialogContent>
                          <AlertDialogHeader>
                            <AlertDialogTitle>Remove SMS Authentication?</AlertDialogTitle>
                            <AlertDialogDescription>
                              You will no longer be able to use SMS codes for authentication.
                            </AlertDialogDescription>
                          </AlertDialogHeader>
                          <AlertDialogFooter>
                            <AlertDialogCancel>Cancel</AlertDialogCancel>
                            <AlertDialogAction onClick={() => deleteSMSMutation.mutate()}>Remove</AlertDialogAction>
                          </AlertDialogFooter>
                        </AlertDialogContent>
                      </AlertDialog>
                    </div>
                  ) : (
                    <Button variant="outline" onClick={() => setSmsEnrollStep('enter-phone')}>
                      <Phone className="h-4 w-4 mr-2" />
                      Setup SMS
                    </Button>
                  )}
                </div>

                {smsEnrollStep === 'enter-phone' && (
                  <Card className="mt-4 border-orange-200">
                    <CardHeader>
                      <CardTitle className="text-orange-900">Setup SMS Authentication</CardTitle>
                      <CardDescription>Enter your phone number to receive codes</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div className="flex gap-2">
                        <div className="w-24">
                          <Label htmlFor="country-code">Country</Label>
                          <Input
                            id="country-code"
                            value={countryCode}
                            onChange={(e) => setCountryCode(e.target.value)}
                            placeholder="+1"
                          />
                        </div>
                        <div className="flex-1">
                          <Label htmlFor="phone-number">Phone Number</Label>
                          <Input
                            id="phone-number"
                            value={phoneNumber}
                            onChange={(e) => setPhoneNumber(e.target.value)}
                            placeholder="555-123-4567"
                          />
                        </div>
                      </div>
                      <div className="flex gap-2">
                        <Button
                          variant="outline"
                          onClick={() => {
                            setSmsEnrollStep('idle')
                            setPhoneNumber('')
                          }}
                        >
                          Cancel
                        </Button>
                        <Button
                          onClick={() => enrollSMSMutation.mutate({ phone_number: phoneNumber, country_code: countryCode })}
                          disabled={enrollSMSMutation.isPending || !phoneNumber}
                        >
                          {enrollSMSMutation.isPending ? <LoadingSpinner size="sm" /> : 'Send Code'}
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                )}

                {smsEnrollStep === 'verify' && (
                  <Card className="mt-4 border-orange-200">
                    <CardHeader>
                      <CardTitle className="text-orange-900">Verify Your Phone</CardTitle>
                      <CardDescription>Enter the 6-digit code sent to your phone</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div className="space-y-2">
                        <Label htmlFor="sms-code">Verification Code</Label>
                        <Input
                          id="sms-code"
                          value={smsVerifyCode}
                          onChange={(e) => setSmsVerifyCode(e.target.value)}
                          placeholder="000000"
                          maxLength={6}
                          className="text-center text-2xl tracking-widest"
                        />
                      </div>
                      <div className="flex gap-2">
                        <Button
                          variant="outline"
                          onClick={() => {
                            setSmsEnrollStep('idle')
                            setSmsVerifyCode('')
                          }}
                        >
                          Cancel
                        </Button>
                        <Button
                          onClick={() => verifySMSMutation.mutate(smsVerifyCode)}
                          disabled={verifySMSMutation.isPending || smsVerifyCode.length !== 6}
                        >
                          {verifySMSMutation.isPending ? <LoadingSpinner size="sm" /> : 'Verify & Enable'}
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                )}
              </div>

              {/* Email OTP Section */}
              <div className="border-t pt-4 mt-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <Mail className="h-5 w-5" />
                    <div>
                      <p className="font-medium">Email OTP</p>
                      <p className="text-sm text-muted-foreground">
                        Receive verification codes via email
                      </p>
                    </div>
                  </div>
                  {isMethodEnabled('email') ? (
                    <div className="flex items-center gap-2">
                      <Badge variant="secondary" className="flex items-center gap-1">
                        <Check className="h-3 w-3" />
                        Enabled
                      </Badge>
                      <AlertDialog>
                        <AlertDialogTrigger asChild>
                          <Button variant="destructive" size="sm">Remove</Button>
                        </AlertDialogTrigger>
                        <AlertDialogContent>
                          <AlertDialogHeader>
                            <AlertDialogTitle>Remove Email OTP?</AlertDialogTitle>
                            <AlertDialogDescription>
                              You will no longer be able to use email codes for authentication.
                            </AlertDialogDescription>
                          </AlertDialogHeader>
                          <AlertDialogFooter>
                            <AlertDialogCancel>Cancel</AlertDialogCancel>
                            <AlertDialogAction onClick={() => deleteEmailOTPMutation.mutate()}>Remove</AlertDialogAction>
                          </AlertDialogFooter>
                        </AlertDialogContent>
                      </AlertDialog>
                    </div>
                  ) : (
                    <Button variant="outline" onClick={() => enrollEmailOTPMutation.mutate()}>
                      <Mail className="h-4 w-4 mr-2" />
                      Setup Email OTP
                    </Button>
                  )}
                </div>

                {emailOtpEnrollStep === 'verify' && (
                  <Card className="mt-4 border-orange-200">
                    <CardHeader>
                      <CardTitle className="text-orange-900">Verify Your Email</CardTitle>
                      <CardDescription>Enter the 6-digit code sent to {profile?.email}</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div className="space-y-2">
                        <Label htmlFor="email-otp-code">Verification Code</Label>
                        <Input
                          id="email-otp-code"
                          value={emailOtpCode}
                          onChange={(e) => setEmailOtpCode(e.target.value)}
                          placeholder="000000"
                          maxLength={6}
                          className="text-center text-2xl tracking-widest"
                        />
                      </div>
                      <div className="flex gap-2">
                        <Button
                          variant="outline"
                          onClick={() => {
                            setEmailOtpEnrollStep('idle')
                            setEmailOtpCode('')
                          }}
                        >
                          Cancel
                        </Button>
                        <Button
                          onClick={() => verifyEmailOTPMutation.mutate(emailOtpCode)}
                          disabled={verifyEmailOTPMutation.isPending || emailOtpCode.length !== 6}
                        >
                          {verifyEmailOTPMutation.isPending ? <LoadingSpinner size="sm" /> : 'Verify & Enable'}
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                )}
              </div>
            </CardContent>
          </Card>

          {/* Trusted Browsers Card */}
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Trusted Browsers</CardTitle>
                  <CardDescription>Browsers where MFA can be skipped</CardDescription>
                </div>
                {trustedBrowsers && trustedBrowsers.filter(b => b.active).length > 0 && (
                  <AlertDialog>
                    <AlertDialogTrigger asChild>
                      <Button variant="destructive" size="sm">
                        Revoke All
                      </Button>
                    </AlertDialogTrigger>
                    <AlertDialogContent>
                      <AlertDialogHeader>
                        <AlertDialogTitle>Revoke All Trusted Browsers?</AlertDialogTitle>
                        <AlertDialogDescription>
                          You will need to complete MFA on all browsers again.
                        </AlertDialogDescription>
                      </AlertDialogHeader>
                      <AlertDialogFooter>
                        <AlertDialogCancel>Cancel</AlertDialogCancel>
                        <AlertDialogAction onClick={() => revokeAllBrowsersMutation.mutate()}>
                          Revoke All
                        </AlertDialogAction>
                      </AlertDialogFooter>
                    </AlertDialogContent>
                  </AlertDialog>
                )}
              </div>
            </CardHeader>
            <CardContent>
              {!trustedBrowsers || trustedBrowsers.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  <Globe className="h-12 w-12 mx-auto mb-3 opacity-40" />
                  <p>No trusted browsers</p>
                  <p className="text-sm">Complete MFA and choose to trust your browser</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {trustedBrowsers.map((browser) => (
                    <div
                      key={browser.id}
                      className={`flex items-center justify-between p-3 border rounded-lg ${
                        browser.active ? 'bg-green-50 border-green-200' : 'bg-gray-50 border-gray-200 opacity-60'
                      }`}
                    >
                      <div className="flex items-center gap-3">
                        <Globe className={`h-5 w-5 ${browser.active ? 'text-green-600' : 'text-gray-400'}`} />
                        <div>
                          <p className="font-medium">{browser.name}</p>
                          <p className="text-xs text-muted-foreground">
                            {browser.ip_address} • Trusted {new Date(browser.trusted_at).toLocaleDateString()}
                          </p>
                          {!browser.active && (
                            <Badge variant="secondary" className="mt-1">
                              {browser.revoked ? 'Revoked' : 'Expired'}
                            </Badge>
                          )}
                        </div>
                      </div>
                      {browser.active && (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => revokeBrowserMutation.mutate(browser.id)}
                          disabled={revokeBrowserMutation.isPending}
                        >
                          <Trash2 className="h-4 w-4 text-red-500" />
                        </Button>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Change Password</CardTitle>
              <CardDescription>
                {passwordInfo?.is_azure_ad
                  ? 'Your password is managed by Azure Active Directory'
                  : passwordInfo?.is_ldap
                  ? 'Your password is managed by Active Directory'
                  : 'Update your account password'}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {passwordInfo?.is_azure_ad && (
                <div className="flex items-center gap-2 p-3 bg-purple-50 dark:bg-purple-950 rounded-md text-sm text-purple-700 dark:text-purple-300">
                  <Shield className="h-4 w-4 flex-shrink-0" />
                  <span>Your account is managed by Azure Active Directory. To change your password, use the Azure AD portal or your organization&apos;s self-service password reset.</span>
                </div>
              )}
              {passwordInfo?.is_ldap && (
                <div className="flex items-center gap-2 p-3 bg-blue-50 dark:bg-blue-950 rounded-md text-sm text-blue-700 dark:text-blue-300">
                  <Shield className="h-4 w-4 flex-shrink-0" />
                  <span>Changes will be applied directly to your Active Directory account. Your organization&apos;s password policy applies.</span>
                </div>
              )}
              {!passwordInfo?.is_azure_ad && (
                <>
                  <div className="space-y-2">
                    <Label htmlFor="current-password">Current Password</Label>
                    <Input
                      id="current-password"
                      type="password"
                      value={currentPassword}
                      onChange={(e) => setCurrentPassword(e.target.value)}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="new-password">New Password</Label>
                    <Input
                      id="new-password"
                      type="password"
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="confirm-password">Confirm New Password</Label>
                    <Input
                      id="confirm-password"
                      type="password"
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                    />
                  </div>
                  <Button
                    onClick={() => {
                      if (newPassword !== confirmPassword) {
                        toast({
                          title: 'Error',
                          description: 'Passwords do not match',
                          variant: 'destructive'
                        })
                        return
                      }

                      changePasswordMutation.mutate(
                        { currentPassword, newPassword },
                        {
                          onSuccess: () => {
                            setCurrentPassword('')
                            setNewPassword('')
                            setConfirmPassword('')
                          },
                        }
                      )
                    }}
                    disabled={changePasswordMutation.isPending}
                  >
                    {passwordInfo?.is_ldap ? 'Change AD Password' : 'Change Password'}
                  </Button>
                </>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="sessions" className="space-y-4">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Active Sessions</CardTitle>
                  <CardDescription>Manage your active sessions across devices</CardDescription>
                </div>
                {sessions && sessions.length > 0 && (
                  <div className="flex items-center gap-2">
                    <AlertDialog>
                      <AlertDialogTrigger asChild>
                        <Button
                          variant="destructive"
                          size="sm"
                          disabled={logoutAllMutation.isPending}
                        >
                          Sign Out Everywhere
                        </Button>
                      </AlertDialogTrigger>
                      <AlertDialogContent>
                        <AlertDialogHeader>
                          <AlertDialogTitle>Sign out of all devices?</AlertDialogTitle>
                          <AlertDialogDescription>
                            This will revoke all your active sessions and refresh tokens across all devices. You will need to sign in again on each device.
                          </AlertDialogDescription>
                        </AlertDialogHeader>
                        <AlertDialogFooter>
                          <AlertDialogCancel>Cancel</AlertDialogCancel>
                          <AlertDialogAction onClick={() => logoutAllMutation.mutate()}>
                            Sign Out Everywhere
                          </AlertDialogAction>
                        </AlertDialogFooter>
                      </AlertDialogContent>
                    </AlertDialog>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        sessions.forEach((session) => revokeSessionMutation.mutate(session.id))
                      }}
                      disabled={revokeSessionMutation.isPending}
                    >
                      Revoke All Sessions
                    </Button>
                  </div>
                )}
              </div>
            </CardHeader>
            <CardContent>
              {sessionsLoading ? (
                <div className="flex justify-center py-8">
                  <LoadingSpinner size="lg" />
                </div>
              ) : !sessions || sessions.length === 0 ? (
                <div className="text-center py-8">
                  <p className="text-muted-foreground">No active sessions</p>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b">
                        <th className="text-left py-2 px-2 font-medium">IP Address</th>
                        <th className="text-left py-2 px-2 font-medium">User Agent</th>
                        <th className="text-left py-2 px-2 font-medium">Started</th>
                        <th className="text-left py-2 px-2 font-medium">Last Seen</th>
                        <th className="text-left py-2 px-2 font-medium">Expires</th>
                        <th className="text-left py-2 px-2 font-medium">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {sessions.map((session) => (
                        <tr key={session.id} className="border-b">
                          <td className="py-2 px-2 font-mono text-xs">{session.ip_address}</td>
                          <td className="py-2 px-2 max-w-[200px] truncate" title={session.user_agent}>
                            {session.user_agent}
                          </td>
                          <td className="py-2 px-2 whitespace-nowrap">
                            {new Date(session.started_at).toLocaleString()}
                          </td>
                          <td className="py-2 px-2 whitespace-nowrap">
                            {new Date(session.last_seen_at).toLocaleString()}
                          </td>
                          <td className="py-2 px-2 whitespace-nowrap">
                            {new Date(session.expires_at).toLocaleString()}
                          </td>
                          <td className="py-2 px-2">
                            <Button
                              variant="destructive"
                              size="sm"
                              onClick={() => revokeSessionMutation.mutate(session.id)}
                              disabled={revokeSessionMutation.isPending}
                            >
                              Revoke
                            </Button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="access-tokens" className="space-y-4">
          {/* Created Token Banner */}
          {createdRawToken && (
            <Card className="border-amber-300 bg-amber-50">
              <CardContent className="pt-6 space-y-3">
                <div className="flex items-start gap-3">
                  <AlertTriangle className="h-5 w-5 text-amber-600 mt-0.5 shrink-0" />
                  <div className="space-y-2 flex-1">
                    <p className="font-medium text-amber-900">Copy this token now. You won't be able to see it again.</p>
                    <div className="flex items-center gap-2">
                      <code className="flex-1 bg-white border border-amber-200 px-3 py-2 rounded text-sm font-mono break-all select-all">
                        {createdRawToken}
                      </code>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => {
                          navigator.clipboard.writeText(createdRawToken)
                          toast({ title: 'Copied', description: 'Token copied to clipboard.' })
                        }}
                      >
                        <Copy className="h-4 w-4" />
                      </Button>
                    </div>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setCreatedRawToken(null)}
                      className="text-amber-700"
                    >
                      Dismiss
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Personal Access Tokens</CardTitle>
                  <CardDescription>Tokens for API access and automation</CardDescription>
                </div>
                <Button onClick={() => setShowCreateToken(true)} disabled={showCreateToken}>
                  <Plus className="h-4 w-4 mr-2" />
                  Create Token
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              {/* Create Token Form */}
              {showCreateToken && (
                <Card className="mb-6 border-blue-200">
                  <CardHeader>
                    <CardTitle className="text-base">Create New Token</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="space-y-2">
                      <Label htmlFor="token-name">Token Name</Label>
                      <Input
                        id="token-name"
                        placeholder="e.g., CI/CD Pipeline, CLI Tool"
                        value={newTokenName}
                        onChange={(e) => setNewTokenName(e.target.value)}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Scopes</Label>
                      <div className="flex items-center gap-6">
                        {['read', 'write', 'admin'].map((scope) => (
                          <div key={scope} className="flex items-center gap-2">
                            <Checkbox
                              id={`scope-${scope}`}
                              checked={newTokenScopes.includes(scope)}
                              onCheckedChange={() => toggleTokenScope(scope)}
                            />
                            <Label htmlFor={`scope-${scope}`} className="text-sm font-normal capitalize cursor-pointer">
                              {scope}
                            </Label>
                          </div>
                        ))}
                      </div>
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="token-expiry">Expiry Date (optional)</Label>
                      <Input
                        id="token-expiry"
                        type="date"
                        value={newTokenExpiry}
                        onChange={(e) => setNewTokenExpiry(e.target.value)}
                      />
                    </div>
                    <div className="flex gap-2">
                      <Button
                        variant="outline"
                        onClick={() => {
                          setShowCreateToken(false)
                          setNewTokenName('')
                          setNewTokenScopes([])
                          setNewTokenExpiry('')
                        }}
                      >
                        Cancel
                      </Button>
                      <Button
                        onClick={() => {
                          if (!newTokenName.trim()) {
                            toast({ title: 'Error', description: 'Token name is required.', variant: 'destructive' })
                            return
                          }
                          if (newTokenScopes.length === 0) {
                            toast({ title: 'Error', description: 'Select at least one scope.', variant: 'destructive' })
                            return
                          }
                          createTokenMutation.mutate({
                            name: newTokenName.trim(),
                            scopes: newTokenScopes,
                            ...(newTokenExpiry ? { expires_at: new Date(newTokenExpiry).toISOString() } : {}),
                          })
                        }}
                        disabled={createTokenMutation.isPending}
                      >
                        {createTokenMutation.isPending ? <LoadingSpinner size="sm" /> : null}
                        Create Token
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* Tokens Table */}
              {tokensLoading ? (
                <div className="flex justify-center py-8">
                  <LoadingSpinner size="lg" />
                </div>
              ) : !accessTokens || accessTokens.length === 0 ? (
                <div className="text-center py-8">
                  <KeyRound className="h-12 w-12 mx-auto mb-3 opacity-40" />
                  <p className="text-muted-foreground">No access tokens</p>
                  <p className="text-sm text-muted-foreground">Create a token to access the API programmatically.</p>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b">
                        <th className="text-left py-2 px-2 font-medium">Name</th>
                        <th className="text-left py-2 px-2 font-medium">Prefix</th>
                        <th className="text-left py-2 px-2 font-medium">Scopes</th>
                        <th className="text-left py-2 px-2 font-medium">Created</th>
                        <th className="text-left py-2 px-2 font-medium">Last Used</th>
                        <th className="text-left py-2 px-2 font-medium">Expires</th>
                        <th className="text-left py-2 px-2 font-medium">Status</th>
                        <th className="text-left py-2 px-2 font-medium">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {accessTokens.map((token) => (
                        <tr key={token.id} className="border-b">
                          <td className="py-2 px-2 font-medium">{token.name}</td>
                          <td className="py-2 px-2 font-mono text-xs">{token.key_prefix}...</td>
                          <td className="py-2 px-2">
                            <div className="flex flex-wrap gap-1">
                              {token.scopes.map((scope) => (
                                <Badge key={scope} variant="secondary" className="text-xs">
                                  {scope}
                                </Badge>
                              ))}
                            </div>
                          </td>
                          <td className="py-2 px-2 whitespace-nowrap">
                            {new Date(token.created_at).toLocaleDateString()}
                          </td>
                          <td className="py-2 px-2 whitespace-nowrap">
                            {token.last_used_at
                              ? new Date(token.last_used_at).toLocaleDateString()
                              : 'Never'}
                          </td>
                          <td className="py-2 px-2 whitespace-nowrap">
                            {token.expires_at
                              ? new Date(token.expires_at).toLocaleDateString()
                              : 'Never'}
                          </td>
                          <td className="py-2 px-2">
                            <Badge
                              variant={token.status === 'active' ? 'secondary' : 'destructive'}
                              className="text-xs"
                            >
                              {token.status}
                            </Badge>
                          </td>
                          <td className="py-2 px-2">
                            {token.status === 'active' && (
                              <AlertDialog>
                                <AlertDialogTrigger asChild>
                                  <Button variant="destructive" size="sm">
                                    Revoke
                                  </Button>
                                </AlertDialogTrigger>
                                <AlertDialogContent>
                                  <AlertDialogHeader>
                                    <AlertDialogTitle>Revoke Access Token?</AlertDialogTitle>
                                    <AlertDialogDescription>
                                      This will permanently revoke the token "{token.name}". Any applications
                                      using this token will lose access immediately.
                                    </AlertDialogDescription>
                                  </AlertDialogHeader>
                                  <AlertDialogFooter>
                                    <AlertDialogCancel>Cancel</AlertDialogCancel>
                                    <AlertDialogAction onClick={() => revokeTokenMutation.mutate(token.id)}>
                                      Revoke Token
                                    </AlertDialogAction>
                                  </AlertDialogFooter>
                                </AlertDialogContent>
                              </AlertDialog>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="authorized-apps" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Authorized Applications</CardTitle>
              <CardDescription>Applications you have granted access to your account</CardDescription>
            </CardHeader>
            <CardContent>
              {consentsLoading ? (
                <div className="flex justify-center py-8">
                  <LoadingSpinner size="lg" />
                </div>
              ) : !userConsents || userConsents.length === 0 ? (
                <div className="text-center py-8">
                  <AppWindow className="h-12 w-12 mx-auto mb-3 opacity-40" />
                  <p className="text-muted-foreground">No authorized applications</p>
                  <p className="text-sm text-muted-foreground">
                    When you sign in to third-party applications using OpenIDX, they will appear here.
                  </p>
                </div>
              ) : (
                <div className="space-y-4">
                  {userConsents.map((consent) => (
                    <div
                      key={consent.client_id}
                      className="flex items-start justify-between p-4 border rounded-lg"
                    >
                      <div className="flex items-start gap-4">
                        {consent.logo_uri ? (
                          <img
                            src={consent.logo_uri}
                            alt={consent.client_name}
                            className="h-10 w-10 rounded-lg object-contain"
                          />
                        ) : (
                          <div className="h-10 w-10 rounded-lg bg-muted flex items-center justify-center">
                            <AppWindow className="h-5 w-5 text-muted-foreground" />
                          </div>
                        )}
                        <div className="space-y-1">
                          <p className="font-medium">{consent.client_name}</p>
                          <div className="flex flex-wrap gap-1">
                            {consent.scopes.map((scope) => (
                              <Badge key={scope} variant="secondary" className="text-xs">
                                {scope}
                              </Badge>
                            ))}
                          </div>
                          <p className="text-xs text-muted-foreground">
                            Authorized {new Date(consent.authorized_at).toLocaleDateString()}
                            {consent.last_used_at && (
                              <> &middot; Last used {new Date(consent.last_used_at).toLocaleDateString()}</>
                            )}
                          </p>
                        </div>
                      </div>
                      <AlertDialog
                        open={revokeConsentClientId === consent.client_id}
                        onOpenChange={(isOpen) => {
                          if (!isOpen) setRevokeConsentClientId(null)
                        }}
                      >
                        <AlertDialogTrigger asChild>
                          <Button
                            variant="destructive"
                            size="sm"
                            onClick={() => setRevokeConsentClientId(consent.client_id)}
                          >
                            Revoke Access
                          </Button>
                        </AlertDialogTrigger>
                        <AlertDialogContent>
                          <AlertDialogHeader>
                            <AlertDialogTitle>Revoke Application Access?</AlertDialogTitle>
                            <AlertDialogDescription>
                              This will revoke {consent.client_name}'s access to your account.
                              The application will no longer be able to act on your behalf.
                              You can re-authorize it later if needed.
                            </AlertDialogDescription>
                          </AlertDialogHeader>
                          <AlertDialogFooter>
                            <AlertDialogCancel>Cancel</AlertDialogCancel>
                            <AlertDialogAction
                              onClick={() => revokeConsentMutation.mutate(consent.client_id)}
                            >
                              Revoke Access
                            </AlertDialogAction>
                          </AlertDialogFooter>
                        </AlertDialogContent>
                      </AlertDialog>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
