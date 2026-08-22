// WebAuthn Credentials Management Page
// This page allows users to manage their WebAuthn/FIDO2 security keys
// All API calls use JWT authentication - user_id is extracted from the token server-side
import { useState } from 'react'
import {
  KeyRound,
  Plus,
  Trash2,
  Loader2,
  AlertCircle,
  Shield,
  Edit,
  Check,
  X,
  AlertTriangle,
} from 'lucide-react'
import { Button } from '../../components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../../components/ui/card'
import { Input } from '../../components/ui/input'
import { Label } from '../../components/ui/label'
import { useToast } from '../../hooks/use-toast'
import {
  useWebAuthnCredentials,
  useRegisterWebAuthnCredential,
  useDeleteWebAuthnCredential,
  useRenameWebAuthnCredential,
} from '../../hooks/useWebAuthnCredentials'
import type { WebAuthnCredential } from '../../api/mfa'

export function WebAuthnCredentialsPage() {
  const { toast } = useToast()
  const { data: credentials = [], isLoading, error, refetch } = useWebAuthnCredentials()

  const registerCredential = useRegisterWebAuthnCredential()
  const deleteCredential = useDeleteWebAuthnCredential()
  const renameCredential = useRenameWebAuthnCredential()

  const [showRegisterForm, setShowRegisterForm] = useState(false)
  const [keyName, setKeyName] = useState('')
  const [deletingId, setDeletingId] = useState<string | null>(null)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [editName, setEditName] = useState('')

  // Get current user info from localStorage (set by auth context)
  const getUserInfo = () => {
    const userStr = localStorage.getItem('user')
    if (userStr) {
      try {
        return JSON.parse(userStr)
      } catch {
        return null
      }
    }
    return null
  }

  const userInfo = getUserInfo()

  const handleRegister = async () => {
    if (!keyName.trim()) {
      toast({ title: 'Error', description: 'Please enter a name for this security key', variant: 'destructive' })
      return
    }

    if (!userInfo?.username) {
      toast({ title: 'Error', description: 'User information not available. Please log in again.', variant: 'destructive' })
      return
    }

    try {
      await registerCredential.mutateAsync({
        username: userInfo.username,
        displayName: userInfo.displayName || userInfo.username,
        friendlyName: keyName,
      })

      toast({ title: 'Success', description: 'Security key registered successfully' })
      setShowRegisterForm(false)
      setKeyName('')
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to register security key'
      toast({ title: 'Error', description: message, variant: 'destructive' })
    }
  }

  const handleDelete = async (credential: WebAuthnCredential) => {
    // Warn if this is the only credential
    if (credentials.length <= 1) {
      toast({
        title: 'Warning',
        description: 'You should have at least one security key registered before removing the last one.',
        variant: 'destructive',
      })
      return
    }

    setDeletingId(credential.id)

    try {
      await deleteCredential.mutateAsync(credential.id)
      toast({ title: 'Success', description: 'Security key removed' })
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to remove security key'
      toast({ title: 'Error', description: message, variant: 'destructive' })
    } finally {
      setDeletingId(null)
    }
  }

  const startEdit = (credential: WebAuthnCredential) => {
    setEditingId(credential.id)
    setEditName(credential.friendly_name)
  }

  const cancelEdit = () => {
    setEditingId(null)
    setEditName('')
  }

  const handleRename = async () => {
    if (!editingId || !editName.trim()) {
      return
    }

    try {
      await renameCredential.mutateAsync({
        credentialId: editingId,
        friendlyName: editName,
      })
      toast({ title: 'Success', description: 'Security key renamed' })
      setEditingId(null)
      setEditName('')
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to rename security key'
      toast({ title: 'Error', description: message, variant: 'destructive' })
    }
  }

  const isWebAuthnSupported = typeof window !== 'undefined' && window.PublicKeyCredential !== undefined

  // Check if user can register passkeys (requires https or localhost)
  const isPasskeyAvailable = isWebAuthnSupported &&
    (window.location.protocol === 'https:' || window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Security Keys</h1>
          <p className="text-muted-foreground">
            Manage your WebAuthn/FIDO2 security keys for passwordless authentication
          </p>
        </div>
        {isPasskeyAvailable && (
          <Button onClick={() => setShowRegisterForm(true)} disabled={showRegisterForm}>
            <Plus className="mr-2 h-4 w-4" /> Register Security Key
          </Button>
        )}
      </div>

      {/* Authentication error */}
      {error && (
        <Card className="border-red-200 bg-red-50">
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <AlertTriangle className="h-5 w-5 text-red-600" />
              <div className="flex-1">
                <p className="text-sm font-medium text-red-800">Authentication Error</p>
                <p className="text-sm text-red-700">
                  {error instanceof Error ? error.message : 'Failed to load credentials. Please log in again.'}
                </p>
              </div>
              <Button variant="outline" size="sm" onClick={() => refetch()}>
                Retry
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* WebAuthn not supported */}
      {!isWebAuthnSupported && (
        <Card className="border-yellow-200 bg-yellow-50">
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <AlertCircle className="h-5 w-5 text-yellow-600" />
              <p className="text-sm text-yellow-800">
                Your browser does not support WebAuthn. Please use a modern browser (Chrome, Firefox, Safari, or Edge)
                to manage security keys.
              </p>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Passkey not available (not on HTTPS) */}
      {isWebAuthnSupported && !isPasskeyAvailable && (
        <Card className="border-blue-200 bg-blue-50">
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <AlertCircle className="h-5 w-5 text-primary" />
              <p className="text-sm text-blue-800">
                Security key registration requires a secure HTTPS connection. This feature will be available in
                production.
              </p>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Registration form */}
      {showRegisterForm && (
        <Card>
          <CardHeader>
            <CardTitle>Register New Security Key</CardTitle>
            <CardDescription>
              Insert your security key and give it a name for easy identification
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex items-end gap-4">
              <div className="flex-1 space-y-2">
                <Label htmlFor="key-name">Key Name</Label>
                <Input
                  id="key-name"
                  placeholder="e.g., YubiKey 5C, Titan Key"
                  value={keyName}
                  onChange={(e) => setKeyName(e.target.value)}
                  disabled={registerCredential.isPending}
                />
              </div>
              <Button onClick={handleRegister} disabled={registerCredential.isPending || !keyName.trim()}>
                {registerCredential.isPending ? (
                  <span className="flex items-center gap-2">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Waiting for key...
                  </span>
                ) : (
                  'Register'
                )}
              </Button>
              <Button
                variant="outline"
                onClick={() => { setShowRegisterForm(false); setKeyName('') }}
                disabled={registerCredential.isPending}
              >
                Cancel
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Credentials list */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <KeyRound className="h-5 w-5" />
            Registered Security Keys
          </CardTitle>
          <CardDescription>
            {credentials.length} security key{credentials.length !== 1 ? 's' : ''} registered
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : credentials.length === 0 ? (
            <div className="text-center py-8">
              <Shield className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
              <p className="text-muted-foreground">No security keys registered yet.</p>
              <p className="text-sm text-muted-foreground mt-1">
                Register a FIDO2/WebAuthn security key for passwordless sign-in.
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {credentials.map((cred) => (
                <div
                  key={cred.id}
                  className="flex items-center justify-between p-4 border rounded-lg group"
                >
                  <div className="flex items-center gap-3 flex-1">
                    <div className="p-2 bg-blue-100 rounded-lg">
                      <KeyRound className="h-5 w-5 text-primary" />
                    </div>
                    <div className="flex-1">
                      {editingId === cred.id ? (
                        <div className="flex items-center gap-2">
                          <Input
                            value={editName}
                            onChange={(e) => setEditName(e.target.value)}
                            className="h-7"
                            onKeyDown={(e) => e.key === 'Enter' && handleRename()}
                            disabled={renameCredential.isPending}
                            autoFocus
                          />
                          <Button size="sm" variant="ghost" className="h-7 w-7 p-0" onClick={handleRename}>
                            <Check className="h-4 w-4" />
                          </Button>
                          <Button size="sm" variant="ghost" className="h-7 w-7 p-0" onClick={cancelEdit}>
                            <X className="h-4 w-4" />
                          </Button>
                        </div>
                      ) : (
                        <>
                          <p className="font-medium">{cred.friendly_name || 'Security Key'}</p>
                          <p className="text-sm text-muted-foreground flex items-center gap-2">
                            <span>{cred.authenticator || 'FIDO2 Security Key'}</span>
                            {cred.is_passkey && (
                              <span className="px-1.5 py-0.5 text-xs bg-green-100 text-green-700 rounded">
                                Passkey
                              </span>
                            )}
                          </p>
                          <p className="text-xs text-muted-foreground">
                            Registered {new Date(cred.created_at).toLocaleDateString()}
                            {cred.last_used_at && (
                              <> · Last used {new Date(cred.last_used_at).toLocaleDateString()}</>
                            )}
                          </p>
                        </>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {editingId !== cred.id && (
                      <>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => startEdit(cred)}
                          disabled={deletingId !== null}
                        >
                          <Edit className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="text-red-600 hover:text-red-700 hover:bg-red-50"
                          onClick={() => handleDelete(cred)}
                          disabled={deletingId === cred.id}
                        >
                          {deletingId === cred.id ? (
                            <Loader2 className="h-4 w-4 animate-spin" />
                          ) : (
                            <Trash2 className="h-4 w-4" />
                          )}
                        </Button>
                      </>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Security info */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">About Security Keys</CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground space-y-2">
          <p>
            Security keys (like YubiKey, Google Titan, or built-in passkeys) provide phishing-resistant
            authentication using public key cryptography.
          </p>
          <ul className="list-disc list-inside space-y-1 ml-2">
            <li>Your credential never leaves your device</li>
            <li>Works across all your devices with passkeys</li>
            <li>Protected by biometrics or PIN</li>
            <li>Cannot be phished or replayed</li>
          </ul>
        </CardContent>
      </Card>
    </div>
  )
}

export default WebAuthnCredentialsPage
