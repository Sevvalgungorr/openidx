import { useEffect, useState } from 'react'
import { KeyRound, Plus, Trash2, Loader2, AlertCircle, Shield } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card'
import { Input } from '../components/ui/input'
import { Label } from '../components/ui/label'
import { useToast } from '../hooks/use-toast'
import { api, WebAuthnCredential } from '../lib/api'
import {
  decodeCredentialCreationOptions,
  serializeAttestationResponse,
} from '../lib/webauthn'

export function SecurityKeysPage() {
  const { toast } = useToast()
  const [credentials, setCredentials] = useState<WebAuthnCredential[]>([])
  const [loading, setLoading] = useState(true)
  const [registering, setRegistering] = useState(false)
  const [showRegisterForm, setShowRegisterForm] = useState(false)
  const [keyName, setKeyName] = useState('')
  const [deleting, setDeleting] = useState<string | null>(null)

  const fetchCredentials = async () => {
    try {
      setLoading(true)
      const data = await api.getWebAuthnCredentials()
      setCredentials(data || [])
    } catch {
      toast({ title: 'Error', description: 'Failed to load security keys', variant: 'destructive' })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchCredentials()
  }, [])

  const handleRegister = async () => {
    if (!keyName.trim()) return

    try {
      setRegistering(true)

      // Step 1: Begin registration (get options from server)
      const beginResponse = await api.beginWebAuthnRegistration()
      const options = decodeCredentialCreationOptions(
        (beginResponse as { publicKey: Parameters<typeof decodeCredentialCreationOptions>[0] }).publicKey
      )

      // Step 2: Create credential via browser API
      const credential = await navigator.credentials.create({ publicKey: options }) as PublicKeyCredential
      if (!credential) {
        throw new Error('Registration was cancelled')
      }

      // Step 3: Send credential to server
      const attestationJSON = serializeAttestationResponse(credential)
      await api.finishWebAuthnRegistration(JSON.parse(attestationJSON))

      toast({ title: 'Success', description: 'Security key registered successfully' })
      setShowRegisterForm(false)
      setKeyName('')
      fetchCredentials()
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to register security key'
      toast({ title: 'Error', description: message, variant: 'destructive' })
    } finally {
      setRegistering(false)
    }
  }

  const handleDelete = async (credentialId: string) => {
    try {
      setDeleting(credentialId)
      await api.deleteWebAuthnCredential(credentialId)
      toast({ title: 'Success', description: 'Security key removed' })
      setCredentials(credentials.filter(c => c.id !== credentialId))
    } catch {
      toast({ title: 'Error', description: 'Failed to remove security key', variant: 'destructive' })
    } finally {
      setDeleting(null)
    }
  }

  const isWebAuthnSupported = typeof window !== 'undefined' && window.PublicKeyCredential !== undefined

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Security Keys</h1>
          <p className="text-muted-foreground">Manage your WebAuthn/FIDO2 security keys for passwordless authentication</p>
        </div>
        {isWebAuthnSupported && (
          <Button onClick={() => setShowRegisterForm(true)} disabled={showRegisterForm}>
            <Plus className="mr-2 h-4 w-4" /> Register Security Key
          </Button>
        )}
      </div>

      {!isWebAuthnSupported && (
        <Card className="border-yellow-200 bg-yellow-50">
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <AlertCircle className="h-5 w-5 text-yellow-600" />
              <p className="text-sm text-yellow-800">
                Your browser does not support WebAuthn. Please use a modern browser (Chrome, Firefox, Safari, or Edge) to manage security keys.
              </p>
            </div>
          </CardContent>
        </Card>
      )}

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
                  disabled={registering}
                />
              </div>
              <Button onClick={handleRegister} disabled={registering || !keyName.trim()}>
                {registering ? (
                  <span className="flex items-center gap-2">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Waiting for key...
                  </span>
                ) : (
                  'Register'
                )}
              </Button>
              <Button variant="outline" onClick={() => { setShowRegisterForm(false); setKeyName('') }} disabled={registering}>
                Cancel
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

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
          {loading ? (
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
                  className="flex items-center justify-between p-4 border rounded-lg"
                >
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-blue-100 rounded-lg">
                      <KeyRound className="h-5 w-5 text-primary" />
                    </div>
                    <div>
                      <p className="font-medium">{cred.name || 'Security Key'}</p>
                      <p className="text-sm text-muted-foreground">
                        Registered {new Date(cred.created_at).toLocaleDateString()}
                        {cred.last_used_at && (
                          <> &middot; Last used {new Date(cred.last_used_at).toLocaleDateString()}</>
                        )}
                        {cred.sign_count > 0 && (
                          <> &middot; Used {cred.sign_count} times</>
                        )}
                      </p>
                    </div>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-red-600 hover:text-red-700 hover:bg-red-50"
                    onClick={() => handleDelete(cred.id)}
                    disabled={deleting === cred.id}
                  >
                    {deleting === cred.id ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      <Trash2 className="h-4 w-4" />
                    )}
                  </Button>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
