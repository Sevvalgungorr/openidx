import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Monitor, Trash2, AlertTriangle, CheckCircle2, XCircle, Clock, Shield, Globe } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogDescription,
} from '../components/ui/dialog'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '../components/ui/alert-dialog'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

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

interface CheckResult {
  trusted: boolean
  browser_id?: string
  name?: string
  expires_at?: string
}

export function TrustedBrowsersPage() {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [revokeDialog, setRevokeDialog] = useState(false)
  const [revokeAllDialog, setRevokeAllDialog] = useState(false)
  const [selectedBrowser, setSelectedBrowser] = useState<TrustedBrowser | null>(null)
  const [trustDialog, setTrustDialog] = useState(false)

  // Fetch trusted browsers
  const { data: browsersRaw, isLoading, isError, error } = useQuery({
    queryKey: ['trusted-browsers'],
    queryFn: async () => {
      return api.get<TrustedBrowser[]>('/api/v1/identity/trusted-browsers')
    }
  })
  const browsers: TrustedBrowser[] = Array.isArray(browsersRaw) ? browsersRaw : []

  // Check if current browser is trusted
  const { data: checkResult } = useQuery<CheckResult>({
    queryKey: ['trusted-browser-check'],
    queryFn: async () => {
      return api.get<CheckResult>('/api/v1/identity/trusted-browsers/check')
    }
  })

  // Mutations
  const trustMutation = useMutation({
    mutationFn: () => api.post('/api/v1/identity/trusted-browsers', {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['trusted-browsers'] })
      queryClient.invalidateQueries({ queryKey: ['trusted-browser-check'] })
      toast({ title: 'Browser Trusted', description: 'This browser has been added to your trusted list.' })
      setTrustDialog(false)
    },
    onError: (error: Error) => {
      toast({ title: 'Error', description: error.message, variant: 'destructive' })
    }
  })

  const revokeMutation = useMutation({
    mutationFn: (browserId: string) =>
      api.delete(`/api/v1/identity/trusted-browsers/${browserId}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['trusted-browsers'] })
      queryClient.invalidateQueries({ queryKey: ['trusted-browser-check'] })
      toast({ title: 'Trust Revoked', description: 'Browser trust has been revoked.' })
      setRevokeDialog(false)
    }
  })

  const revokeAllMutation = useMutation({
    mutationFn: () => api.delete('/api/v1/identity/trusted-browsers'),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['trusted-browsers'] })
      queryClient.invalidateQueries({ queryKey: ['trusted-browser-check'] })
      toast({ title: 'All Trust Revoked', description: 'All trusted browsers have been revoked.' })
      setRevokeAllDialog(false)
    }
  })

  const openRevoke = (browser: TrustedBrowser) => {
    setSelectedBrowser(browser)
    setRevokeDialog(true)
  }

  const activeBrowsers = browsers.filter(b => b.active)
  const inactiveBrowsers = browsers.filter(b => !b.active)

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    })
  }

  const daysUntilExpiry = (expiresAt: string) => {
    const days = Math.ceil((new Date(expiresAt).getTime() - Date.now()) / (1000 * 60 * 60 * 24))
    return days
  }

  if (isLoading) {
    return (
      <div className="flex justify-center py-12">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  if (isError) {
    return <QueryError error={error} resource="trusted browsers" />
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Trusted Browsers</h1>
          <p className="text-muted-foreground">Manage browsers that can skip MFA verification</p>
        </div>
        <div className="flex gap-2">
          {browsers.length > 0 && (
            <Button variant="outline" onClick={() => setRevokeAllDialog(true)}>
              <Trash2 className="h-4 w-4 mr-2" />
              Revoke All
            </Button>
          )}
          {!checkResult?.trusted && (
            <Button onClick={() => setTrustDialog(true)}>
              <Shield className="h-4 w-4 mr-2" />
              Trust This Browser
            </Button>
          )}
        </div>
      </div>

      {/* Current Browser Status */}
      <Card className={checkResult?.trusted ? 'border-green-200 bg-green-50' : 'border-amber-200 bg-amber-50'}>
        <CardContent className="pt-4">
          <div className="flex items-center gap-3">
            {checkResult?.trusted ? (
              <>
                <CheckCircle2 className="h-5 w-5 text-green-600" />
                <div>
                  <p className="font-medium text-green-900">This browser is trusted</p>
                  <p className="text-sm text-green-800">
                    You won't be asked for MFA on this browser until {checkResult.expires_at && formatDate(checkResult.expires_at)}
                  </p>
                </div>
              </>
            ) : (
              <>
                <AlertTriangle className="h-5 w-5 text-amber-600" />
                <div>
                  <p className="font-medium text-amber-900">This browser is not trusted</p>
                  <p className="text-sm text-amber-800">
                    You will be prompted for MFA verification on each login
                  </p>
                </div>
              </>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Info Card */}
      <Card>
        <CardContent className="pt-4">
          <div className="flex items-start gap-3">
            <Shield className="h-5 w-5 text-blue-600 mt-0.5" />
            <div>
              <p className="font-medium">How Trusted Browsers Work</p>
              <ul className="text-sm text-muted-foreground mt-1 space-y-1">
                <li>When you trust a browser, you won't need to verify MFA for 30 days</li>
                <li>Trust is based on your browser fingerprint and IP address range</li>
                <li>If you sign in from a new location, you may still be asked for MFA</li>
                <li>Revoke trust if you lose access to a device or suspect compromise</li>
              </ul>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Active Browsers */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <CheckCircle2 className="h-5 w-5 text-green-600" />
            Active Trusted Browsers
          </CardTitle>
          <CardDescription>Browsers that can skip MFA verification</CardDescription>
        </CardHeader>
        <CardContent>
          {activeBrowsers.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <Monitor className="h-12 w-12 mx-auto mb-3 opacity-40" />
              <p>No active trusted browsers</p>
            </div>
          ) : (
            <div className="space-y-3">
              {activeBrowsers.map((browser) => (
                <div
                  key={browser.id}
                  className="flex items-center justify-between p-4 border rounded-lg bg-white"
                >
                  <div className="flex items-center gap-4">
                    <Monitor className="h-8 w-8 text-muted-foreground" />
                    <div>
                      <div className="flex items-center gap-2">
                        <p className="font-medium">{browser.name}</p>
                        <Badge className="bg-green-100 text-green-800">Active</Badge>
                      </div>
                      <div className="flex items-center gap-4 text-sm text-muted-foreground mt-1">
                        <span className="flex items-center gap-1">
                          <Globe className="h-3 w-3" />
                          {browser.ip_address}
                        </span>
                        <span className="flex items-center gap-1">
                          <Clock className="h-3 w-3" />
                          Expires in {daysUntilExpiry(browser.expires_at)} days
                        </span>
                      </div>
                      {browser.last_used_at && (
                        <p className="text-xs text-muted-foreground mt-1">
                          Last used: {formatDate(browser.last_used_at)}
                        </p>
                      )}
                    </div>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => openRevoke(browser)}
                    className="text-red-600"
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Inactive/Revoked Browsers */}
      {inactiveBrowsers.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <XCircle className="h-5 w-5 text-gray-400" />
              Expired or Revoked
            </CardTitle>
            <CardDescription>These browsers are no longer trusted</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {inactiveBrowsers.map((browser) => (
                <div
                  key={browser.id}
                  className="flex items-center justify-between p-4 border rounded-lg bg-gray-50 opacity-60"
                >
                  <div className="flex items-center gap-4">
                    <Monitor className="h-8 w-8 text-muted-foreground" />
                    <div>
                      <div className="flex items-center gap-2">
                        <p className="font-medium">{browser.name}</p>
                        {browser.revoked ? (
                          <Badge variant="secondary">Revoked</Badge>
                        ) : (
                          <Badge variant="secondary">Expired</Badge>
                        )}
                      </div>
                      <p className="text-sm text-muted-foreground">
                        {browser.revoked ? 'Revoked' : 'Expired'}: {formatDate(browser.expires_at)}
                      </p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Trust Dialog */}
      <Dialog open={trustDialog} onOpenChange={setTrustDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Trust This Browser?</DialogTitle>
            <DialogDescription>
              By trusting this browser, you won't need to complete MFA verification for the next 30 days.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="bg-amber-50 border border-amber-200 rounded-lg p-4">
              <div className="flex items-start gap-3">
                <AlertTriangle className="h-5 w-5 text-amber-600 mt-0.5" />
                <div className="text-sm text-amber-800">
                  <p className="font-medium">Security Notice</p>
                  <p>Only trust browsers on devices you own and control. Do not trust shared or public computers.</p>
                </div>
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setTrustDialog(false)}>Cancel</Button>
            <Button onClick={() => trustMutation.mutate()}>
              <Shield className="h-4 w-4 mr-2" />
              Trust This Browser
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Revoke Dialog */}
      <AlertDialog open={revokeDialog} onOpenChange={setRevokeDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Revoke Browser Trust?</AlertDialogTitle>
            <AlertDialogDescription>
              This will require MFA verification the next time you sign in from "{selectedBrowser?.name}".
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => selectedBrowser && revokeMutation.mutate(selectedBrowser.id)}
              className="bg-red-600 hover:bg-red-700"
            >
              Revoke Trust
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Revoke All Dialog */}
      <AlertDialog open={revokeAllDialog} onOpenChange={setRevokeAllDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Revoke All Trusted Browsers?</AlertDialogTitle>
            <AlertDialogDescription>
              This will require MFA verification on all your devices. You'll need to trust browsers again after signing in.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => revokeAllMutation.mutate()}
              className="bg-red-600 hover:bg-red-700"
            >
              Revoke All
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
