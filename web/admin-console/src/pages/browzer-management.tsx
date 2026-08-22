import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import {
  Globe, RefreshCw, Shield, Server, Clock,
  AlertTriangle, CheckCircle, FileKey, ExternalLink,
} from 'lucide-react'
import { api } from '../lib/api'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs'
import { useToast } from '../hooks/use-toast'
import { QueryError } from '../components/query-error'

interface BrowZerTarget {
  vhost: string
  service: string
  path: string
  scheme: string
}

interface BrowZerDomainConfig {
  domain: string
  cert_type: string
  cert_subject: string
  cert_issuer: string
  cert_not_before: string
  cert_not_after: string
  cert_fingerprint: string
  cert_san: string[]
  custom_cert_uploaded_at: string | null
  previous_domain: string | null
  domain_changed_at: string | null
}

interface BrowZerManagementStatus {
  browzer_enabled: boolean
  domain: string
  bootstrapper_url: string
  cert_type: string
  cert_subject: string
  cert_issuer: string
  cert_not_after: string
  cert_fingerprint: string
  cert_san: string[]
  cert_days_left: number
  targets_count: number
  targets: BrowZerTarget[]
  domain_config: BrowZerDomainConfig | null
}

export function BrowZerManagementPage() {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const [newDomain, setNewDomain] = useState('')

  const { data: status, isLoading, isError, error } = useQuery<BrowZerManagementStatus>({
    queryKey: ['browzer-management'],
    queryFn: () => api.get('/api/v1/access/ziti/browzer/management'),
    refetchInterval: 10000,
  })

  const domainMutation = useMutation({
    mutationFn: (domain: string) => api.put('/api/v1/access/ziti/browzer/domain', { domain }),
    onSuccess: () => {
      toast({ title: 'Domain changed', description: 'Config files regenerated. Bootstrapper will restart.' })
      queryClient.invalidateQueries({ queryKey: ['browzer-management'] })
      setNewDomain('')
    },
    onError: (err: Error) => {
      toast({ title: 'Domain change failed', description: err.message, variant: 'destructive' })
    },
  })

  const restartMutation = useMutation({
    mutationFn: () => api.post('/api/v1/access/ziti/browzer/restart'),
    onSuccess: () => {
      toast({ title: 'Restart triggered', description: 'The bootstrapper will restart within a few seconds.' })
    },
    onError: (err: Error) => {
      toast({ title: 'Restart failed', description: err.message, variant: 'destructive' })
    },
  })

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    )
  }

  if (isError) return <QueryError error={error} resource="BrowZer management" />

  const certExpiringSoon = status && status.cert_days_left > 0 && status.cert_days_left <= 30

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">BrowZer Bootstrapper Management</h1>
          <p className="text-muted-foreground">
            Manage TLS certificates, domain, and bootstrapper lifecycle
          </p>
        </div>
        <div className="flex items-center gap-2">
          {status?.browzer_enabled ? (
            <Badge variant="default" className="gap-1">
              <CheckCircle className="h-3 w-3" /> Enabled
            </Badge>
          ) : (
            <Badge variant="secondary" className="gap-1">Disabled</Badge>
          )}
        </div>
      </div>

      {/* Status Banner */}
      {certExpiringSoon && (
        <div className="flex items-center gap-2 rounded-lg border border-yellow-500/50 bg-yellow-500/10 p-4">
          <AlertTriangle className="h-5 w-5 text-yellow-500" />
          <span className="text-sm">
            Certificate expires in <strong>{status?.cert_days_left} days</strong>.
            {status?.cert_type === 'self_signed' ? ' Consider uploading a CA-signed certificate.' : ' Upload a renewed certificate.'}
          </span>
        </div>
      )}

      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="certificates">Certificates</TabsTrigger>
          <TabsTrigger value="domain">Domain</TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {/* Status Card */}
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Status</CardTitle>
                <Shield className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">BrowZer</span>
                    <Badge variant={status?.browzer_enabled ? 'default' : 'secondary'}>
                      {status?.browzer_enabled ? 'Enabled' : 'Disabled'}
                    </Badge>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">Domain</span>
                    <span className="font-mono text-xs">{status?.domain}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">URL</span>
                    <a href={status?.bootstrapper_url} target="_blank" rel="noopener noreferrer"
                       className="font-mono text-xs text-blue-500 hover:underline">
                      {status?.bootstrapper_url}
                    </a>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Certificate Summary Card */}
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Certificate</CardTitle>
                <FileKey className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">Type</span>
                    <Badge variant={status?.cert_type === 'custom' ? 'default' : 'outline'}>
                      {status?.cert_type === 'custom' ? 'CA-Signed' : 'Self-Signed'}
                    </Badge>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">Issuer</span>
                    <span className="text-xs truncate max-w-[180px]">{status?.cert_issuer || 'N/A'}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">Expires</span>
                    <span className={`text-xs ${certExpiringSoon ? 'text-yellow-500 font-semibold' : ''}`}>
                      {status?.cert_not_after ? new Date(status.cert_not_after).toLocaleDateString() : 'N/A'}
                      {status?.cert_days_left !== undefined && status.cert_days_left > 0
                        ? ` (${status.cert_days_left}d)`
                        : ''}
                    </span>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Targets Card */}
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Targets</CardTitle>
                <Server className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold">{status?.targets_count ?? 0}</div>
                <p className="text-xs text-muted-foreground mt-1">Active bootstrapper targets</p>
                {status?.targets && status.targets.length > 0 && (
                  <div className="mt-3 space-y-1">
                    {status.targets.map((t, i) => (
                      <div key={i} className="flex items-center gap-2 text-xs">
                        <Globe className="h-3 w-3 text-muted-foreground" />
                        <span className="font-mono">{t.vhost}</span>
                        <span className="text-muted-foreground">{t.service}</span>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Actions */}
          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-medium">Actions</CardTitle>
            </CardHeader>
            <CardContent>
              <Button
                onClick={() => restartMutation.mutate()}
                disabled={restartMutation.isPending}
                variant="outline"
                className="gap-2"
              >
                <RefreshCw className={`h-4 w-4 ${restartMutation.isPending ? 'animate-spin' : ''}`} />
                Restart Bootstrapper
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Certificates Tab */}
        <TabsContent value="certificates" className="space-y-4">
          {/* Certificate Summary */}
          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-medium">BrowZer Certificate</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid gap-3 sm:grid-cols-2">
                <div>
                  <p className="text-xs text-muted-foreground">Type</p>
                  <Badge variant={status?.cert_type === 'custom' ? 'default' : 'outline'}>
                    {status?.cert_type === 'custom' ? 'CA-Signed' : 'Self-Signed'}
                  </Badge>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Issuer</p>
                  <p className="text-sm truncate">{status?.cert_issuer || 'N/A'}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Expires</p>
                  <p className={`text-sm ${certExpiringSoon ? 'text-yellow-500 font-semibold' : ''}`}>
                    {status?.cert_not_after ? new Date(status.cert_not_after).toLocaleDateString() : 'N/A'}
                    {status?.cert_days_left !== undefined && status.cert_days_left > 0
                      ? ` (${status.cert_days_left}d)`
                      : ''}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Subject</p>
                  <p className="text-sm font-mono truncate">{status?.cert_subject || 'N/A'}</p>
                </div>
              </div>
              <div className="mt-4 pt-4 border-t">
                <p className="text-sm text-muted-foreground mb-3">
                  Platform certificates are managed centrally and shared across all TLS services
                  including BrowZer, OAuth proxy, Ziti controller, and APISIX.
                </p>
                <Button
                  onClick={() => navigate('/certificates')}
                  className="gap-2"
                >
                  <FileKey className="h-4 w-4" />
                  Manage Certificates
                  <ExternalLink className="h-3 w-3" />
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Domain Tab */}
        <TabsContent value="domain" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-medium">Current Domain</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-center gap-3">
                <Globe className="h-5 w-5 text-muted-foreground" />
                <span className="text-lg font-mono">{status?.domain}</span>
                {status?.domain_config?.previous_domain && (
                  <span className="text-xs text-muted-foreground">
                    (previously: {status.domain_config.previous_domain})
                  </span>
                )}
              </div>
              {status?.domain_config?.domain_changed_at && (
                <p className="text-xs text-muted-foreground mt-2">
                  <Clock className="h-3 w-3 inline mr-1" />
                  Last changed: {new Date(status.domain_config.domain_changed_at).toLocaleString()}
                </p>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-medium">Change Domain</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <p className="text-sm text-muted-foreground">
                Changing the domain will update proxy routes, OAuth redirect URIs, and regenerate
                bootstrapper targets. If no custom certificate is uploaded, a new self-signed cert
                will be generated for the new domain.
              </p>
              <div className="flex gap-2">
                <Input
                  placeholder="e.g. browzer.tdv.org"
                  value={newDomain}
                  onChange={(e) => setNewDomain(e.target.value)}
                  className="max-w-sm font-mono"
                />
                <Button
                  onClick={() => {
                    if (newDomain.trim()) domainMutation.mutate(newDomain.trim())
                  }}
                  disabled={domainMutation.isPending || !newDomain.trim()}
                  className="gap-2"
                >
                  <Globe className={`h-4 w-4 ${domainMutation.isPending ? 'animate-spin' : ''}`} />
                  Save Domain
                </Button>
              </div>

              <div className="rounded-lg border border-yellow-500/50 bg-yellow-500/10 p-4 space-y-2">
                <p className="text-sm font-medium flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-yellow-500" />
                  Important: Cascading Updates
                </p>
                <ul className="text-xs text-muted-foreground space-y-1 list-disc list-inside">
                  <li>All BrowZer proxy routes will be updated to use the new domain</li>
                  <li>OAuth client redirect URIs will be updated</li>
                  <li>Bootstrapper config will be regenerated</li>
                  <li>DNS records must point the new domain to your server</li>
                  <li>Some containers may need manual restart after the change</li>
                </ul>
              </div>
            </CardContent>
          </Card>

          {/* Post-change instructions */}
          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-yellow-500" />
                After Domain Change
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground mb-2">
                After changing the domain, restart these containers:
              </p>
              <pre className="bg-muted p-3 rounded text-xs font-mono">
docker restart openidx-oauth-tls-proxy openidx-ziti-controller-proxy openidx-ziti-router
              </pre>
              <p className="text-sm text-muted-foreground mt-2">
                The BrowZer bootstrapper restarts automatically.
              </p>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
