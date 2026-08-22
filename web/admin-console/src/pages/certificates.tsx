import { useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Upload, RefreshCw, Server, Clock,
  AlertTriangle, Trash2, Lock, Unlock,
} from 'lucide-react'
import { api } from '../lib/api'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs'
import { useToast } from '../hooks/use-toast'
import { ConfirmAction } from '../components/confirm-action'
import { QueryError } from '../components/query-error'

interface PlatformCertConsumer {
  name: string
  port: number
  protocol: string
  status: string
  description: string
  restart_hint: string
}

interface PlatformCertInfo {
  cert_type: string
  subject: string
  issuer: string
  not_before: string
  not_after: string
  days_left: number
  fingerprint: string
  sans: string[]
  serial_number: string
  uploaded_at: string | null
  consumers: PlatformCertConsumer[]
}

interface APISIXSSLConfig {
  enabled: boolean
  last_updated: string
  cert_fingerprint: string
}

interface CertExpiryAlert {
  source: string
  name: string
  days_left: number
  severity: string
  not_after: string
}

interface PlatformCertHealthStatus {
  platform: PlatformCertInfo | null
  apisix: APISIXSSLConfig | null
  expiry_alerts: CertExpiryAlert[]
}

interface ZitiCertificate {
  id: string
  name: string
  cert_type: string
  subject: string
  issuer: string
  fingerprint: string
  not_before: string
  not_after: string
  auto_renew: boolean
  status: string
  days_until_expiry: number
}

export function CertificatesPage() {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const certFileRef = useRef<HTMLInputElement>(null)
  const keyFileRef = useRef<HTMLInputElement>(null)

  const { data: certStatus, isLoading, isError, error } = useQuery<PlatformCertHealthStatus>({
    queryKey: ['certificates-status'],
    queryFn: () => api.get('/api/v1/access/certificates/status'),
    refetchInterval: 15000,
  })

  const { data: zitiCertsRaw } = useQuery({
    queryKey: ['ziti-certificates'],
    queryFn: () => api.get('/api/v1/access/ziti/certificates'),
  })
  const zitiCerts: ZitiCertificate[] = Array.isArray(zitiCertsRaw) ? zitiCertsRaw : []

  const uploadMutation = useMutation({
    mutationFn: async () => {
      const certInput = certFileRef.current
      const keyInput = keyFileRef.current
      if (!certInput?.files?.[0] || !keyInput?.files?.[0]) {
        throw new Error('Please select both certificate and key files')
      }
      const formData = new FormData()
      formData.append('cert', certInput.files[0])
      formData.append('key', keyInput.files[0])
      return api.postFormData('/api/v1/access/certificates/platform', formData)
    },
    onSuccess: () => {
      toast({ title: 'Certificate uploaded', description: 'All platform consumers will use the new certificate.' })
      queryClient.invalidateQueries({ queryKey: ['certificates-status'] })
      if (certFileRef.current) certFileRef.current.value = ''
      if (keyFileRef.current) keyFileRef.current.value = ''
    },
    onError: (err: Error) => {
      toast({ title: 'Upload failed', description: err.message, variant: 'destructive' })
    },
  })

  const revertMutation = useMutation({
    mutationFn: () => api.delete('/api/v1/access/certificates/platform'),
    onSuccess: () => {
      toast({ title: 'Reverted to self-signed certificate' })
      queryClient.invalidateQueries({ queryKey: ['certificates-status'] })
    },
    onError: (err: Error) => {
      toast({ title: 'Revert failed', description: err.message, variant: 'destructive' })
    },
  })

  const enableApisixMutation = useMutation({
    mutationFn: () => api.post('/api/v1/access/certificates/apisix/enable'),
    onSuccess: () => {
      toast({ title: 'APISIX HTTPS enabled', description: 'Available at https://localhost:8443' })
      queryClient.invalidateQueries({ queryKey: ['certificates-status'] })
    },
    onError: (err: Error) => {
      toast({ title: 'Failed to enable APISIX SSL', description: err.message, variant: 'destructive' })
    },
  })

  const disableApisixMutation = useMutation({
    mutationFn: () => api.post('/api/v1/access/certificates/apisix/disable'),
    onSuccess: () => {
      toast({ title: 'APISIX HTTPS disabled' })
      queryClient.invalidateQueries({ queryKey: ['certificates-status'] })
    },
    onError: (err: Error) => {
      toast({ title: 'Failed to disable APISIX SSL', description: err.message, variant: 'destructive' })
    },
  })

  const rotateMutation = useMutation({
    mutationFn: (id: string) => api.post(`/api/v1/access/ziti/certificates/${id}/rotate`, {}),
    onSuccess: () => {
      toast({ title: 'Certificate rotated' })
      queryClient.invalidateQueries({ queryKey: ['ziti-certificates'] })
    },
    onError: () => {
      toast({ title: 'Rotation failed', variant: 'destructive' })
    },
  })

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    )
  }

  if (isError) return <QueryError error={error} resource="certificates" />

  const platform = certStatus?.platform
  const apisix = certStatus?.apisix
  const alerts = certStatus?.expiry_alerts || []
  const certExpiringSoon = platform && platform.days_left > 0 && platform.days_left <= 30

  const expiryBadge = (days: number) => {
    const variant: 'default' | 'destructive' | 'secondary' =
      days < 7 ? 'destructive' : days <= 30 ? 'secondary' : 'default'
    const label = days <= 0 ? 'Expired' : `${days}d remaining`
    return <Badge variant={variant}>{label}</Badge>
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Certificate Management</h1>
        <p className="text-muted-foreground">
          Manage TLS certificates across the OpenIDX platform
        </p>
      </div>

      {/* Expiry Alert Banner */}
      {alerts.length > 0 && (
        <div className="flex items-center gap-2 rounded-lg border border-yellow-500/50 bg-yellow-500/10 p-4">
          <AlertTriangle className="h-5 w-5 text-yellow-500 shrink-0" />
          <div>
            {alerts.map((alert, i) => (
              <p key={i} className="text-sm">
                <strong>{alert.name}</strong> expires in <strong>{alert.days_left} days</strong>
                {alert.severity === 'critical' && ' — action required!'}
              </p>
            ))}
          </div>
        </div>
      )}

      <Tabs defaultValue="platform">
        <TabsList>
          <TabsTrigger value="platform">Platform TLS</TabsTrigger>
          <TabsTrigger value="apisix">API Gateway</TabsTrigger>
          <TabsTrigger value="ziti">Ziti Certificates</TabsTrigger>
        </TabsList>

        {/* Platform TLS Tab */}
        <TabsContent value="platform" className="space-y-4">
          {/* Certificate Details */}
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Platform TLS Certificate</CardTitle>
              <Badge variant={platform?.cert_type === 'custom' ? 'default' : 'outline'}>
                {platform?.cert_type === 'custom' ? 'CA-Signed' : 'Self-Signed'}
              </Badge>
            </CardHeader>
            <CardContent>
              <div className="grid gap-3 sm:grid-cols-2">
                <div>
                  <p className="text-xs text-muted-foreground">Subject</p>
                  <p className="text-sm font-mono">{platform?.subject || 'N/A'}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Issuer</p>
                  <p className="text-sm font-mono">{platform?.issuer || 'N/A'}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Valid From</p>
                  <p className="text-sm">{platform?.not_before ? new Date(platform.not_before).toLocaleDateString() : 'N/A'}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Expires</p>
                  <p className={`text-sm ${certExpiringSoon ? 'text-yellow-500 font-semibold' : ''}`}>
                    {platform?.not_after ? new Date(platform.not_after).toLocaleDateString() : 'N/A'}
                    {platform?.days_left !== undefined && platform.days_left > 0
                      ? ` (${platform.days_left} days left)`
                      : ''}
                  </p>
                </div>
                <div className="sm:col-span-2">
                  <p className="text-xs text-muted-foreground">Subject Alternative Names</p>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {platform?.sans?.length ? platform.sans.map((san, i) => (
                      <Badge key={i} variant="outline" className="text-xs font-mono">{san}</Badge>
                    )) : <span className="text-sm text-muted-foreground">None</span>}
                  </div>
                </div>
                <div className="sm:col-span-2">
                  <p className="text-xs text-muted-foreground">SHA-256 Fingerprint</p>
                  <p className="text-xs font-mono break-all">{platform?.fingerprint || 'N/A'}</p>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Consumers */}
          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-medium">Certificate Consumers</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                {platform?.consumers?.map((consumer, i) => (
                  <div key={i} className="flex items-start gap-3 rounded-lg border p-3">
                    <Server className="h-4 w-4 mt-0.5 text-muted-foreground shrink-0" />
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium truncate">{consumer.name}</span>
                        <Badge variant={consumer.status === 'active' ? 'default' : 'secondary'} className="text-[10px] px-1.5 py-0">
                          {consumer.status}
                        </Badge>
                      </div>
                      <p className="text-xs text-muted-foreground">{consumer.description}</p>
                      <p className="text-xs font-mono text-muted-foreground mt-1">
                        {consumer.protocol} :{consumer.port}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Upload Custom Certificate */}
          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-medium">Upload Custom Certificate</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <p className="text-sm text-muted-foreground">
                Upload a PEM-encoded certificate and private key from a Certificate Authority.
                This certificate will be used by all platform TLS consumers listed above.
              </p>
              <div className="grid gap-4 sm:grid-cols-2">
                <div>
                  <label className="text-sm font-medium mb-1 block">Certificate (.pem, .crt)</label>
                  <Input ref={certFileRef} type="file" accept=".pem,.crt,.cer" />
                </div>
                <div>
                  <label className="text-sm font-medium mb-1 block">Private Key (.pem, .key)</label>
                  <Input ref={keyFileRef} type="file" accept=".pem,.key" />
                </div>
              </div>
              <div className="flex gap-2">
                <Button
                  onClick={() => uploadMutation.mutate()}
                  disabled={uploadMutation.isPending}
                  className="gap-2"
                >
                  <Upload className={`h-4 w-4 ${uploadMutation.isPending ? 'animate-spin' : ''}`} />
                  Upload Certificate
                </Button>
                {platform?.cert_type === 'custom' && (
                  <ConfirmAction
                    title="Revert to self-signed certificate?"
                    description="This removes the uploaded CA-signed platform TLS certificate and restores the auto-generated self-signed certificate. Every platform TLS consumer (APISIX, OAuth proxy, Ziti controller/router) will serve the self-signed cert, and clients that pinned or trusted the CA-signed cert will see TLS errors until reconfigured. This cannot be undone without re-uploading the certificate."
                    destructive
                    requireReason
                    confirmLabel="Revert to Self-Signed"
                    onConfirm={() => revertMutation.mutateAsync()}
                  >
                    {(open) => (
                      <Button
                        onClick={open}
                        disabled={revertMutation.isPending}
                        variant="outline"
                        className="gap-2"
                      >
                        <Trash2 className="h-4 w-4" />
                        Revert to Self-Signed
                      </Button>
                    )}
                  </ConfirmAction>
                )}
              </div>
            </CardContent>
          </Card>

          {/* Post-change instructions */}
          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-yellow-500" />
                After Certificate Changes
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground mb-2">
                The BrowZer bootstrapper and APISIX restart automatically. Other consumers need manual restart:
              </p>
              <pre className="bg-muted p-3 rounded text-xs font-mono">
docker restart openidx-oauth-tls-proxy openidx-ziti-controller-proxy openidx-ziti-router
              </pre>
            </CardContent>
          </Card>
        </TabsContent>

        {/* API Gateway Tab */}
        <TabsContent value="apisix" className="space-y-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">APISIX HTTPS</CardTitle>
              {apisix?.enabled ? (
                <Badge variant="default" className="gap-1">
                  <Lock className="h-3 w-3" /> Enabled
                </Badge>
              ) : (
                <Badge variant="secondary" className="gap-1">
                  <Unlock className="h-3 w-3" /> Disabled
                </Badge>
              )}
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-3 sm:grid-cols-2">
                <div>
                  <p className="text-xs text-muted-foreground">HTTP Endpoint</p>
                  <p className="text-sm font-mono">http://localhost:8088</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">HTTPS Endpoint</p>
                  <p className={`text-sm font-mono ${apisix?.enabled ? '' : 'text-muted-foreground'}`}>
                    {apisix?.enabled ? 'https://localhost:8443' : 'Not configured'}
                  </p>
                </div>
                {apisix?.last_updated && (
                  <div className="sm:col-span-2">
                    <p className="text-xs text-muted-foreground">Last Updated</p>
                    <p className="text-sm">
                      <Clock className="h-3 w-3 inline mr-1" />
                      {new Date(apisix.last_updated).toLocaleString()}
                    </p>
                  </div>
                )}
              </div>

              <div className="flex gap-2">
                {apisix?.enabled ? (
                  <Button
                    onClick={() => disableApisixMutation.mutate()}
                    disabled={disableApisixMutation.isPending}
                    variant="outline"
                    className="gap-2"
                  >
                    <Unlock className="h-4 w-4" />
                    Disable HTTPS
                  </Button>
                ) : (
                  <Button
                    onClick={() => enableApisixMutation.mutate()}
                    disabled={enableApisixMutation.isPending}
                    className="gap-2"
                  >
                    <Lock className={`h-4 w-4 ${enableApisixMutation.isPending ? 'animate-spin' : ''}`} />
                    Enable HTTPS
                  </Button>
                )}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-medium">How it works</CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="text-sm text-muted-foreground space-y-2 list-disc list-inside">
                <li>Enabling HTTPS injects the platform TLS certificate into the APISIX configuration</li>
                <li>APISIX automatically reloads when the configuration changes — no restart needed</li>
                <li>HTTPS is served on port <span className="font-mono">8443</span> using the same certificate as other platform services</li>
                <li>HTTP on port <span className="font-mono">8088</span> remains available regardless of HTTPS status</li>
                <li>When you upload a new platform certificate, APISIX SSL is automatically updated</li>
              </ul>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Ziti Certificates Tab */}
        <TabsContent value="ziti" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-medium">Ziti Internal Certificates</CardTitle>
            </CardHeader>
            <CardContent>
              {!zitiCerts || zitiCerts.length === 0 ? (
                <p className="text-sm text-muted-foreground">No Ziti certificates found.</p>
              ) : (
                <div className="space-y-3">
                  {/* Expiry alerts */}
                  {zitiCerts.filter(c => c.days_until_expiry <= 30 && c.days_until_expiry > 0).length > 0 && (
                    <div className="p-3 rounded-lg border border-yellow-500/50 bg-yellow-500/10">
                      <div className="flex items-center gap-2 mb-1">
                        <AlertTriangle className="h-4 w-4 text-yellow-500" />
                        <span className="text-sm font-medium">Certificates Expiring Soon</span>
                      </div>
                      {zitiCerts
                        .filter(c => c.days_until_expiry <= 30 && c.days_until_expiry > 0)
                        .map(cert => (
                          <div key={cert.id} className="flex items-center justify-between text-sm mt-1">
                            <span>{cert.name} — {cert.days_until_expiry}d remaining</span>
                            <ConfirmAction
                              title="Rotate this certificate?"
                              description="A new certificate is issued and the old certificate stops working once rotated. Anything still presenting the old certificate will fail until it picks up the new one."
                              destructive
                              confirmLabel="Rotate"
                              onConfirm={() => rotateMutation.mutate(cert.id)}
                            >
                              {(open) => (
                                <Button variant="outline" size="sm" onClick={open}>
                                  Rotate
                                </Button>
                              )}
                            </ConfirmAction>
                          </div>
                        ))}
                    </div>
                  )}

                  {/* Cert list */}
                  <div className="rounded-md border">
                    <table className="w-full">
                      <thead>
                        <tr className="border-b bg-muted/50">
                          <th className="p-2 text-left text-xs font-medium text-muted-foreground">Name</th>
                          <th className="p-2 text-left text-xs font-medium text-muted-foreground">Type</th>
                          <th className="p-2 text-left text-xs font-medium text-muted-foreground">Subject</th>
                          <th className="p-2 text-left text-xs font-medium text-muted-foreground">Expiry</th>
                          <th className="p-2 text-left text-xs font-medium text-muted-foreground">Auto Renew</th>
                          <th className="p-2 w-[80px]"></th>
                        </tr>
                      </thead>
                      <tbody>
                        {zitiCerts.map(cert => (
                          <tr key={cert.id} className="border-b hover:bg-muted/50">
                            <td className="p-2 text-sm font-medium">{cert.name}</td>
                            <td className="p-2"><Badge variant="outline" className="text-xs">{cert.cert_type}</Badge></td>
                            <td className="p-2 text-sm text-muted-foreground truncate max-w-[200px]">{cert.subject}</td>
                            <td className="p-2">{expiryBadge(cert.days_until_expiry)}</td>
                            <td className="p-2">
                              <Badge variant={cert.auto_renew ? 'default' : 'secondary'} className="text-xs">
                                {cert.auto_renew ? 'Yes' : 'No'}
                              </Badge>
                            </td>
                            <td className="p-2">
                              <ConfirmAction
                                title="Rotate this certificate?"
                                description="A new certificate is issued and the old certificate stops working once rotated. Anything still presenting the old certificate will fail until it picks up the new one."
                                destructive
                                confirmLabel="Rotate"
                                onConfirm={() => rotateMutation.mutate(cert.id)}
                              >
                                {(open) => (
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    onClick={open}
                                    disabled={rotateMutation.isPending}
                                    className="gap-1 text-xs"
                                  >
                                    <RefreshCw className="h-3 w-3" /> Rotate
                                  </Button>
                                )}
                              </ConfirmAction>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
