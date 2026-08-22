import { useState, useMemo, useCallback } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { QRCodeCanvas } from 'qrcode.react'
import { useNavigate } from 'react-router-dom'
import { Laptop, Smartphone, Apple, Monitor, Copy, CheckCircle2, Loader2, ArrowLeft } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Button } from '../components/ui/button'
import { Badge } from '../components/ui/badge'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'
import { QueryError } from '../components/query-error'

type OSKey = 'windows' | 'macos' | 'linux' | 'android' | 'ios'

const OSES: { key: OSKey; label: string; icon: typeof Laptop }[] = [
  { key: 'windows', label: 'Windows', icon: Monitor },
  { key: 'macos', label: 'macOS', icon: Apple },
  { key: 'linux', label: 'Linux', icon: Laptop },
  { key: 'android', label: 'Android', icon: Smartphone },
  { key: 'ios', label: 'iPhone / iPad', icon: Apple },
]

function detectOS(): OSKey {
  const ua = navigator.userAgent.toLowerCase()
  if (/android/.test(ua)) return 'android'
  if (/iphone|ipad|ipod/.test(ua)) return 'ios'
  if (/mac os x/.test(ua)) return 'macos'
  if (/linux/.test(ua)) return 'linux'
  return 'windows'
}

interface EnrollSession {
  id: string
  code: string
  deep_link: string
  server: string
  expires_at: string
}

interface AgentManifestEntry {
  url: string
  version?: string
}

export function AddDevicePage() {
  const navigate = useNavigate()
  const { toast } = useToast()
  const [os, setOs] = useState<OSKey>(detectOS())

  // Per-OS installer manifest (Phase 2 populates /downloads/agent-manifest.json).
  // Absent today → the wizard still works; we just skip the download button.
  const { data: manifest } = useQuery({
    queryKey: ['agent-manifest'],
    queryFn: () => api.get<Record<string, AgentManifestEntry>>('/downloads/agent-manifest.json'),
    retry: false,
    staleTime: 5 * 60_000,
  })
  const installer = manifest?.[os]

  // Create an enrollment session on demand ("Connect this device").
  const createSession = useMutation({
    mutationFn: () => api.post<EnrollSession>('/api/v1/access/agent/enroll/session', {}),
    onError: (e: Error) =>
      toast({ title: 'Could not start', description: e.message, variant: 'destructive' }),
  })
  const session = createSession.data

  // Poll the session until the device connects.
  const { data: status, isError, error } = useQuery({
    queryKey: ['enroll-session-status', session?.id],
    queryFn: () =>
      api.get<{ status: string; agent_id: string; device_trusted: boolean }>(
        `/api/v1/access/agent/enroll/session/${session!.id}/status`
      ),
    enabled: !!session?.id,
    refetchInterval: (q) =>
      (q.state.data as { status?: string } | undefined)?.status === 'enrolled' ? false : 3000,
  })
  const done = status?.status === 'enrolled'

  const copy = useCallback(
    (text: string, what: string) => {
      navigator.clipboard.writeText(text)
      toast({ title: 'Copied', description: `${what} copied to clipboard.` })
    },
    [toast]
  )

  const androidNote = useMemo(() => os === 'android' || os === 'ios', [os])

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <div>
        <Button variant="ghost" size="sm" className="mb-2 -ml-2" onClick={() => navigate('/my-devices')}>
          <ArrowLeft className="mr-1.5 h-4 w-4" /> My Devices
        </Button>
        <h1 className="text-2xl font-bold tracking-tight">Add a device to the network</h1>
        <p className="text-muted-foreground">
          Connect this device to Zero Trust access in three steps — no keys to copy.
        </p>
      </div>

      {/* Step 1 — pick the OS */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">1. Choose your device type</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-2">
            {OSES.map(({ key, label, icon: Icon }) => (
              <Button
                key={key}
                variant={os === key ? 'default' : 'outline'}
                size="sm"
                onClick={() => setOs(key)}
              >
                <Icon className="mr-1.5 h-4 w-4" /> {label}
              </Button>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Step 2 — get the app */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">2. Install the OpenIDX app</CardTitle>
          <CardDescription>
            {androidNote
              ? 'Install the OpenIDX app on your phone, then scan the code below from inside the app.'
              : 'Install the OpenIDX client for your operating system, then continue below.'}
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap items-center gap-3">
          {installer ? (
            <Button asChild size="sm">
              <a href={installer.url}>Download for {OSES.find((o) => o.key === os)?.label}</a>
            </Button>
          ) : (
            <p className="text-sm text-muted-foreground">
              Installer for {OSES.find((o) => o.key === os)?.label} is provided by your administrator.
            </p>
          )}
        </CardContent>
      </Card>

      {/* Step 3 — connect */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">3. Connect this device</CardTitle>
        </CardHeader>
        <CardContent>
          {!session ? (
            <Button onClick={() => createSession.mutate()} disabled={createSession.isPending}>
              {createSession.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Generate connect code
            </Button>
          ) : done ? (
            <div className="flex flex-col items-center gap-3 py-6 text-center">
              <CheckCircle2 className="h-12 w-12 text-green-600" />
              <p className="text-lg font-medium">Device connected</p>
              <Badge variant={status?.device_trusted ? 'default' : 'secondary'}>
                {status?.device_trusted ? 'Trusted — full access' : 'Pending trust approval'}
              </Badge>
              <Button className="mt-2" onClick={() => navigate('/my-devices')}>
                Done
              </Button>
            </div>
          ) : isError ? (
            <QueryError error={error} resource="enrollment status" />
          ) : (
            <div className="flex flex-col items-center gap-4">
              <div className="rounded-lg border bg-background p-4">
                <QRCodeCanvas value={session.deep_link} size={180} includeMargin />
              </div>
              <p className="text-sm text-muted-foreground">
                Scan this in the OpenIDX app, or open the link on this device.
              </p>
              <div className="flex flex-wrap justify-center gap-2">
                <Button asChild size="sm">
                  <a href={session.deep_link}>Open in app</a>
                </Button>
                <Button variant="outline" size="sm" onClick={() => copy(session.code, 'Connect code')}>
                  <Copy className="mr-1.5 h-3.5 w-3.5" /> Copy code
                </Button>
              </div>
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <Loader2 className="h-4 w-4 animate-spin" /> Waiting for this device to connect…
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
