import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import {
  AppWindow,
  ArrowRight,
  Check,
  Database,
  Globe,
  Loader2,
  Monitor,
  Search,
  Send,
  Terminal,
} from 'lucide-react'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Input } from '../components/ui/input'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'
import { QueryError } from '../components/query-error'

// The user-facing contract. It deliberately describes a journey (from -> to on a
// port) and one action; nothing about how the connection is carried underneath.
interface ResourceAction {
  label: string
  kind: 'open_url' | 'broker_connect' | 'request'
  url?: string
  target?: string
}

interface MyResource {
  id: string
  name: string
  kind: 'web' | 'remote_desktop' | 'ssh' | 'database'
  from: string
  to: string
  port: number
  how: 'browser' | 'broker'
  status: 'ready' | 'request_access' | 'needs_setup'
  action: ResourceAction
  note?: string
}

interface MyResourcesResponse {
  resources: MyResource[]
  summary: { total: number; ready: number }
}

const KIND_META: Record<MyResource['kind'], { icon: typeof Globe; label: string }> = {
  web: { icon: Globe, label: 'Web app' },
  remote_desktop: { icon: Monitor, label: 'Remote desktop' },
  ssh: { icon: Terminal, label: 'Server (SSH)' },
  database: { icon: Database, label: 'Database' },
}

const STATUS_META: Record<
  MyResource['status'],
  { label: string; variant: 'default' | 'secondary' | 'outline' }
> = {
  ready: { label: 'Ready', variant: 'default' },
  request_access: { label: 'Approval needed', variant: 'secondary' },
  needs_setup: { label: 'Setup needed', variant: 'outline' },
}

export function MyNetworkPage() {
  const { toast } = useToast()
  const [search, setSearch] = useState('')
  const [busyId, setBusyId] = useState<string | null>(null)

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['my-network-resources'],
    queryFn: () => api.get<MyResourcesResponse>('/api/v1/access/my/resources'),
  })

  // Opens the session in a new tab. Used for anything the session broker renders.
  const connectMutation = useMutation({
    mutationFn: (entryId: string) =>
      api.post<{ connect_url: string }>(`/api/v1/access/pam/entries/${entryId}/connect`),
    onSuccess: (res) => {
      setBusyId(null)
      if (res?.connect_url) {
        window.open(res.connect_url, '_blank')
      }
    },
    onError: (error: Error) => {
      setBusyId(null)
      toast({
        title: 'Could not connect',
        description: error.message || 'Please try again, or ask an administrator.',
        variant: 'destructive',
      })
    },
  })

  const requestMutation = useMutation({
    mutationFn: (entryId: string) =>
      api.post(`/api/v1/access/pam/entries/${entryId}/request`, {
        reason: 'Requested from My Network',
      }),
    onSuccess: () => {
      setBusyId(null)
      toast({
        title: 'Request sent',
        description: 'You will be notified once it is approved.',
      })
      refetch()
    },
    onError: (error: Error) => {
      setBusyId(null)
      toast({
        title: 'Could not send request',
        description: error.message || 'Please try again later.',
        variant: 'destructive',
      })
    },
  })

  const runAction = (r: MyResource) => {
    setBusyId(r.id)
    switch (r.action.kind) {
      case 'open_url':
        setBusyId(null)
        if (r.action.url) window.open(r.action.url, '_blank')
        break
      case 'broker_connect':
        connectMutation.mutate(r.action.target || r.id)
        break
      case 'request':
        requestMutation.mutate(r.action.target || r.id)
        break
    }
  }

  const resources = data?.resources || []
  const term = search.trim().toLowerCase()
  const shown = term
    ? resources.filter(
        (r) =>
          r.name.toLowerCase().includes(term) ||
          r.to.toLowerCase().includes(term) ||
          KIND_META[r.kind]?.label.toLowerCase().includes(term)
      )
    : resources

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">My Network</h1>
        <p className="text-muted-foreground">
          Everything you can reach, and how to get there. Most of it opens right in this
          browser with nothing to install.
        </p>
      </div>

      {!isLoading && resources.length > 0 && (
        <div className="flex flex-wrap items-center gap-3">
          <Badge variant="default" className="gap-1">
            <Check className="h-3 w-3" />
            {data?.summary.ready ?? 0} ready to use
          </Badge>
          <span className="text-sm text-muted-foreground">
            {data?.summary.total ?? 0} total
          </span>
        </div>
      )}

      {resources.length > 0 && (
        <div className="relative max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            className="pl-10"
            placeholder="Search by name or address..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
      )}

      {isLoading ? (
        <p className="text-center py-12 text-muted-foreground">Loading your resources...</p>
      ) : isError ? (
        <QueryError error={error} resource="your network access" />
      ) : shown.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <AppWindow className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
            <p className="text-lg font-medium">
              {resources.length === 0 ? 'Nothing assigned yet' : 'No matches'}
            </p>
            <p className="text-muted-foreground">
              {resources.length === 0
                ? 'Ask your administrator for access, or request it from the Access Requests page.'
                : 'Try a different search.'}
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {shown.map((r) => {
            const meta = KIND_META[r.kind] || KIND_META.web
            const Icon = meta.icon
            const status = STATUS_META[r.status] || STATUS_META.needs_setup
            const busy = busyId === r.id
            return (
              <Card key={r.id} className="flex flex-col">
                <CardHeader className="pb-3">
                  <div className="flex items-start gap-3">
                    <div className="h-10 w-10 rounded-lg bg-blue-100 flex items-center justify-center shrink-0">
                      <Icon className="h-5 w-5 text-blue-600" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <CardTitle className="text-base truncate">{r.name}</CardTitle>
                      <div className="flex items-center gap-2 mt-1">
                        <Badge variant="outline" className="text-xs">
                          {meta.label}
                        </Badge>
                        <Badge variant={status.variant} className="text-xs">
                          {status.label}
                        </Badge>
                      </div>
                    </div>
                  </div>
                </CardHeader>

                <CardContent className="flex flex-col flex-1 gap-3">
                  {/* The where -> where sentence: the one thing users ask for. */}
                  <div className="flex items-center gap-2 text-sm text-muted-foreground">
                    <span>{r.from}</span>
                    <ArrowRight className="h-3.5 w-3.5 shrink-0" />
                    <span className="font-medium text-foreground truncate">
                      {r.to}
                      {r.port ? `:${r.port}` : ''}
                    </span>
                  </div>

                  {r.note && <p className="text-xs text-muted-foreground">{r.note}</p>}

                  {/* Exactly one primary action per resource. */}
                  <Button
                    className="mt-auto w-full"
                    disabled={busy}
                    onClick={() => runAction(r)}
                  >
                    {busy ? (
                      <>
                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                        Working...
                      </>
                    ) : (
                      <>
                        {r.action.kind === 'request' ? (
                          <Send className="mr-2 h-4 w-4" />
                        ) : (
                          <ArrowRight className="mr-2 h-4 w-4" />
                        )}
                        {r.action.label}
                      </>
                    )}
                  </Button>
                </CardContent>
              </Card>
            )
          })}
        </div>
      )}
    </div>
  )
}
