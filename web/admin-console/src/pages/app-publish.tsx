import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Upload,
  Search,
  RefreshCw,
  Trash2,
  Loader2,
  CheckCircle2,
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  Globe,
  Lock,
  Plus,
  Radar,
  ArrowRight,
  ExternalLink,
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Checkbox } from '../components/ui/checkbox'
import { Label } from '../components/ui/label'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '../components/ui/select'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogDescription,
} from '../components/ui/dialog'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../components/ui/table'
import { ConfirmAction } from '../components/confirm-action'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

// ---- Types ----

interface PublishedApp {
  id: string
  name: string
  description: string
  target_url: string
  spec_url: string
  status: string
  discovery_started_at: string | null
  discovery_completed_at: string | null
  discovery_error: string | null
  discovery_strategies: string[]
  total_paths_discovered: number
  total_paths_published: number
  public_host?: string
  landing_path?: string
  created_at: string
  updated_at: string
}

interface DiscoveredPath {
  id: string
  app_id: string
  path: string
  http_methods: string[]
  classification: string
  classification_source: string
  discovery_strategy: string
  suggested_policy: string
  require_auth: boolean
  allowed_roles: string[]
  require_device_trust: boolean
  published: boolean
  route_id: string | null
  metadata: Record<string, unknown>
  created_at: string
  updated_at: string
}

interface PathsResponse {
  paths: DiscoveredPath[]
  total: number
}

interface AppsResponse {
  apps: PublishedApp[]
  total: number
}

// ---- Classification helpers ----

const classificationColors: Record<string, string> = {
  critical: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
  sensitive: 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200',
  protected: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
  public: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
}

const classificationIcons: Record<string, React.ComponentType<{ className?: string }>> = {
  critical: ShieldAlert,
  sensitive: Lock,
  protected: ShieldCheck,
  public: Globe,
}

const statusColors: Record<string, string> = {
  pending: 'bg-muted text-foreground',
  discovering: 'bg-yellow-100 text-yellow-800',
  discovered: 'bg-green-100 text-green-800',
  published: 'bg-blue-100 text-blue-800',
  error: 'bg-red-100 text-red-800',
}

// ---- Component ----

export function AppPublishPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [activeTab, setActiveTab] = useState('apps')
  const [selectedApp, setSelectedApp] = useState<PublishedApp | null>(null)
  const [registerOpen, setRegisterOpen] = useState(false)
  const [publishOpen, setPublishOpen] = useState(false)
  const [search, setSearch] = useState('')
  const [classFilter, setClassFilter] = useState<string>('all')
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [registerForm, setRegisterForm] = useState({
    name: '',
    target_url: '',
    description: '',
    spec_url: '',
  })
  const [publishConfig, setPublishConfig] = useState({
    enable_ziti: false,
    enable_browzer: false,
  })
  const [publishAppOpen, setPublishAppOpen] = useState(false)
  const [publishAppTarget, setPublishAppTarget] = useState<PublishedApp | null>(null)
  const [publicHost, setPublicHost] = useState('')
  const [landingPath, setLandingPath] = useState('/')

  // ---- Queries ----

  const appsQuery = useQuery({
    queryKey: ['published-apps'],
    queryFn: () => api.get<AppsResponse>('/api/v1/access/apps'),
  })

  const pathsQuery = useQuery({
    queryKey: ['discovered-paths', selectedApp?.id],
    queryFn: () => api.get<PathsResponse>(`/api/v1/access/apps/${selectedApp!.id}/paths`),
    enabled: !!selectedApp,
    refetchInterval: selectedApp?.status === 'discovering' ? 2000 : false,
  })

  // Re-fetch app detail when discovering (for status updates)
  const appDetailQuery = useQuery({
    queryKey: ['published-app', selectedApp?.id],
    queryFn: () => api.get<PublishedApp>(`/api/v1/access/apps/${selectedApp!.id}`),
    enabled: !!selectedApp && selectedApp.status === 'discovering',
    refetchInterval: 2000,
  })

  // Keep selectedApp in sync when appDetail finishes discovering
  const appDetailData = appDetailQuery.data
  if (appDetailData && appDetailData.status !== selectedApp?.status) {
    setSelectedApp(appDetailData)
    if (appDetailData.status !== 'discovering') {
      queryClient.invalidateQueries({ queryKey: ['published-apps'] })
      queryClient.invalidateQueries({ queryKey: ['discovered-paths', appDetailData.id] })
    }
  }

  // ---- Mutations ----

  const registerApp = useMutation({
    mutationFn: (data: typeof registerForm) =>
      api.post<PublishedApp>('/api/v1/access/apps', data),
    onSuccess: (app) => {
      queryClient.invalidateQueries({ queryKey: ['published-apps'] })
      toast({ title: 'App Registered', description: `${app.name} has been registered.` })
      setRegisterOpen(false)
      setRegisterForm({ name: '', target_url: '', description: '', spec_url: '' })
    },
    onError: (error: Error) => {
      toast({ title: 'Registration Failed', description: error.message, variant: 'destructive' })
    },
  })

  const deleteApp = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/access/apps/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['published-apps'] })
      toast({ title: 'App Deleted' })
      if (selectedApp) {
        setSelectedApp(null)
        setActiveTab('apps')
      }
    },
    onError: (error: Error) => {
      toast({ title: 'Delete Failed', description: error.message, variant: 'destructive' })
    },
  })

  const startDiscovery = useMutation({
    mutationFn: (id: string) =>
      api.post<PublishedApp>(`/api/v1/access/apps/${id}/discover`),
    onSuccess: (app) => {
      setSelectedApp(app)
      queryClient.invalidateQueries({ queryKey: ['published-apps'] })
      toast({ title: 'Discovery Started', description: 'Scanning for paths and endpoints...' })
    },
    onError: (error: Error) => {
      toast({ title: 'Discovery Failed', description: error.message, variant: 'destructive' })
    },
  })

  const updateClassification = useMutation({
    mutationFn: ({ pathId, data }: { pathId: string; data: { classification: string } }) =>
      api.put<DiscoveredPath>(
        `/api/v1/access/apps/${selectedApp!.id}/paths/${pathId}`,
        data
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['discovered-paths', selectedApp?.id] })
    },
    onError: (error: Error) => {
      toast({ title: 'Update Failed', description: error.message, variant: 'destructive' })
    },
  })

  const publishPaths = useMutation({
    mutationFn: (data: { path_ids: string[]; enable_ziti: boolean; enable_browzer: boolean }) =>
      api.post(`/api/v1/access/apps/${selectedApp!.id}/publish`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['discovered-paths', selectedApp?.id] })
      queryClient.invalidateQueries({ queryKey: ['published-apps'] })
      queryClient.invalidateQueries({ queryKey: ['proxy-routes'] })
      toast({ title: 'Paths Published', description: `${selected.size} paths published as proxy routes.` })
      setPublishOpen(false)
      setSelected(new Set())
    },
    onError: (error: Error) => {
      toast({ title: 'Publish Failed', description: error.message, variant: 'destructive' })
    },
  })

  // One-click publish: expose the whole app at a public host + launcher tile.
  const publishApp = useMutation({
    mutationFn: (data: { public_host?: string; landing_path?: string }) =>
      api.post<{ public_url: string; public_host: string }>(
        `/api/v1/access/apps/${publishAppTarget!.id}/publish-app`,
        data,
      ),
    onSuccess: (res) => {
      queryClient.invalidateQueries({ queryKey: ['published-apps'] })
      queryClient.invalidateQueries({ queryKey: ['proxy-routes'] })
      queryClient.invalidateQueries({ queryKey: ['my-applications'] })
      toast({
        title: 'App Published',
        description: `${res.public_url} — now available in My Apps.`,
      })
      setPublishAppOpen(false)
      setPublicHost('')
    },
    onError: (error: Error) => {
      toast({ title: 'Publish Failed', description: error.message, variant: 'destructive' })
    },
  })

  // ---- Derived data ----

  const apps = appsQuery.data?.apps || []
  const paths = pathsQuery.data?.paths || []

  const filteredPaths = paths.filter((p) => {
    const matchesSearch = p.path.toLowerCase().includes(search.toLowerCase())
    const matchesClass = classFilter === 'all' || p.classification === classFilter
    return matchesSearch && matchesClass
  })

  const unpublishedPaths = filteredPaths.filter((p) => !p.published)

  const classificationCounts = paths.reduce(
    (acc, p) => {
      acc[p.classification] = (acc[p.classification] || 0) + 1
      return acc
    },
    {} as Record<string, number>
  )

  // ---- Selection helpers ----

  const togglePath = (id: string) => {
    const next = new Set(selected)
    if (next.has(id)) next.delete(id)
    else next.add(id)
    setSelected(next)
  }

  const selectAllUnpublished = () => {
    if (selected.size === unpublishedPaths.length) {
      setSelected(new Set())
    } else {
      setSelected(new Set(unpublishedPaths.map((p) => p.id)))
    }
  }

  // ---- Render ----

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-2">
            <Upload className="h-8 w-8 text-indigo-500" />
            App Publish
          </h1>
          <p className="text-muted-foreground mt-1">
            Register internal apps, discover endpoints, classify security levels, and publish as proxy routes
          </p>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="apps">Apps ({apps.length})</TabsTrigger>
          <TabsTrigger value="paths" disabled={!selectedApp}>
            Discovered Paths {selectedApp ? `(${paths.length})` : ''}
          </TabsTrigger>
          <TabsTrigger value="published" disabled={!selectedApp}>
            Published {selectedApp ? `(${paths.filter((p) => p.published).length})` : ''}
          </TabsTrigger>
        </TabsList>

        {/* ============ TAB 1: APPS ============ */}
        <TabsContent value="apps" className="space-y-4">
          <div className="flex justify-end">
            <Button onClick={() => setRegisterOpen(true)}>
              <Plus className="h-4 w-4 mr-2" />
              Register App
            </Button>
          </div>

          {appsQuery.isLoading ? (
            <div className="flex items-center justify-center py-12">
              <LoadingSpinner />
            </div>
          ) : appsQuery.isError ? (
            <QueryError error={appsQuery.error} resource="published apps" />
          ) : apps.length === 0 ? (
            <Card>
              <CardContent className="py-12 text-center text-muted-foreground">
                No apps registered yet. Click "Register App" to get started.
              </CardContent>
            </Card>
          ) : (
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              {apps.map((app) => (
                <Card key={app.id} className="relative">
                  <CardHeader className="pb-3">
                    <div className="flex items-start justify-between">
                      <div className="flex-1 min-w-0">
                        <CardTitle className="text-lg truncate">{app.name}</CardTitle>
                        <CardDescription className="font-mono text-xs truncate mt-1">
                          {app.target_url}
                        </CardDescription>
                      </div>
                      <Badge className={statusColors[app.status] || 'bg-muted'}>
                        {app.status === 'discovering' && (
                          <Loader2 className="h-3 w-3 mr-1 animate-spin" />
                        )}
                        {app.status}
                      </Badge>
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    {app.description && (
                      <p className="text-sm text-muted-foreground line-clamp-2">
                        {app.description}
                      </p>
                    )}
                    <div className="flex gap-4 text-sm text-muted-foreground">
                      <span>{app.total_paths_discovered} discovered</span>
                      <span>{app.total_paths_published} published</span>
                    </div>
                    {app.discovery_strategies.length > 0 && (
                      <div className="flex gap-1 flex-wrap">
                        {app.discovery_strategies.map((s) => (
                          <Badge key={s} variant="secondary" className="text-xs">
                            {s}
                          </Badge>
                        ))}
                      </div>
                    )}
                    {app.discovery_error && (
                      <p className="text-sm text-red-600 flex items-center gap-1">
                        <AlertTriangle className="h-3 w-3" />
                        {app.discovery_error}
                      </p>
                    )}
                    <div className="flex gap-2 pt-2">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => {
                          startDiscovery.mutate(app.id)
                        }}
                        disabled={app.status === 'discovering'}
                      >
                        <Radar className="h-4 w-4 mr-1" />
                        {app.status === 'discovering' ? 'Scanning...' : 'Discover'}
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => {
                          setSelectedApp(app)
                          setActiveTab('paths')
                        }}
                        disabled={app.total_paths_discovered === 0}
                      >
                        <ArrowRight className="h-4 w-4 mr-1" />
                        Paths
                      </Button>
                      <Button
                        size="sm"
                        onClick={() => {
                          setPublishAppTarget(app)
                          setPublicHost(
                            app.public_host ||
                              app.name
                                .toLowerCase()
                                .replace(/[^a-z0-9]+/g, '-')
                                .replace(/^-+|-+$/g, ''),
                          )
                          setLandingPath(app.landing_path || '/')
                          setPublishAppOpen(true)
                        }}
                      >
                        <ExternalLink className="h-4 w-4 mr-1" />
                        {app.public_host ? 'Published' : 'Publish App'}
                      </Button>
                      <ConfirmAction
                        title="Delete this app?"
                        description={`This permanently removes ${app.name} and its published access configuration. This cannot be undone.`}
                        destructive
                        confirmLabel="Delete"
                        onConfirm={() => deleteApp.mutateAsync(app.id)}
                      >
                        {(open) => (
                          <Button
                            size="sm"
                            variant="ghost"
                            className="text-red-600 ml-auto"
                            onClick={open}
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        )}
                      </ConfirmAction>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        {/* ============ TAB 2: DISCOVERED PATHS ============ */}
        <TabsContent value="paths" className="space-y-4">
          {selectedApp && (
            <>
              {/* Summary cards */}
              <div className="grid gap-4 md:grid-cols-5">
                <Card>
                  <CardHeader className="pb-2">
                    <CardDescription>Total</CardDescription>
                    <CardTitle className="text-2xl">{paths.length}</CardTitle>
                  </CardHeader>
                </Card>
                {['critical', 'sensitive', 'protected', 'public'].map((cls) => {
                  const Icon = classificationIcons[cls]
                  return (
                    <Card key={cls}>
                      <CardHeader className="pb-2">
                        <CardDescription className="flex items-center gap-1 capitalize">
                          <Icon className="h-3 w-3" />
                          {cls}
                        </CardDescription>
                        <CardTitle className="text-2xl">{classificationCounts[cls] || 0}</CardTitle>
                      </CardHeader>
                    </Card>
                  )
                })}
              </div>

              {/* Actions bar */}
              <Card>
                <CardContent className="pt-6">
                  <div className="flex flex-wrap gap-4 items-center">
                    <div className="flex-1 min-w-[200px]">
                      <div className="relative">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                        <Input
                          placeholder="Search paths..."
                          value={search}
                          onChange={(e) => setSearch(e.target.value)}
                          className="pl-9"
                        />
                      </div>
                    </div>
                    <Select value={classFilter} onValueChange={setClassFilter}>
                      <SelectTrigger className="w-[160px]">
                        <SelectValue placeholder="Classification" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">All Classes</SelectItem>
                        <SelectItem value="critical">Critical</SelectItem>
                        <SelectItem value="sensitive">Sensitive</SelectItem>
                        <SelectItem value="protected">Protected</SelectItem>
                        <SelectItem value="public">Public</SelectItem>
                      </SelectContent>
                    </Select>
                    <Button
                      variant="outline"
                      onClick={() => {
                        startDiscovery.mutate(selectedApp.id)
                      }}
                      disabled={selectedApp.status === 'discovering'}
                    >
                      <RefreshCw className={`h-4 w-4 mr-2 ${selectedApp.status === 'discovering' ? 'animate-spin' : ''}`} />
                      Re-Discover
                    </Button>
                    <Button
                      onClick={() => setPublishOpen(true)}
                      disabled={selected.size === 0}
                    >
                      <Upload className="h-4 w-4 mr-2" />
                      Publish Selected ({selected.size})
                    </Button>
                  </div>
                </CardContent>
              </Card>

              {/* Paths table */}
              <Card>
                <CardContent className="p-0">
                  {pathsQuery.isLoading ? (
                    <div className="flex items-center justify-center py-12">
                      <LoadingSpinner />
                    </div>
                  ) : (
                      <Table>
                        <TableHeader className="bg-muted">
                          <TableRow>
                            <TableHead className="w-12 p-4">
                              <Checkbox
                                checked={
                                  selected.size === unpublishedPaths.length &&
                                  unpublishedPaths.length > 0
                                }
                                onCheckedChange={selectAllUnpublished}
                              />
                            </TableHead>
                            <TableHead className="text-left p-4 font-medium">Path</TableHead>
                            <TableHead className="text-left p-4 font-medium">Methods</TableHead>
                            <TableHead className="text-left p-4 font-medium">Classification</TableHead>
                            <TableHead className="text-left p-4 font-medium">Auth</TableHead>
                            <TableHead className="text-left p-4 font-medium">Source</TableHead>
                            <TableHead className="text-left p-4 font-medium">Status</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody className="divide-y">
                          {filteredPaths.map((path) => {
                            const ClsIcon = classificationIcons[path.classification] || ShieldCheck
                            return (
                              <TableRow key={path.id} className="hover:bg-muted/50">
                                <TableCell className="p-4">
                                  <Checkbox
                                    checked={selected.has(path.id)}
                                    onCheckedChange={() => togglePath(path.id)}
                                    disabled={path.published}
                                  />
                                </TableCell>
                                <TableCell className="p-4">
                                  <code className="text-sm bg-muted px-2 py-0.5 rounded">
                                    {path.path}
                                  </code>
                                </TableCell>
                                <TableCell className="p-4">
                                  <div className="flex gap-1 flex-wrap">
                                    {path.http_methods.map((m) => (
                                      <Badge key={m} variant="secondary" className="text-xs">
                                        {m}
                                      </Badge>
                                    ))}
                                  </div>
                                </TableCell>
                                <TableCell className="p-4">
                                  <Select
                                    value={path.classification}
                                    onValueChange={(val) =>
                                      updateClassification.mutate({
                                        pathId: path.id,
                                        data: { classification: val },
                                      })
                                    }
                                  >
                                    <SelectTrigger className="w-[140px] h-8">
                                      <SelectValue>
                                        <span className="flex items-center gap-1">
                                          <ClsIcon className="h-3 w-3" />
                                          <span className="capitalize">{path.classification}</span>
                                        </span>
                                      </SelectValue>
                                    </SelectTrigger>
                                    <SelectContent>
                                      {['critical', 'sensitive', 'protected', 'public'].map(
                                        (cls) => {
                                          const Icon = classificationIcons[cls]
                                          return (
                                            <SelectItem key={cls} value={cls}>
                                              <span className="flex items-center gap-1">
                                                <Icon className="h-3 w-3" />
                                                <span className="capitalize">{cls}</span>
                                              </span>
                                            </SelectItem>
                                          )
                                        }
                                      )}
                                    </SelectContent>
                                  </Select>
                                </TableCell>
                                <TableCell className="p-4 text-sm">
                                  {path.require_auth ? (
                                    <span className="flex items-center gap-1 text-amber-600">
                                      <Lock className="h-3 w-3" /> Required
                                      {path.allowed_roles.length > 0 && (
                                        <span className="text-xs text-muted-foreground ml-1">
                                          ({path.allowed_roles.join(', ')})
                                        </span>
                                      )}
                                    </span>
                                  ) : (
                                    <span className="text-green-600">Public</span>
                                  )}
                                </TableCell>
                                <TableCell className="p-4">
                                  <Badge variant="outline" className="text-xs">
                                    {path.classification_source}
                                  </Badge>
                                </TableCell>
                                <TableCell className="p-4">
                                  {path.published ? (
                                    <Badge className="bg-green-100 text-green-800">
                                      <CheckCircle2 className="h-3 w-3 mr-1" />
                                      Published
                                    </Badge>
                                  ) : (
                                    <Badge variant="secondary">Pending</Badge>
                                  )}
                                </TableCell>
                              </TableRow>
                            )
                          })}
                          {filteredPaths.length === 0 && (
                            <TableRow>
                              <TableCell colSpan={7} className="p-8 text-center text-muted-foreground">
                                {paths.length === 0
                                  ? 'No paths discovered yet. Run discovery first.'
                                  : 'No paths match your filter.'}
                              </TableCell>
                            </TableRow>
                          )}
                        </TableBody>
                      </Table>
                  )}
                </CardContent>
              </Card>
            </>
          )}
        </TabsContent>

        {/* ============ TAB 3: PUBLISHED ============ */}
        <TabsContent value="published" className="space-y-4">
          {selectedApp && (
            <Card>
              <CardContent className="p-0">
                  <Table>
                    <TableHeader className="bg-muted">
                      <TableRow>
                        <TableHead className="text-left p-4 font-medium">Path</TableHead>
                        <TableHead className="text-left p-4 font-medium">Methods</TableHead>
                        <TableHead className="text-left p-4 font-medium">Classification</TableHead>
                        <TableHead className="text-left p-4 font-medium">Auth Policy</TableHead>
                        <TableHead className="text-left p-4 font-medium">Route</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody className="divide-y">
                      {paths
                        .filter((p) => p.published)
                        .map((path) => {
                          const ClsIcon = classificationIcons[path.classification] || ShieldCheck
                          return (
                            <TableRow key={path.id} className="hover:bg-muted/50">
                              <TableCell className="p-4">
                                <code className="text-sm bg-muted px-2 py-0.5 rounded">
                                  {path.path}
                                </code>
                              </TableCell>
                              <TableCell className="p-4">
                                <div className="flex gap-1">
                                  {path.http_methods.map((m) => (
                                    <Badge key={m} variant="secondary" className="text-xs">
                                      {m}
                                    </Badge>
                                  ))}
                                </div>
                              </TableCell>
                              <TableCell className="p-4">
                                <Badge className={classificationColors[path.classification]}>
                                  <ClsIcon className="h-3 w-3 mr-1" />
                                  {path.classification}
                                </Badge>
                              </TableCell>
                              <TableCell className="p-4 text-sm">
                                {path.require_auth
                                  ? `Auth: ${path.allowed_roles.length > 0 ? path.allowed_roles.join(', ') : 'any user'}`
                                  : 'Public'}
                                {path.require_device_trust && ' + Device Trust'}
                              </TableCell>
                              <TableCell className="p-4">
                                {path.route_id && (
                                  <a
                                    href="/proxy-routes"
                                    className="text-primary hover:underline flex items-center gap-1 text-sm"
                                  >
                                    View Route
                                    <ExternalLink className="h-3 w-3" />
                                  </a>
                                )}
                              </TableCell>
                            </TableRow>
                          )
                        })}
                      {paths.filter((p) => p.published).length === 0 && (
                        <TableRow>
                          <TableCell colSpan={5} className="p-8 text-center text-muted-foreground">
                            No paths published yet. Go to Discovered Paths and publish some.
                          </TableCell>
                        </TableRow>
                      )}
                    </TableBody>
                  </Table>
              </CardContent>
            </Card>
          )}
        </TabsContent>
      </Tabs>

      {/* ============ REGISTER APP DIALOG ============ */}
      <Dialog open={registerOpen} onOpenChange={setRegisterOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Register Application</DialogTitle>
            <DialogDescription>
              Add an internal web application for endpoint discovery and publishing.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="app-name">Name</Label>
              <Input
                id="app-name"
                placeholder="My Internal App"
                value={registerForm.name}
                onChange={(e) =>
                  setRegisterForm((f) => ({ ...f, name: e.target.value }))
                }
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="target-url">Target URL</Label>
              <Input
                id="target-url"
                placeholder="http://internal-app:8080"
                value={registerForm.target_url}
                onChange={(e) =>
                  setRegisterForm((f) => ({ ...f, target_url: e.target.value }))
                }
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="spec-url">OpenAPI Spec URL (optional)</Label>
              <Input
                id="spec-url"
                placeholder="http://internal-app:8080/openapi.json"
                value={registerForm.spec_url}
                onChange={(e) =>
                  setRegisterForm((f) => ({ ...f, spec_url: e.target.value }))
                }
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="app-desc">Description (optional)</Label>
              <Input
                id="app-desc"
                placeholder="HR portal for employee management"
                value={registerForm.description}
                onChange={(e) =>
                  setRegisterForm((f) => ({ ...f, description: e.target.value }))
                }
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRegisterOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => registerApp.mutate(registerForm)}
              disabled={!registerForm.name || !registerForm.target_url || registerApp.isPending}
            >
              {registerApp.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              Register
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ============ PUBLISH DIALOG ============ */}
      <Dialog open={publishOpen} onOpenChange={setPublishOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Publish Selected Paths</DialogTitle>
            <DialogDescription>
              Create proxy routes for {selected.size} selected path{selected.size !== 1 ? 's' : ''}.
              Each path will become a separate proxy route with its classification-based auth policy.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="text-sm text-muted-foreground">
              Selected paths will be published as proxy routes for <strong>{selectedApp?.name}</strong> targeting{' '}
              <code className="bg-muted px-1 rounded">{selectedApp?.target_url}</code>.
            </div>
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <Checkbox
                  id="enable-ziti"
                  checked={publishConfig.enable_ziti}
                  onCheckedChange={(checked) =>
                    setPublishConfig((c) => ({ ...c, enable_ziti: !!checked }))
                  }
                />
                <Label htmlFor="enable-ziti">Enable OpenZiti zero-trust overlay</Label>
              </div>
              <div className="flex items-center gap-2">
                <Checkbox
                  id="enable-browzer"
                  checked={publishConfig.enable_browzer}
                  onCheckedChange={(checked) =>
                    setPublishConfig((c) => ({ ...c, enable_browzer: !!checked }))
                  }
                />
                <Label htmlFor="enable-browzer">Enable BrowZer clientless access</Label>
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setPublishOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={() =>
                publishPaths.mutate({
                  path_ids: Array.from(selected),
                  enable_ziti: publishConfig.enable_ziti,
                  enable_browzer: publishConfig.enable_browzer,
                })
              }
              disabled={publishPaths.isPending}
            >
              {publishPaths.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              Publish {selected.size} Path{selected.size !== 1 ? 's' : ''}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ============ ONE-CLICK PUBLISH APP ============ */}
      <Dialog open={publishAppOpen} onOpenChange={setPublishAppOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Publish as one-click app</DialogTitle>
            <DialogDescription>
              Expose <span className="font-medium">{publishAppTarget?.name}</span> at its own
              HTTPS host behind OpenIDX SSO and add it to every user's My Apps launcher.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-2">
              <Label htmlFor="public-host">Public host</Label>
              <Input
                id="public-host"
                placeholder="netgraph.apps.tdv.org"
                value={publicHost}
                onChange={(e) => setPublicHost(e.target.value)}
              />
              <p className="text-xs text-muted-foreground">
                The hostname users will open. If you enter just a label (e.g. <code>netgraph</code>)
                the server appends the configured apps domain. Point a DNS/hosts entry at this
                gateway; the wildcard TLS cert covers it.
              </p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="landing-path">Landing path</Label>
              <Input
                id="landing-path"
                placeholder="/"
                value={landingPath}
                onChange={(e) => setLandingPath(e.target.value)}
              />
              <p className="text-xs text-muted-foreground">
                Where the launcher tile opens. Use <code>/</code> unless the app's UI lives
                elsewhere (e.g. <code>/ui/</code>).
              </p>
            </div>
            <div className="rounded-md bg-muted p-3 text-sm text-muted-foreground">
              Internal target:{' '}
              <span className="font-mono">{publishAppTarget?.target_url}</span>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setPublishAppOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={() =>
                publishApp.mutate({
                  public_host: publicHost.trim() || undefined,
                  landing_path: landingPath.trim() || '/',
                })
              }
              disabled={publishApp.isPending}
            >
              {publishApp.isPending ? (
                <Loader2 className="h-4 w-4 mr-1 animate-spin" />
              ) : (
                <ExternalLink className="h-4 w-4 mr-1" />
              )}
              Publish
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
