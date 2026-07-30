import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Search, MoreHorizontal, Edit, Trash2, RefreshCw, Plug, History } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '../components/ui/dropdown-menu'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '../components/ui/dialog'
import { Label } from '../components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '../components/ui/select'
import { Switch } from '../components/ui/switch'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '../components/ui/table'
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
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'
import { LoadingSpinner } from '../components/ui/loading-spinner'

interface DirectoryConfig {
  // LDAP fields
  host: string
  port: number
  use_tls: boolean
  start_tls: boolean
  skip_tls_verify: boolean
  bind_dn: string
  bind_password: string
  base_dn: string
  user_base_dn: string
  group_base_dn: string
  user_filter: string
  group_filter: string
  member_attribute: string
  page_size: number
  sync_interval: number
  sync_enabled: boolean
  deprovision_action: string
  attribute_mapping: {
    username: string
    email: string
    first_name: string
    last_name: string
    display_name: string
    group_name: string
  }
  // Azure AD fields (used when type='azure_ad')
  tenant_id: string
  client_id: string
  client_secret: string
}

interface DirectoryIntegration {
  id: string
  name: string
  type: string
  config: DirectoryConfig
  enabled: boolean
  last_sync_at: string | null
  sync_status: string
  created_at: string
  updated_at: string
}

interface SyncLog {
  id: string
  directory_id: string
  sync_type: string
  status: string
  started_at: string
  completed_at: string | null
  users_added: number
  users_updated: number
  users_disabled: number
  groups_added: number
  groups_updated: number
  groups_deleted: number
  error_message: string | null
}

const defaultConfig: DirectoryConfig = {
  host: '',
  port: 389,
  use_tls: false,
  start_tls: false,
  skip_tls_verify: false,
  bind_dn: '',
  bind_password: '',
  base_dn: '',
  user_base_dn: '',
  group_base_dn: '',
  user_filter: '(objectClass=inetOrgPerson)',
  group_filter: '(objectClass=groupOfNames)',
  member_attribute: 'member',
  page_size: 500,
  sync_interval: 60,
  sync_enabled: false,
  deprovision_action: 'disable',
  attribute_mapping: {
    username: 'uid',
    email: 'mail',
    first_name: 'givenName',
    last_name: 'sn',
    display_name: 'cn',
    group_name: 'cn',
  },
  tenant_id: '',
  client_id: '',
  client_secret: '',
}

const adDefaults: DirectoryConfig['attribute_mapping'] = {
  username: 'sAMAccountName',
  email: 'mail',
  first_name: 'givenName',
  last_name: 'sn',
  display_name: 'displayName',
  group_name: 'cn',
}

const ldapDefaults: DirectoryConfig['attribute_mapping'] = {
  username: 'uid',
  email: 'mail',
  first_name: 'givenName',
  last_name: 'sn',
  display_name: 'cn',
  group_name: 'cn',
}

const azureAdDefaults: DirectoryConfig['attribute_mapping'] = {
  username: 'userPrincipalName',
  email: 'mail',
  first_name: 'givenName',
  last_name: 'surname',
  display_name: 'displayName',
  group_name: 'displayName',
}

interface DirectoryFormData {
  name: string
  type: string
  config: DirectoryConfig
  enabled: boolean
}

interface DiagnoseFinding {
  stage: string
  severity: 'error' | 'warning' | 'info' | 'ok'
  title: string
  detail?: string
  suggested?: Record<string, unknown>
  evidence?: Record<string, unknown>
}

interface DiagnoseResult {
  ok: boolean
  summary: string
  findings: DiagnoseFinding[]
  suggested_config?: Record<string, unknown>
}

const emptyForm: DirectoryFormData = {
  name: '',
  type: 'ldap',
  config: { ...defaultConfig },
  enabled: true,
}

// validateForm mirrors the backend guard (internal/admin.validateDirectoryIntegration):
// required fields per directory type. Returns a field-path -> message map.
function validateForm(f: DirectoryFormData): Record<string, string> {
  const e: Record<string, string> = {}
  const c = f.config
  const s = (v?: string) => (v ?? '').trim()
  if (s(f.name) === '') e['name'] = 'Name is required.'
  if (s(f.type) === '') { e['type'] = 'Directory type is required.'; return e }

  if (f.type === 'ldap' || f.type === 'active_directory') {
    if (s(c.host) === '') e['config.host'] = 'Host is required.'
    if (!c.port || c.port <= 0) e['config.port'] = 'Port is required.'
    if (s(c.bind_dn) === '') e['config.bind_dn'] = 'Bind DN is required (e.g. user@domain for AD).'
    if (s(c.bind_password) === '') e['config.bind_password'] = 'Bind password is required.'
    if (s(c.base_dn) === '' && s(c.user_base_dn) === '')
      e['config.base_dn'] = 'Base DN is required (e.g. DC=corp,DC=local). Try "Diagnose & Auto-Fix".'
    if (s(c.user_filter) === '') e['config.user_filter'] = 'User filter is required.'
    if (s(c.attribute_mapping?.username) === '')
      e['config.attribute_mapping.username'] = 'Username mapping is required (e.g. sAMAccountName for AD).'
    if (s(c.attribute_mapping?.email) === '')
      e['config.attribute_mapping.email'] = 'Email mapping is required (e.g. userPrincipalName for AD).'
  } else if (f.type === 'azure_ad') {
    if (s(c.tenant_id) === '') e['config.tenant_id'] = 'Tenant ID is required.'
    if (s(c.client_id) === '') e['config.client_id'] = 'Client ID is required.'
    if (s(c.client_secret) === '') e['config.client_secret'] = 'Client secret is required.'
  }
  return e
}

export function DirectoriesPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [search, setSearch] = useState('')
  const [dialogOpen, setDialogOpen] = useState(false)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [deleteId, setDeleteId] = useState<string | null>(null)
  const [formData, setFormData] = useState<DirectoryFormData>({ ...emptyForm })
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})
  const [activeTab, setActiveTab] = useState<'connection' | 'search' | 'mapping' | 'sync'>('connection')
  const [syncLogsId, setSyncLogsId] = useState<string | null>(null)

  const { data: directories = [], isLoading } = useQuery({
    queryKey: ['directories'],
    queryFn: () => api.get<DirectoryIntegration[]>('/api/v1/directories'),
  })

  const { data: syncLogs = [] } = useQuery({
    queryKey: ['sync-logs', syncLogsId],
    queryFn: () => api.get<SyncLog[]>(`/api/v1/directories/${syncLogsId}/sync-logs`),
    enabled: !!syncLogsId,
  })

  const createMutation = useMutation({
    mutationFn: (data: DirectoryFormData) => api.post('/api/v1/directories', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['directories'] })
      setDialogOpen(false)
      toast({ title: 'Directory created' })
    },
    onError: (err) => handleMutationError(err, 'Failed to create directory'),
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: DirectoryFormData }) =>
      api.put(`/api/v1/directories/${id}`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['directories'] })
      setDialogOpen(false)
      toast({ title: 'Directory updated' })
    },
    onError: (err) => handleMutationError(err, 'Failed to update directory'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/directories/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['directories'] })
      setDeleteId(null)
      toast({ title: 'Directory deleted' })
    },
    onError: () => toast({ title: 'Failed to delete directory', variant: 'destructive' }),
  })

  const syncMutation = useMutation({
    mutationFn: ({ id, full }: { id: string; full: boolean }) =>
      api.post(`/api/v1/directories/${id}/sync?full=${full}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['directories'] })
      toast({ title: 'Sync initiated' })
    },
    onError: () => toast({ title: 'Failed to trigger sync', variant: 'destructive' }),
  })

  const testMutation = useMutation({
    mutationFn: (id: string) => api.post<{ success: boolean; message: string }>(`/api/v1/directories/${id}/test`),
    onSuccess: (data) => {
      const result = data as { success: boolean; message: string }
      toast({ title: result.success ? 'Connection successful' : 'Connection failed' })
    },
    onError: () => toast({ title: 'Connection test failed', variant: 'destructive' }),
  })

  // --- Live diagnostics (auto-detect + suggest fixes) ---
  const [diagResult, setDiagResult] = useState<DiagnoseResult | null>(null)
  const diagnoseMutation = useMutation({
    mutationFn: () =>
      api.post<DiagnoseResult>('/api/v1/directory-diagnose', {
        type: formData.type,
        config: formData.config,
      }),
    onSuccess: (data) => {
      setDiagResult(data as DiagnoseResult)
    },
    onError: () =>
      toast({ title: 'Diagnostics failed to run', variant: 'destructive' }),
  })

  // Apply the merged suggested_config patch to the form. Suggestion keys use the
  // stored config JSON keys; attribute_mapping.* keys patch the nested mapping.
  const applySuggestions = (patch: Record<string, unknown>) => {
    setFormData((prev) => {
      const next = { ...prev, config: { ...prev.config, attribute_mapping: { ...prev.config.attribute_mapping } } }
      for (const [k, v] of Object.entries(patch)) {
        if (k.startsWith('attribute_mapping.')) {
          const attr = k.slice('attribute_mapping.'.length)
          ;(next.config.attribute_mapping as Record<string, unknown>)[attr] = v
        } else if (k === 'directory_type') {
          next.type = v === 'active_directory' ? 'active_directory' : prev.type
          ;(next.config as Record<string, unknown>)[k] = v
        } else {
          ;(next.config as Record<string, unknown>)[k] = v
        }
      }
      return next
    })
    toast({ title: 'Suggestions applied', description: 'Review the fields, then Test or Save.' })
    setDiagResult(null)
  }

  const filtered = directories.filter(
    (d) => d.name.toLowerCase().includes(search.toLowerCase())
  )

  const openCreate = () => {
    setEditingId(null)
    setFormData({ ...emptyForm, config: { ...defaultConfig } })
    setFieldErrors({})
    setDiagResult(null)
    setActiveTab('connection')
    setDialogOpen(true)
  }

  const openEdit = (dir: DirectoryIntegration) => {
    setEditingId(dir.id)
    setFormData({
      name: dir.name,
      type: dir.type,
      config: { ...defaultConfig, ...dir.config },
      enabled: dir.enabled,
    })
    setFieldErrors({})
    setDiagResult(null)
    setActiveTab('connection')
    setDialogOpen(true)
  }

  // handleMutationError surfaces backend validation field errors (the {fields}
  // map from validateDirectoryIntegration) inline, jumping to the right tab.
  const handleMutationError = (err: unknown, fallback: string) => {
    const resp = (err as { response?: { data?: { fields?: Record<string, string>; error?: string } } })?.response
    const fields = resp?.data?.fields
    if (fields && Object.keys(fields).length > 0) {
      setFieldErrors(fields)
      toast({ title: 'Please fix the highlighted fields', variant: 'destructive' })
      return
    }
    toast({ title: resp?.data?.error || fallback, variant: 'destructive' })
  }

  const handleSubmit = () => {
    const errs = validateForm(formData)
    setFieldErrors(errs)
    if (Object.keys(errs).length > 0) {
      // Jump to the tab holding the first error so it is visible.
      const firstKey = Object.keys(errs)[0]
      if (firstKey === 'name' || firstKey.startsWith('config.host') || firstKey.startsWith('config.port') ||
          firstKey.startsWith('config.bind') || firstKey.startsWith('config.tenant') ||
          firstKey.startsWith('config.client')) {
        setActiveTab('connection')
      } else if (firstKey.startsWith('config.base_dn') || firstKey.startsWith('config.user_filter') ||
                 firstKey.startsWith('config.group')) {
        setActiveTab('search')
      } else if (firstKey.startsWith('config.attribute_mapping')) {
        setActiveTab('mapping')
      }
      toast({ title: 'Please fix the highlighted fields', variant: 'destructive' })
      return
    }
    if (editingId) {
      updateMutation.mutate({ id: editingId, data: formData })
    } else {
      createMutation.mutate(formData)
    }
  }

  const applyDefaults = () => {
    const mapping = formData.type === 'active_directory' ? { ...adDefaults } : { ...ldapDefaults }
    setFormData({
      ...formData,
      config: {
        ...formData.config,
        attribute_mapping: mapping,
        user_filter: formData.type === 'active_directory'
          ? '(&(objectClass=user)(objectCategory=person))'
          : '(objectClass=inetOrgPerson)',
        group_filter: formData.type === 'active_directory'
          ? '(objectClass=group)'
          : '(objectClass=groupOfNames)',
        member_attribute: formData.type === 'active_directory' ? 'member' : 'member',
        port: formData.config.use_tls ? 636 : 389,
      },
    })
  }

  const statusBadge = (status: string) => {
    switch (status) {
      case 'synced': return <Badge variant="default" className="bg-green-600">Synced</Badge>
      case 'syncing': return <Badge variant="default" className="bg-blue-600">Syncing</Badge>
      case 'failed': return <Badge variant="destructive">Failed</Badge>
      default: return <Badge variant="secondary">Never</Badge>
    }
  }

  if (isLoading) return <div className="flex justify-center p-8"><LoadingSpinner size="lg" /></div>

  // Inline error text for a field path (empty when no error).
  const FieldError = ({ path }: { path: string }) =>
    fieldErrors[path] ? <p className="text-xs text-red-500 mt-1">{fieldErrors[path]}</p> : null

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Directory Integrations</h1>
          <p className="text-muted-foreground">
            Connect LDAP and Active Directory servers for user/group synchronization
          </p>
        </div>
        <Button onClick={openCreate}>
          <Plus className="mr-2 h-4 w-4" />
          Add Directory
        </Button>
      </div>

      <div className="flex items-center space-x-2">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search directories..."
            className="pl-8"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Directories</CardTitle>
          <CardDescription>{filtered.length} directory integration(s)</CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Last Sync</TableHead>
                <TableHead>Enabled</TableHead>
                <TableHead className="w-[70px]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center text-muted-foreground py-8">
                    No directory integrations configured
                  </TableCell>
                </TableRow>
              ) : (
                filtered.map((dir) => (
                  <TableRow key={dir.id}>
                    <TableCell className="font-medium">{dir.name}</TableCell>
                    <TableCell>
                      <Badge variant="outline">
                        {dir.type === 'azure_ad' ? 'Azure AD' : dir.type === 'active_directory' ? 'Active Directory' : 'LDAP'}
                      </Badge>
                    </TableCell>
                    <TableCell>{statusBadge(dir.sync_status)}</TableCell>
                    <TableCell>
                      {dir.last_sync_at
                        ? new Date(dir.last_sync_at).toLocaleString()
                        : 'Never'}
                    </TableCell>
                    <TableCell>
                      <Badge variant={dir.enabled ? 'default' : 'secondary'}>
                        {dir.enabled ? 'Enabled' : 'Disabled'}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="sm">
                            <MoreHorizontal className="h-4 w-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem onClick={() => openEdit(dir)}>
                            <Edit className="mr-2 h-4 w-4" />
                            Edit
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => testMutation.mutate(dir.id)}>
                            <Plug className="mr-2 h-4 w-4" />
                            Test Connection
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => syncMutation.mutate({ id: dir.id, full: false })}>
                            <RefreshCw className="mr-2 h-4 w-4" />
                            Incremental Sync
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => syncMutation.mutate({ id: dir.id, full: true })}>
                            <RefreshCw className="mr-2 h-4 w-4" />
                            Full Sync
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => setSyncLogsId(dir.id)}>
                            <History className="mr-2 h-4 w-4" />
                            Sync History
                          </DropdownMenuItem>
                          <DropdownMenuItem
                            className="text-destructive"
                            onClick={() => setDeleteId(dir.id)}
                          >
                            <Trash2 className="mr-2 h-4 w-4" />
                            Delete
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Sync History Dialog */}
      <Dialog open={!!syncLogsId} onOpenChange={(open) => { if (!open) setSyncLogsId(null) }}>
        <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Sync History</DialogTitle>
          </DialogHeader>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Type</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Started</TableHead>
                <TableHead>Users +/-</TableHead>
                <TableHead>Groups +/-</TableHead>
                <TableHead>Error</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {syncLogs.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center text-muted-foreground py-4">
                    No sync history
                  </TableCell>
                </TableRow>
              ) : (
                syncLogs.map((log) => (
                  <TableRow key={log.id}>
                    <TableCell>
                      <Badge variant="outline">{log.sync_type}</Badge>
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={log.status === 'success' ? 'default' : log.status === 'failed' ? 'destructive' : 'secondary'}
                        className={log.status === 'success' ? 'bg-green-600' : ''}
                      >
                        {log.status}
                      </Badge>
                    </TableCell>
                    <TableCell>{new Date(log.started_at).toLocaleString()}</TableCell>
                    <TableCell>
                      +{log.users_added} / ~{log.users_updated} / -{log.users_disabled}
                    </TableCell>
                    <TableCell>
                      +{log.groups_added} / ~{log.groups_updated} / -{log.groups_deleted}
                    </TableCell>
                    <TableCell className="max-w-[200px] truncate">
                      {log.error_message || '-'}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </DialogContent>
      </Dialog>

      {/* Add/Edit Dialog */}
      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>
              {editingId ? 'Edit Directory' : 'Add Directory'}
            </DialogTitle>
          </DialogHeader>

          {/* Tabs */}
          <div className="flex space-x-1 border-b mb-4">
            {(['connection', 'search', 'mapping', 'sync'] as const).map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
                  activeTab === tab
                    ? 'border-primary text-primary'
                    : 'border-transparent text-muted-foreground hover:text-foreground'
                }`}
              >
                {tab.charAt(0).toUpperCase() + tab.slice(1)}
              </button>
            ))}
          </div>

          {/* Connection Tab */}
          {activeTab === 'connection' && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Name</Label>
                  <Input
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    placeholder="My LDAP Server"
                  />
                  <FieldError path="name" />
                </div>
                <div className="space-y-2">
                  <Label>Type</Label>
                  <Select
                    value={formData.type}
                    onValueChange={(v) => {
                      const mapping = v === 'active_directory' ? adDefaults : v === 'azure_ad' ? azureAdDefaults : ldapDefaults
                      setFormData({ ...formData, type: v, config: { ...formData.config, attribute_mapping: mapping } })
                    }}
                  >
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="ldap">LDAP (OpenLDAP, etc.)</SelectItem>
                      <SelectItem value="active_directory">Active Directory</SelectItem>
                      <SelectItem value="azure_ad">Azure AD / Entra ID</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              {formData.type === 'azure_ad' ? (
                <>
                  <div className="space-y-2">
                    <Label>Tenant ID</Label>
                    <Input
                      value={formData.config.tenant_id}
                      onChange={(e) => setFormData({
                        ...formData,
                        config: { ...formData.config, tenant_id: e.target.value },
                      })}
                      placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                    />
                    <p className="text-xs text-muted-foreground">Azure AD tenant (directory) ID from the Azure portal</p>
                  </div>

                  <div className="space-y-2">
                    <Label>Client ID (Application ID)</Label>
                    <Input
                      value={formData.config.client_id}
                      onChange={(e) => setFormData({
                        ...formData,
                        config: { ...formData.config, client_id: e.target.value },
                      })}
                      placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                    />
                    <p className="text-xs text-muted-foreground">App registration client ID with Microsoft Graph API permissions</p>
                  </div>

                  <div className="space-y-2">
                    <Label>Client Secret</Label>
                    <Input
                      type="password"
                      value={formData.config.client_secret}
                      onChange={(e) => setFormData({
                        ...formData,
                        config: { ...formData.config, client_secret: e.target.value },
                      })}
                    />
                    <p className="text-xs text-muted-foreground">Client secret from the app registration certificates &amp; secrets</p>
                  </div>
                </>
              ) : (
                <>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label>Host</Label>
                      <Input
                        value={formData.config.host}
                        onChange={(e) => setFormData({
                          ...formData,
                          config: { ...formData.config, host: e.target.value },
                        })}
                        placeholder="ldap.example.com"
                      />
                      <FieldError path="config.host" />
                    </div>
                    <div className="space-y-2">
                      <Label>Port</Label>
                      <Input
                        type="number"
                        value={formData.config.port}
                        onChange={(e) => setFormData({
                          ...formData,
                          config: { ...formData.config, port: parseInt(e.target.value) || 389 },
                        })}
                      />
                    </div>
                  </div>

                  <div className="flex items-center gap-6">
                    <div className="flex items-center space-x-2">
                      <Switch
                        checked={formData.config.use_tls}
                        onCheckedChange={(v) => setFormData({
                          ...formData,
                          config: { ...formData.config, use_tls: v, port: v ? 636 : 389 },
                        })}
                      />
                      <Label>LDAPS (TLS)</Label>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Switch
                        checked={formData.config.start_tls}
                        onCheckedChange={(v) => setFormData({
                          ...formData,
                          config: { ...formData.config, start_tls: v },
                        })}
                      />
                      <Label>StartTLS</Label>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Switch
                        checked={formData.config.skip_tls_verify}
                        onCheckedChange={(v) => setFormData({
                          ...formData,
                          config: { ...formData.config, skip_tls_verify: v },
                        })}
                      />
                      <Label>Skip TLS Verify</Label>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <Label>Bind DN</Label>
                    <Input
                      value={formData.config.bind_dn}
                      onChange={(e) => setFormData({
                        ...formData,
                        config: { ...formData.config, bind_dn: e.target.value },
                      })}
                      placeholder="cn=admin,dc=example,dc=com"
                    />
                    <FieldError path="config.bind_dn" />
                  </div>

                  <div className="space-y-2">
                    <Label>Bind Password</Label>
                    <Input
                      type="password"
                      value={formData.config.bind_password}
                      onChange={(e) => setFormData({
                        ...formData,
                        config: { ...formData.config, bind_password: e.target.value },
                      })}
                    />
                    <FieldError path="config.bind_password" />
                  </div>
                </>
              )}

              <div className="flex items-center space-x-2">
                <Switch
                  checked={formData.enabled}
                  onCheckedChange={(v) => setFormData({ ...formData, enabled: v })}
                />
                <Label>Enabled</Label>
              </div>
            </div>
          )}

          {/* Search Tab */}
          {activeTab === 'search' && (
            <div className="space-y-4">
              {formData.type === 'azure_ad' ? (
                <>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label>User Filter (OData $filter)</Label>
                      <Input
                        value={formData.config.user_filter}
                        onChange={(e) => setFormData({
                          ...formData,
                          config: { ...formData.config, user_filter: e.target.value },
                        })}
                        placeholder="accountEnabled eq true"
                      />
                      <p className="text-xs text-muted-foreground">OData filter expression for Microsoft Graph /users endpoint</p>
                    </div>
                    <div className="space-y-2">
                      <Label>Group Filter (OData $filter)</Label>
                      <Input
                        value={formData.config.group_filter}
                        onChange={(e) => setFormData({
                          ...formData,
                          config: { ...formData.config, group_filter: e.target.value },
                        })}
                        placeholder="securityEnabled eq true"
                      />
                      <p className="text-xs text-muted-foreground">OData filter expression for Microsoft Graph /groups endpoint</p>
                    </div>
                  </div>
                </>
              ) : (
                <>
                  <div className="space-y-2">
                    <Label>Base DN</Label>
                    <Input
                      value={formData.config.base_dn}
                      onChange={(e) => setFormData({
                        ...formData,
                        config: { ...formData.config, base_dn: e.target.value },
                      })}
                      placeholder="dc=example,dc=com"
                    />
                    <FieldError path="config.base_dn" />
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label>User Base DN (optional)</Label>
                      <Input
                        value={formData.config.user_base_dn}
                        onChange={(e) => setFormData({
                          ...formData,
                          config: { ...formData.config, user_base_dn: e.target.value },
                        })}
                        placeholder="ou=people,dc=example,dc=com"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Group Base DN (optional)</Label>
                      <Input
                        value={formData.config.group_base_dn}
                        onChange={(e) => setFormData({
                          ...formData,
                          config: { ...formData.config, group_base_dn: e.target.value },
                        })}
                        placeholder="ou=groups,dc=example,dc=com"
                      />
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label>User Filter</Label>
                      <Input
                        value={formData.config.user_filter}
                        onChange={(e) => setFormData({
                          ...formData,
                          config: { ...formData.config, user_filter: e.target.value },
                        })}
                      />
                      <FieldError path="config.user_filter" />
                    </div>
                    <div className="space-y-2">
                      <Label>Group Filter</Label>
                      <Input
                        value={formData.config.group_filter}
                        onChange={(e) => setFormData({
                          ...formData,
                          config: { ...formData.config, group_filter: e.target.value },
                        })}
                      />
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label>Member Attribute</Label>
                      <Input
                        value={formData.config.member_attribute}
                        onChange={(e) => setFormData({
                          ...formData,
                          config: { ...formData.config, member_attribute: e.target.value },
                        })}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Page Size</Label>
                      <Input
                        type="number"
                        value={formData.config.page_size}
                        onChange={(e) => setFormData({
                          ...formData,
                          config: { ...formData.config, page_size: parseInt(e.target.value) || 500 },
                        })}
                      />
                    </div>
                  </div>
                </>
              )}
            </div>
          )}

          {/* Mapping Tab */}
          {activeTab === 'mapping' && (
            <div className="space-y-4">
              <div className="flex justify-end">
                <Button variant="outline" size="sm" onClick={applyDefaults}>
                  Apply {formData.type === 'active_directory' ? 'AD' : 'LDAP'} Defaults
                </Button>
              </div>
              {(['username', 'email', 'first_name', 'last_name', 'display_name', 'group_name'] as const).map(
                (field) => (
                  <div key={field} className="grid grid-cols-2 gap-4 items-start">
                    <Label className="capitalize mt-2">{field.replace('_', ' ')}</Label>
                    <div>
                      <Input
                        value={formData.config.attribute_mapping[field]}
                        onChange={(e) =>
                          setFormData({
                            ...formData,
                            config: {
                              ...formData.config,
                              attribute_mapping: {
                                ...formData.config.attribute_mapping,
                                [field]: e.target.value,
                              },
                            },
                          })
                        }
                      />
                      <FieldError path={`config.attribute_mapping.${field}`} />
                    </div>
                  </div>
                )
              )}
            </div>
          )}

          {/* Sync Tab */}
          {activeTab === 'sync' && (
            <div className="space-y-4">
              <div className="flex items-center space-x-2">
                <Switch
                  checked={formData.config.sync_enabled}
                  onCheckedChange={(v) => setFormData({
                    ...formData,
                    config: { ...formData.config, sync_enabled: v },
                  })}
                />
                <Label>Enable Scheduled Sync</Label>
              </div>
              <div className="space-y-2">
                <Label>Sync Interval (minutes)</Label>
                <Input
                  type="number"
                  value={formData.config.sync_interval}
                  onChange={(e) => setFormData({
                    ...formData,
                    config: { ...formData.config, sync_interval: parseInt(e.target.value) || 60 },
                  })}
                  disabled={!formData.config.sync_enabled}
                />
              </div>
              <div className="space-y-2">
                <Label>Deprovision Action</Label>
                <Select
                  value={formData.config.deprovision_action}
                  onValueChange={(v) => setFormData({
                    ...formData,
                    config: { ...formData.config, deprovision_action: v },
                  })}
                >
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="disable">Disable account</SelectItem>
                    <SelectItem value="delete">Delete account</SelectItem>
                  </SelectContent>
                </Select>
                <p className="text-sm text-muted-foreground">
                  Action taken when a user is removed from the LDAP directory during full sync.
                </p>
              </div>
            </div>
          )}

          {/* Live diagnostics results */}
          {diagResult && (
            <div className="mt-4 rounded-lg border p-3 space-y-2 bg-muted/30">
              <div className="flex items-center justify-between">
                <div className="text-sm font-semibold">
                  {diagResult.ok ? '✅ ' : '⚠️ '}
                  {diagResult.summary}
                </div>
                <Button variant="ghost" size="sm" onClick={() => setDiagResult(null)}>
                  Dismiss
                </Button>
              </div>
              <div className="space-y-1.5 max-h-64 overflow-y-auto">
                {diagResult.findings.map((f, i) => (
                  <div key={i} className="text-xs flex gap-2 items-start">
                    <span
                      className={
                        f.severity === 'error'
                          ? 'text-red-500'
                          : f.severity === 'warning'
                          ? 'text-amber-500'
                          : f.severity === 'ok'
                          ? 'text-emerald-500'
                          : 'text-blue-400'
                      }
                    >
                      {f.severity === 'error'
                        ? '✕'
                        : f.severity === 'warning'
                        ? '!'
                        : f.severity === 'ok'
                        ? '✓'
                        : 'ℹ'}
                    </span>
                    <div>
                      <div className="font-medium">{f.title}</div>
                      {f.detail && <div className="text-muted-foreground">{f.detail}</div>}
                      {f.suggested && (
                        <div className="text-muted-foreground mt-0.5">
                          Suggested:{' '}
                          {Object.entries(f.suggested)
                            .map(([k, v]) => `${k} = ${String(v)}`)
                            .join(', ')}
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
              {diagResult.suggested_config && Object.keys(diagResult.suggested_config).length > 0 && (
                <Button
                  size="sm"
                  className="w-full"
                  onClick={() => applySuggestions(diagResult.suggested_config!)}
                >
                  Apply all suggested fixes ({Object.keys(diagResult.suggested_config).length})
                </Button>
              )}
            </div>
          )}

          <div className="flex justify-end space-x-2 pt-4">
            <Button variant="outline" onClick={() => setDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="secondary"
              onClick={() => diagnoseMutation.mutate()}
              disabled={diagnoseMutation.isPending || (formData.type !== 'ldap' && formData.type !== 'active_directory')}
            >
              {diagnoseMutation.isPending && <LoadingSpinner size="sm" className="mr-2" />}
              Diagnose &amp; Auto-Fix
            </Button>
            <Button onClick={handleSubmit} disabled={createMutation.isPending || updateMutation.isPending}>
              {(createMutation.isPending || updateMutation.isPending) && (
                <LoadingSpinner size="sm" className="mr-2" />
              )}
              {editingId ? 'Update' : 'Create'}
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <AlertDialog open={!!deleteId} onOpenChange={(open) => { if (!open) setDeleteId(null) }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Directory Integration?</AlertDialogTitle>
            <AlertDialogDescription>
              This will remove the directory integration and its sync history.
              Synced users will not be deleted but will no longer be updated.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={() => deleteId && deleteMutation.mutate(deleteId)}
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
