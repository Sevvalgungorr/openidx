import { useMemo, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Folder, FolderPlus, Plus, Search, Star, Play, Eye, Trash2, Pencil, Upload,
  Server, Terminal, Monitor, Globe, KeyRound, StickyNote, CreditCard, ShieldCheck, Shield,
  Send, Copy, Lock, Route, AlertTriangle, AppWindow,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Textarea } from '../components/ui/textarea'
import { Badge } from '../components/ui/badge'
import { Checkbox } from '../components/ui/checkbox'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from '../components/ui/dialog'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '../components/ui/alert-dialog'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '../components/ui/select'
import {
  api, PamEntry, PamEntryType, PamFolder, PamEntryInput, PamConnectResult, PamImportResult,
} from '../lib/api'
import { useToast } from '../hooks/use-toast'
import { TerminalSession } from '../components/remote/terminal-session'
import { connectionPathSteps } from '../lib/connection-path'
import { remoteAppArgsLookSecret, REMOTE_APP_SECRET_HINT } from '../lib/remote-app'

// Icon + accent per entry type, so the list reads like RDM's typed tree.
const typeIcon = (t: string) => {
  switch (t) {
    case 'rdp': return Monitor
    case 'windows_app_host': return AppWindow
    case 'ssh':
    case 'telnet': return Terminal
    case 'vnc': return Server
    case 'website':
    case 'website_login': return Globe
    case 'credential':
    case 'ssh_key':
    case 'api_key':
    case 'certificate': return KeyRound
    case 'credit_card':
    case 'bank_account': return CreditCard
    default: return StickyNote
  }
}

const kindBadge: Record<string, string> = {
  session: 'bg-blue-100 text-blue-800',
  credential: 'bg-purple-100 text-purple-800',
  info: 'bg-gray-100 text-gray-800',
}

// Common RemoteApp publications; picking one pre-fills the alias/args so
// admins don't have to know Guacamole's parameter names. Aliases must match
// what the RDS host publishes (New-RDRemoteApp -Alias ...).
const remoteAppPresets: { label: string; alias: string; args?: string }[] = [
  { label: 'SQL Server Management Studio', alias: 'SSMS', args: '-E' },
  { label: 'PowerShell', alias: 'PowerShell' },
  { label: 'Visual Studio Code', alias: 'Code' },
  { label: 'Google Chrome', alias: 'Chrome' },
]

const emptyForm: PamEntryInput = {
  name: '', entry_type: 'rdp', description: '', tags: [],
  hostname: '', port: 0, username: '', domain: '', url: '',
  settings: {}, secret: '', credential_entry_id: '',
  allow_reveal: false, require_approval: false, record_session: false,
}

export function PamConnectionsPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()

  const [selectedFolder, setSelectedFolder] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [favoritesOnly, setFavoritesOnly] = useState(false)

  const [showEntryDialog, setShowEntryDialog] = useState(false)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [form, setForm] = useState<PamEntryInput>(emptyForm)

  const [showFolderDialog, setShowFolderDialog] = useState(false)
  const [folderName, setFolderName] = useState('')

  const [showImport, setShowImport] = useState(false)
  const [importData, setImportData] = useState('')
  const [importResult, setImportResult] = useState<PamImportResult | null>(null)

  // Clientless in-browser SSH terminal (wasm-ssh renderer). When set, a dialog
  // hosts the xterm session for this entry instead of opening a guac tab.
  const [terminalEntry, setTerminalEntry] = useState<PamEntry | null>(null)

  const [revealFor, setRevealFor] = useState<PamEntry | null>(null)
  const [revealReason, setRevealReason] = useState('')
  const [revealedValue, setRevealedValue] = useState<string | null>(null)

  const [requestFor, setRequestFor] = useState<PamEntry | null>(null)
  const [requestReason, setRequestReason] = useState('')

  const [deleteEntry, setDeleteEntry] = useState<PamEntry | null>(null)

  // "How does this connect" explainer dialog for a session entry.
  const [pathEntry, setPathEntry] = useState<PamEntry | null>(null)

  const { data: typesData } = useQuery({
    queryKey: ['pam-entry-types'],
    queryFn: () => api.pam.listEntryTypes(),
  })
  const entryTypes: PamEntryType[] = typesData?.types || []

  const { data: foldersData } = useQuery({
    queryKey: ['pam-folders'],
    queryFn: () => api.pam.listFolders(),
  })
  const folders: PamFolder[] = foldersData?.folders || []

  const { data: entriesData, isLoading } = useQuery({
    queryKey: ['pam-entries', selectedFolder, search, favoritesOnly],
    queryFn: () => api.pam.listEntries({
      folder_id: selectedFolder || undefined,
      q: search || undefined,
      favorites: favoritesOnly || undefined,
    }),
  })
  const entries: PamEntry[] = useMemo(() => entriesData?.entries || [], [entriesData])

  const credentialEntries = useMemo(
    () => entries.filter((e) => e.kind === 'credential'),
    [entries],
  )

  // How many loaded session entries borrow each credential entry's secret —
  // makes the credential ↔ session relationship visible from both sides.
  const credentialUsage = useMemo(() => {
    const usage = new Map<string, string[]>()
    for (const e of entries) {
      if (e.credential_entry_id) {
        usage.set(e.credential_entry_id, [...(usage.get(e.credential_entry_id) || []), e.name])
      }
    }
    return usage
  }, [entries])

  const selectedType = entryTypes.find((t) => t.type === form.entry_type)

  // RemoteApp (single published Windows app instead of a full desktop). These
  // are plain Guacamole RDP parameters carried in the entry's settings JSON —
  // the backend already forwards non-reserved settings to guacd, so SSMS &co
  // launch passwordless through the existing vault-injected flow.
  const settingStr = (key: string): string => {
    const v = form.settings?.[key]
    return typeof v === 'string' ? v : ''
  }
  const setSetting = (key: string, value: string) =>
    setForm((f) => {
      const next: Record<string, unknown> = { ...(f.settings || {}) }
      if (value) next[key] = value
      else delete next[key]
      return { ...f, settings: next }
    })
  // Guacamole expects RemoteApp aliases in the "||alias" form the RDS host
  // registers them under; prefix automatically so admins can type "SSMS".
  const setRemoteAppAlias = (raw: string) => {
    const trimmed = raw.trim()
    setSetting('remote-app', trimmed && !trimmed.startsWith('||') ? `||${trimmed}` : trimmed)
  }

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['pam-entries'] })
    queryClient.invalidateQueries({ queryKey: ['pam-folders'] })
  }

  const saveEntry = useMutation({
    mutationFn: () => {
      const body: PamEntryInput = {
        ...form,
        folder_id: form.folder_id || selectedFolder || undefined,
        port: form.port ? Number(form.port) : undefined,
        secret: form.secret || undefined,
        credential_entry_id: form.credential_entry_id || undefined,
      }
      return editingId ? api.pam.updateEntry(editingId, body) : api.pam.createEntry(body)
    },
    onSuccess: () => {
      invalidate()
      setShowEntryDialog(false)
      setForm(emptyForm)
      setEditingId(null)
      toast({ title: editingId ? 'Entry updated' : 'Entry created' })
    },
    onError: (e: Error) => toast({ title: 'Save failed', description: e.message, variant: 'destructive' }),
  })

  const createFolder = useMutation({
    mutationFn: () => api.pam.createFolder({ name: folderName, parent_id: selectedFolder || undefined }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['pam-folders'] })
      setShowFolderDialog(false)
      setFolderName('')
      toast({ title: 'Folder created' })
    },
  })

  const toggleFavorite = useMutation({
    mutationFn: (entry: PamEntry) =>
      entry.favorite ? api.pam.unfavorite(entry.id) : api.pam.favorite(entry.id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['pam-entries'] }),
  })

  const connect = useMutation({
    mutationFn: (id: string) => api.pam.connect(id),
    onSuccess: (res: PamConnectResult) => {
      const url = res.connect_url || res.url
      if (url) {
        window.open(url, '_blank', 'noopener')
        toast({
          title: 'Session launched',
          description: res.credential_injected
            ? 'Credential injected server-side — no password shown.'
            : undefined,
        })
      } else {
        toast({ title: 'Nothing to launch', variant: 'destructive' })
      }
    },
    onError: (e: Error & { status?: number; body?: PamConnectResult }) => {
      if (e.body?.approval_required || /requires approval/i.test(e.message)) {
        toast({ title: 'Approval required', description: 'Request access, then launch once approved.', variant: 'destructive' })
      } else {
        toast({ title: 'Launch failed', description: e.message, variant: 'destructive' })
      }
    },
  })

  // launch dispatches on the entry's renderer: wasm-ssh opens the in-browser
  // terminal dialog (no guac tab); everything else uses the existing connect
  // flow (guacamole tab / website URL). The permission + approval gate is
  // enforced server-side for both paths.
  const launch = (entry: PamEntry) => {
    if (entry.renderer === 'wasm-ssh') {
      setTerminalEntry(entry)
      return
    }
    connect.mutate(entry.id)
  }

  const del = useMutation({
    mutationFn: (id: string) => api.pam.deleteEntry(id),
    onSuccess: () => {
      invalidate()
      setDeleteEntry(null)
      toast({ title: 'Entry deleted' })
    },
  })

  const { data: broker } = useQuery({
    queryKey: ['pam-broker-status'],
    queryFn: () => api.pam.brokerStatus(),
  })
  const zitiAvailable = broker?.reach_modes?.includes('ziti') ?? false

  const toggleZiti = useMutation({
    mutationFn: (entry: PamEntry) =>
      entry.ziti_enabled ? api.pam.disableZiti(entry.id) : api.pam.enableZiti(entry.id),
    onSuccess: (res: { reach_mode: string }) => {
      invalidate()
      toast({
        title: res.reach_mode === 'ziti' ? 'Ziti reach enabled' : 'Ziti reach disabled',
        description: res.reach_mode === 'ziti'
          ? 'This connection now reaches its target over the OpenZiti overlay — no inbound target exposure.'
          : 'Reverted to direct reach.',
      })
    },
    onError: (e: Error) => toast({ title: 'Ziti toggle failed', description: e.message, variant: 'destructive' }),
  })

  const reveal = useMutation({
    mutationFn: () => api.pam.reveal(revealFor!.id, revealReason),
    onSuccess: (res: { value: string }) => setRevealedValue(res.value),
    onError: (e: Error) => toast({ title: 'Reveal failed', description: e.message, variant: 'destructive' }),
  })

  const requestAccess = useMutation({
    mutationFn: () => api.pam.requestAccess(requestFor!.id, requestReason),
    onSuccess: () => {
      setRequestFor(null)
      setRequestReason('')
      toast({ title: 'Access requested', description: 'An approver will review your request.' })
    },
  })

  const runImport = useMutation({
    mutationFn: () => api.pam.importRDM(importData, selectedFolder || undefined),
    onSuccess: (res: PamImportResult) => {
      setImportResult(res)
      setImportData('')
      invalidate()
      toast({ title: 'Import complete', description: `${res.entries_created} entries, ${res.folders_created} folders.` })
    },
    onError: (e: Error) => toast({ title: 'Import failed', description: e.message, variant: 'destructive' }),
  })

  const openCreate = () => {
    setEditingId(null)
    setForm({ ...emptyForm, folder_id: selectedFolder || undefined })
    setShowEntryDialog(true)
  }

  const openEdit = (entry: PamEntry) => {
    setEditingId(entry.id)
    setForm({
      folder_id: entry.folder_id, name: entry.name, entry_type: entry.entry_type,
      description: entry.description, tags: entry.tags, hostname: entry.hostname,
      port: entry.port, username: entry.username, domain: entry.domain, url: entry.url,
      settings: entry.settings || {},
      secret: '', credential_entry_id: entry.credential_entry_id,
      allow_reveal: entry.allow_reveal, require_approval: entry.require_approval,
      record_session: entry.record_session, renderer: entry.renderer,
    })
    setShowEntryDialog(true)
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Server className="h-6 w-6" /> Connections
          </h1>
          <p className="text-muted-foreground">
            Devolutions RDM-style connection manager — launch RDP/SSH/VNC sessions with the
            credential injected server-side. You never see the password.
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => { setImportResult(null); setShowImport(true) }}>
            <Upload className="h-4 w-4 mr-1" /> Import from RDM
          </Button>
          <Button variant="outline" onClick={() => setShowFolderDialog(true)}>
            <FolderPlus className="h-4 w-4 mr-1" /> New Folder
          </Button>
          <Button onClick={openCreate}>
            <Plus className="h-4 w-4 mr-1" /> New Entry
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Folder tree */}
        <Card className="lg:col-span-1 h-fit">
          <CardHeader><CardTitle className="text-sm">Folders</CardTitle></CardHeader>
          <CardContent className="space-y-1">
            <button
              className={`w-full text-left px-2 py-1.5 rounded text-sm flex items-center gap-2 ${selectedFolder === null ? 'bg-primary/10 font-medium' : 'hover:bg-muted'}`}
              onClick={() => setSelectedFolder(null)}
            >
              <Folder className="h-4 w-4" /> All Connections
            </button>
            {folders.map((f) => (
              <button
                key={f.id}
                className={`w-full text-left px-2 py-1.5 rounded text-sm flex items-center justify-between gap-2 ${selectedFolder === f.id ? 'bg-primary/10 font-medium' : 'hover:bg-muted'}`}
                style={{ paddingLeft: f.parent_id ? '1.75rem' : '0.5rem' }}
                onClick={() => setSelectedFolder(f.id)}
              >
                <span className="flex items-center gap-2 truncate"><Folder className="h-4 w-4 shrink-0" /> {f.name}</span>
                <Badge variant="outline" className="shrink-0">{f.entry_count}</Badge>
              </button>
            ))}
          </CardContent>
        </Card>

        {/* Entry list */}
        <div className="lg:col-span-3 space-y-4">
          <div className="flex items-center gap-2">
            <div className="relative flex-1">
              <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                className="pl-8"
                placeholder="Search connections, hosts, tags…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>
            <Button
              variant={favoritesOnly ? 'default' : 'outline'}
              onClick={() => setFavoritesOnly((v) => !v)}
            >
              <Star className="h-4 w-4 mr-1" /> Favorites
            </Button>
          </div>

          {isLoading ? (
            <div className="flex justify-center py-12"><LoadingSpinner /></div>
          ) : entries.length === 0 ? (
            <Card><CardContent className="py-12 text-center text-muted-foreground">
              No connections yet. Create one, or import your Devolutions RDM export.
            </CardContent></Card>
          ) : (
            <div className="space-y-2">
              {entries.map((entry) => {
                const Icon = typeIcon(entry.entry_type)
                const launchable = entry.kind === 'session'
                return (
                  <Card key={entry.id} className="hover:border-primary/40 transition-colors">
                    <CardContent className="flex items-center gap-3 py-3">
                      <button onClick={() => toggleFavorite.mutate(entry)} title="Favorite">
                        <Star className={`h-4 w-4 ${entry.favorite ? 'fill-yellow-400 text-yellow-500' : 'text-muted-foreground'}`} />
                      </button>
                      <Icon className="h-5 w-5 text-muted-foreground shrink-0" />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="font-medium truncate">{entry.name}</span>
                          <Badge className={kindBadge[entry.kind] || ''}>{entry.entry_type}</Badge>
                          {entry.require_approval && <Badge variant="outline" title="Requires approval"><Lock className="h-3 w-3" /></Badge>}
                          {entry.record_session && <Badge variant="outline">rec</Badge>}
                          {typeof entry.settings['remote-app'] === 'string' && entry.settings['remote-app'] !== '' && (
                            <Badge variant="outline" title="Launches a single published RemoteApp instead of the full desktop">
                              app: {String(entry.settings['remote-app']).replace(/^\|\|/, '')}
                            </Badge>
                          )}
                          {entry.has_secret && <Badge variant="outline" title="Vaulted secret"><KeyRound className="h-3 w-3" /></Badge>}
                          {entry.ziti_enabled && <Badge className="bg-emerald-100 text-emerald-800" title="Reaches target over the OpenZiti overlay (zero-trust)"><Shield className="h-3 w-3 mr-1" />via Ziti</Badge>}
                          {entry.kind === 'credential' && (credentialUsage.get(entry.id)?.length ?? 0) > 0 && (
                            <Badge variant="outline" title={`Injected into: ${credentialUsage.get(entry.id)!.join(', ')}`}>
                              used by {credentialUsage.get(entry.id)!.length}
                            </Badge>
                          )}
                        </div>
                        <div className="text-xs text-muted-foreground truncate">
                          {entry.hostname && <span>{entry.username ? `${entry.username}@` : ''}{entry.hostname}{entry.port ? `:${entry.port}` : ''}</span>}
                          {entry.url && <span>{entry.url}</span>}
                          {entry.credential_entry_name && <span> · linked credential: {entry.credential_entry_name}</span>}
                        </div>
                      </div>
                      <div className="flex items-center gap-1 shrink-0">
                        {launchable && (
                          <Button size="sm" onClick={() => launch(entry)} disabled={connect.isPending}>
                            <Play className="h-4 w-4 mr-1" /> Connect
                          </Button>
                        )}
                        {entry.require_approval && (
                          <Button size="sm" variant="outline" onClick={() => { setRequestFor(entry); setRequestReason('') }} title="Request access">
                            <Send className="h-4 w-4" />
                          </Button>
                        )}
                        {entry.has_secret && entry.allow_reveal && (
                          <Button size="sm" variant="outline" onClick={() => { setRevealFor(entry); setRevealReason(''); setRevealedValue(null) }} title="Reveal secret">
                            <Eye className="h-4 w-4" />
                          </Button>
                        )}
                        {launchable && (zitiAvailable || entry.ziti_enabled) && (
                          <Button
                            size="sm"
                            variant={entry.ziti_enabled ? 'default' : 'outline'}
                            onClick={() => toggleZiti.mutate(entry)}
                            disabled={toggleZiti.isPending}
                            title={entry.ziti_enabled ? 'Disable Ziti reach (revert to direct)' : 'Enable Ziti reach (zero-trust overlay to target)'}
                          >
                            <Shield className="h-4 w-4" />
                          </Button>
                        )}
                        {launchable && (
                          <Button size="sm" variant="ghost" onClick={() => setPathEntry(entry)} title="Launch path">
                            <Route className="h-4 w-4" />
                          </Button>
                        )}
                        <Button size="sm" variant="ghost" onClick={() => openEdit(entry)} title="Edit">
                          <Pencil className="h-4 w-4" />
                        </Button>
                        <Button size="sm" variant="ghost" onClick={() => setDeleteEntry(entry)} title="Delete">
                          <Trash2 className="h-4 w-4 text-destructive" />
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                )
              })}
            </div>
          )}
        </div>
      </div>

      {/* Entry create/edit dialog */}
      <Dialog open={showEntryDialog} onOpenChange={setShowEntryDialog}>
        <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
          <DialogHeader><DialogTitle>{editingId ? 'Edit Entry' : 'New Entry'}</DialogTitle></DialogHeader>
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-sm font-medium">Type</label>
                <Select value={form.entry_type} onValueChange={(v) => setForm((f) => ({ ...f, entry_type: v }))} disabled={!!editingId}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {entryTypes.map((t) => (
                      <SelectItem key={t.type} value={t.type}>{t.label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <label className="text-sm font-medium">Name</label>
                <Input value={form.name} onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} placeholder="DC01 – Domain Controller" />
              </div>
            </div>

            {selectedType?.protocol && (
              <div className="grid grid-cols-3 gap-4">
                <div className="col-span-2">
                  <label className="text-sm font-medium">Hostname</label>
                  <Input value={form.hostname} onChange={(e) => setForm((f) => ({ ...f, hostname: e.target.value }))} placeholder="dc01.corp.local" />
                </div>
                <div>
                  <label className="text-sm font-medium">Port</label>
                  <Input type="number" value={form.port || ''} onChange={(e) => setForm((f) => ({ ...f, port: Number(e.target.value) }))} placeholder="auto" />
                </div>
              </div>
            )}

            {form.entry_type === 'website' && (
              <div>
                <label className="text-sm font-medium">URL</label>
                <Input value={form.url} onChange={(e) => setForm((f) => ({ ...f, url: e.target.value }))} placeholder="https://portal.corp" />
              </div>
            )}

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-sm font-medium">Username</label>
                <Input value={form.username} onChange={(e) => setForm((f) => ({ ...f, username: e.target.value }))} placeholder="administrator" />
              </div>
              {form.entry_type === 'rdp' && (
                <div>
                  <label className="text-sm font-medium">Domain</label>
                  <Input value={form.domain} onChange={(e) => setForm((f) => ({ ...f, domain: e.target.value }))} placeholder="CORP" />
                </div>
              )}
            </div>

            {form.entry_type === 'rdp' && (
              <div className="rounded-md border p-3 space-y-3">
                <div>
                  <p className="text-sm font-medium">RemoteApp (optional)</p>
                  <p className="text-xs text-muted-foreground">
                    Publish a single application (e.g. SSMS) instead of the full desktop.
                    Requires the program to be published as a RemoteApp on the RDS host.
                    Credentials stay vault-injected; recording and approval work as usual.
                  </p>
                </div>
                <div>
                  <label className="text-sm font-medium">Preset</label>
                  <Select
                    value="custom"
                    onValueChange={(v) => {
                      const preset = remoteAppPresets.find((p) => p.alias === v)
                      if (!preset) return
                      setForm((f) => ({
                        ...f,
                        settings: {
                          ...(f.settings || {}),
                          'remote-app': `||${preset.alias}`,
                          ...(preset.args ? { 'remote-app-args': preset.args } : {}),
                        },
                      }))
                    }}
                  >
                    <SelectTrigger><SelectValue placeholder="Pick a common app…" /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="custom">Custom…</SelectItem>
                      {remoteAppPresets.map((p) => (
                        <SelectItem key={p.alias} value={p.alias}>{p.label}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="text-sm font-medium">Program alias</label>
                    <Input
                      value={settingStr('remote-app').replace(/^\|\|/, '')}
                      onChange={(e) => setRemoteAppAlias(e.target.value)}
                      placeholder="SSMS"
                    />
                  </div>
                  <div>
                    <label className="text-sm font-medium">Working directory</label>
                    <Input
                      value={settingStr('remote-app-dir')}
                      onChange={(e) => setSetting('remote-app-dir', e.target.value)}
                      placeholder="C:\Users\Public"
                    />
                  </div>
                </div>
                <div>
                  <label className="text-sm font-medium">Command-line arguments</label>
                  <Input
                    value={settingStr('remote-app-args')}
                    onChange={(e) => setSetting('remote-app-args', e.target.value)}
                    placeholder="-S sql01.corp.local -E"
                    aria-invalid={remoteAppArgsLookSecret(settingStr('remote-app-args'))}
                    className={remoteAppArgsLookSecret(settingStr('remote-app-args')) ? 'border-destructive' : undefined}
                  />
                  {remoteAppArgsLookSecret(settingStr('remote-app-args')) && (
                    <p className="mt-1 flex items-start gap-1.5 text-xs text-destructive">
                      <AlertTriangle className="h-3.5 w-3.5 shrink-0 mt-px" />
                      <span>{REMOTE_APP_SECRET_HINT}</span>
                    </p>
                  )}
                </div>
              </div>
            )}

            {/* Credential: own secret or linked credential entry */}
            {selectedType?.kind === 'session' && credentialEntries.length > 0 && (
              <div>
                <label className="text-sm font-medium">Linked credential (optional)</label>
                <Select
                  value={form.credential_entry_id || 'none'}
                  onValueChange={(v) => setForm((f) => ({ ...f, credential_entry_id: v === 'none' ? '' : v }))}
                >
                  <SelectTrigger><SelectValue placeholder="Use this entry's own secret" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="none">Use this entry's own secret</SelectItem>
                    {credentialEntries.map((c) => (
                      <SelectItem key={c.id} value={c.id}>{c.name}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}

            {!form.credential_entry_id && (
              <div>
                <label className="text-sm font-medium">
                  {selectedType?.secret_label || 'Secret'}{editingId ? ' (leave blank to keep current)' : ''}
                </label>
                <Textarea
                  value={form.secret}
                  onChange={(e) => setForm((f) => ({ ...f, secret: e.target.value }))}
                  placeholder="Stored envelope-encrypted in the vault; injected server-side at connect time."
                  rows={form.entry_type === 'ssh_key' ? 4 : 2}
                />
              </div>
            )}

            <div>
              <label className="text-sm font-medium">Description</label>
              <Input value={form.description} onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))} />
            </div>

            <div className="flex flex-wrap gap-4 pt-2">
              <label className="flex items-center gap-2 text-sm">
                <Checkbox checked={form.allow_reveal} onCheckedChange={(v) => setForm((f) => ({ ...f, allow_reveal: !!v }))} />
                Allow password reveal
              </label>
              <label className="flex items-center gap-2 text-sm">
                <Checkbox checked={form.require_approval} onCheckedChange={(v) => setForm((f) => ({ ...f, require_approval: !!v }))} />
                Require approval to connect
              </label>
              <label className="flex items-center gap-2 text-sm">
                <Checkbox checked={form.record_session} onCheckedChange={(v) => setForm((f) => ({ ...f, record_session: !!v }))} />
                Record session
              </label>
            </div>
            {selectedType?.protocol === 'ssh' && (
              <label className="flex items-center gap-2 text-sm pt-1">
                <Checkbox
                  checked={form.renderer === 'wasm-ssh'}
                  onCheckedChange={(v) => setForm((f) => ({ ...f, renderer: v ? 'wasm-ssh' : 'guacamole' }))}
                />
                Open in browser terminal (clientless SSH, no Guacamole tab)
              </label>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowEntryDialog(false)}>Cancel</Button>
            <Button
              onClick={() => saveEntry.mutate()}
              disabled={saveEntry.isPending || !form.name || remoteAppArgsLookSecret(settingStr('remote-app-args'))}
            >
              {editingId ? 'Save' : 'Create'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Connection path explainer: the launch chain with this entry's real config */}
      <Dialog open={!!pathEntry} onOpenChange={(o) => { if (!o) setPathEntry(null) }}>
        <DialogContent className="max-w-md">
          <DialogHeader><DialogTitle>How “{pathEntry?.name}” connects</DialogTitle></DialogHeader>
          {pathEntry && (
            <div>
              {connectionPathSteps(pathEntry).map((step, i, arr) => {
                const StepIcon = step.icon
                return (
                  <div key={i} className="flex gap-3">
                    <div className="flex flex-col items-center">
                      <div className="rounded-full border p-1.5 bg-muted/40">
                        <StepIcon className="h-4 w-4 text-muted-foreground" />
                      </div>
                      {i < arr.length - 1 && <div className="w-px flex-1 bg-border my-1" />}
                    </div>
                    <div className="pb-4 min-w-0">
                      <p className="text-sm font-medium">{step.title}</p>
                      <p className="text-xs text-muted-foreground">{step.desc}</p>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* New folder dialog */}
      <Dialog open={showFolderDialog} onOpenChange={setShowFolderDialog}>
        <DialogContent>
          <DialogHeader><DialogTitle>New Folder</DialogTitle></DialogHeader>
          <Input value={folderName} onChange={(e) => setFolderName(e.target.value)} placeholder="Folder name" />
          {selectedFolder && <p className="text-xs text-muted-foreground">Created under the selected folder.</p>}
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowFolderDialog(false)}>Cancel</Button>
            <Button onClick={() => createFolder.mutate()} disabled={!folderName || createFolder.isPending}>Create</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* RDM import dialog */}
      <Dialog open={showImport} onOpenChange={setShowImport}>
        <DialogContent className="max-w-2xl">
          <DialogHeader><DialogTitle>Import from Devolutions RDM</DialogTitle></DialogHeader>
          {importResult ? (
            <div className="space-y-3">
              <div className="flex items-center gap-2 text-green-600"><ShieldCheck className="h-5 w-5" /> Import complete</div>
              <div className="grid grid-cols-3 gap-3 text-center">
                <Card><CardContent className="py-3"><div className="text-2xl font-bold">{importResult.entries_created}</div><div className="text-xs text-muted-foreground">Entries</div></CardContent></Card>
                <Card><CardContent className="py-3"><div className="text-2xl font-bold">{importResult.folders_created}</div><div className="text-xs text-muted-foreground">Folders</div></CardContent></Card>
                <Card><CardContent className="py-3"><div className="text-2xl font-bold">{importResult.secrets_stored}</div><div className="text-xs text-muted-foreground">Secrets vaulted</div></CardContent></Card>
              </div>
              {Object.keys(importResult.by_type).length > 0 && (
                <div className="flex flex-wrap gap-2">
                  {Object.entries(importResult.by_type).map(([t, n]) => (
                    <Badge key={t} variant="outline">{t}: {n}</Badge>
                  ))}
                </div>
              )}
              {importResult.skipped.length > 0 && (
                <div className="text-xs text-muted-foreground">
                  {importResult.skipped.length} skipped: {importResult.skipped.slice(0, 5).map((s) => s.name).join(', ')}
                  {importResult.skipped.length > 5 ? '…' : ''}
                </div>
              )}
              <DialogFooter>
                <Button onClick={() => setShowImport(false)}>Done</Button>
              </DialogFooter>
            </div>
          ) : (
            <div className="space-y-3">
              <p className="text-sm text-muted-foreground">
                In RDM: <strong>File → Export</strong> → choose <strong>.json</strong>. Paste the export below.
                Groups become folders, sessions/credentials become entries, and passwords are sealed into the vault.
              </p>
              <Textarea
                value={importData}
                onChange={(e) => setImportData(e.target.value)}
                placeholder='{"Connections":[ … ]}'
                rows={10}
                className="font-mono text-xs"
              />
              <DialogFooter>
                <Button variant="outline" onClick={() => setShowImport(false)}>Cancel</Button>
                <Button onClick={() => runImport.mutate()} disabled={!importData || runImport.isPending}>
                  <Upload className="h-4 w-4 mr-1" /> Import
                </Button>
              </DialogFooter>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Reveal dialog */}
      <Dialog open={!!revealFor} onOpenChange={(o) => { if (!o) setRevealFor(null) }}>
        <DialogContent>
          <DialogHeader><DialogTitle>Reveal secret — {revealFor?.name}</DialogTitle></DialogHeader>
          {revealedValue === null ? (
            <div className="space-y-3">
              <p className="text-sm text-muted-foreground">Revealing is audited and reason-stamped.</p>
              <Textarea value={revealReason} onChange={(e) => setRevealReason(e.target.value)} placeholder="Reason for reveal (required)" rows={2} />
              <DialogFooter>
                <Button variant="outline" onClick={() => setRevealFor(null)}>Cancel</Button>
                <Button onClick={() => reveal.mutate()} disabled={!revealReason || reveal.isPending}>
                  <Eye className="h-4 w-4 mr-1" /> Reveal
                </Button>
              </DialogFooter>
            </div>
          ) : (
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <Input readOnly value={revealedValue} className="font-mono" />
                <Button size="sm" variant="outline" onClick={() => { navigator.clipboard.writeText(revealedValue); toast({ title: 'Copied' }) }}>
                  <Copy className="h-4 w-4" />
                </Button>
              </div>
              <DialogFooter>
                <Button onClick={() => setRevealFor(null)}>Close</Button>
              </DialogFooter>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Request access dialog */}
      <Dialog open={!!requestFor} onOpenChange={(o) => { if (!o) setRequestFor(null) }}>
        <DialogContent>
          <DialogHeader><DialogTitle>Request access — {requestFor?.name}</DialogTitle></DialogHeader>
          <Textarea value={requestReason} onChange={(e) => setRequestReason(e.target.value)} placeholder="Why do you need this session? (optional)" rows={3} />
          <DialogFooter>
            <Button variant="outline" onClick={() => setRequestFor(null)}>Cancel</Button>
            <Button onClick={() => requestAccess.mutate()} disabled={requestAccess.isPending}>
              <Send className="h-4 w-4 mr-1" /> Request
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete confirm */}
      <AlertDialog open={!!deleteEntry} onOpenChange={(o) => { if (!o) setDeleteEntry(null) }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete “{deleteEntry?.name}”?</AlertDialogTitle>
            <AlertDialogDescription>
              The vaulted secret is cryptographically erased and the brokered connection removed. This cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={() => deleteEntry && del.mutate(deleteEntry.id)}>Delete</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Clientless in-browser SSH terminal (wasm-ssh renderer). */}
      <Dialog open={!!terminalEntry} onOpenChange={(o) => { if (!o) setTerminalEntry(null) }}>
        <DialogContent className="max-w-4xl p-0 overflow-hidden">
          {terminalEntry && (
            <TerminalSession
              entryId={terminalEntry.id}
              entryName={terminalEntry.name}
              onClose={() => setTerminalEntry(null)}
            />
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}
