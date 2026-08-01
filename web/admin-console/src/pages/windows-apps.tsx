import { useMemo, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  AppWindow, Play, Plus, Trash2, Pencil, ShieldAlert, ShieldCheck, Server,
  Layers, Download, AlertTriangle, CheckCircle2, HelpCircle, Rss, Link2, Unlink,
} from 'lucide-react'
import { Card, CardContent } from '../components/ui/card'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Textarea } from '../components/ui/textarea'
import { Badge } from '../components/ui/badge'
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
  api, WindowsApp, WindowsAppInput, WindowsAppPool, WindowsAppHostState,
  WindowsAppHostAgent, WindowsAppLaunchConflict, PamEntry,
} from '../lib/api'
import { useToast } from '../hooks/use-toast'
import { remoteAppArgsLookSecret, REMOTE_APP_SECRET_HINT } from '../lib/remote-app'
import { isAxiosError } from 'axios'

const emptyApp: WindowsAppInput = {
  host_entry_id: '', alias: '', display_name: '', exec_path: '', args: '', working_dir: '',
}

// A launch conflict the user must resolve (server replied 409).
type Conflict = { app: WindowsApp; body: WindowsAppLaunchConflict }

export function WindowsAppsPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()

  const [showAppDialog, setShowAppDialog] = useState(false)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [form, setForm] = useState<WindowsAppInput>(emptyApp)
  const [deleteApp, setDeleteApp] = useState<WindowsApp | null>(null)
  const [conflict, setConflict] = useState<Conflict | null>(null)
  const [showImport, setShowImport] = useState(false)
  const [importHost, setImportHost] = useState('')
  const [importData, setImportData] = useState('')

  const { data, isLoading } = useQuery({
    queryKey: ['windows-apps'],
    queryFn: () => api.windowsApps.list(),
  })
  const apps: WindowsApp[] = useMemo(() => data?.apps ?? [], [data])
  const pools: WindowsAppPool[] = useMemo(() => data?.pools ?? [], [data])
  const hostState: WindowsAppHostState[] = useMemo(() => data?.host_state ?? [], [data])
  const hostAgents: WindowsAppHostAgent[] = useMemo(() => data?.host_agents ?? [], [data])

  // Candidate hosts for the "add app" form: RDP-capable PAM entries. We fetch
  // the connections list and filter to app hosts + plain rdp entries.
  const { data: entriesData } = useQuery({
    queryKey: ['pam-entries', 'app-hosts'],
    queryFn: () => api.pam.listEntries(),
  })
  const hostEntries: PamEntry[] = useMemo(
    () => (entriesData?.entries ?? []).filter(
      (e) => e.entry_type === 'windows_app_host' || e.entry_type === 'rdp',
    ),
    [entriesData],
  )

  // Hosts running with the dangerous allowlist bypass — surfaced prominently.
  const insecureHosts = useMemo(
    () => hostState.filter((h) => h.allow_unlisted_remote_programs === true),
    [hostState],
  )

  // Dedicated app hosts (not plain rdp) — the discovery section binds an agent
  // to each so its published apps auto-sync.
  const appHosts: PamEntry[] = useMemo(
    () => hostEntries.filter((e) => e.entry_type === 'windows_app_host'),
    [hostEntries],
  )
  const agentByHost = useMemo(() => {
    const m = new Map<string, WindowsAppHostAgent>()
    for (const a of hostAgents) m.set(a.host_entry_id, a)
    return m
  }, [hostAgents])
  // Per-host agent_id being typed into the link field (keyed by host id).
  const [linkInputs, setLinkInputs] = useState<Record<string, string>>({})

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['windows-apps'] })

  const linkAgent = useMutation({
    mutationFn: (v: { hostId: string; agentId: string }) => api.windowsApps.linkAgent(v.hostId, v.agentId),
    onSuccess: (_r, v) => {
      invalidate()
      setLinkInputs((s) => ({ ...s, [v.hostId]: '' }))
      toast({ title: 'Agent linked', description: 'Discovery will auto-sync this host.' })
    },
    onError: (e: Error) => toast({ title: 'Link failed', description: e.message, variant: 'destructive' }),
  })
  const unlinkAgent = useMutation({
    mutationFn: (hostId: string) => api.windowsApps.unlinkAgent(hostId),
    onSuccess: () => { invalidate(); toast({ title: 'Agent unlinked' }) },
    onError: (e: Error) => toast({ title: 'Unlink failed', description: e.message, variant: 'destructive' }),
  })

  const saveApp = useMutation({
    mutationFn: () => {
      const body: WindowsAppInput = {
        ...form,
        host_entry_id: form.host_entry_id || undefined,
        pool_id: form.pool_id || undefined,
      }
      return editingId ? api.windowsApps.update(editingId, body) : api.windowsApps.create(body)
    },
    onSuccess: () => {
      invalidate()
      setShowAppDialog(false)
      setForm(emptyApp)
      setEditingId(null)
      toast({ title: editingId ? 'App updated' : 'App added' })
    },
    onError: (e: Error) => toast({ title: 'Save failed', description: e.message, variant: 'destructive' }),
  })

  const removeApp = useMutation({
    mutationFn: (id: string) => api.windowsApps.remove(id),
    onSuccess: () => { invalidate(); setDeleteApp(null); toast({ title: 'App removed' }) },
  })

  const importDiscovery = useMutation({
    mutationFn: () => api.windowsApps.importDiscovery(importHost, importData),
    onSuccess: (r) => {
      invalidate()
      setShowImport(false)
      setImportData('')
      toast({ title: 'Discovery imported', description: `${r.apps_created} added, ${r.apps_updated} updated` })
    },
    onError: (e: Error) => toast({ title: 'Import failed', description: e.message, variant: 'destructive' }),
  })

  // Launch. On a 409 the server sends a WindowsAppLaunchConflict — open the
  // resolution dialog instead of erroring. replaceSessionId retries after the
  // user chooses to disconnect a session.
  const launch = useMutation({
    mutationFn: (v: { app: WindowsApp; replaceSessionId?: string }) =>
      api.windowsApps.launch(v.app.id, v.replaceSessionId),
    onSuccess: (r) => {
      setConflict(null)
      window.open(r.connect_url, '_blank', 'noopener')
      toast({ title: 'Launching', description: `${r.host_name} — session ${r.recorded ? 'recorded' : 'live'}` })
    },
    onError: (e: unknown, v) => {
      // A placement conflict is a 409 carrying a WindowsAppLaunchConflict body,
      // not an error to toast — open the resolution dialog instead.
      if (isAxiosError(e) && e.response?.status === 409 && e.response.data) {
        setConflict({ app: v.app, body: e.response.data as WindowsAppLaunchConflict })
        return
      }
      toast({ title: 'Launch failed', description: (e as Error).message, variant: 'destructive' })
    },
  })

  const openEdit = (app: WindowsApp) => {
    setEditingId(app.id)
    setForm({
      host_entry_id: app.host_entry_id ?? '', pool_id: app.pool_id ?? '',
      alias: app.alias, display_name: app.display_name,
      exec_path: app.exec_path ?? '', args: app.args ?? '', working_dir: app.working_dir ?? '',
      require_approval: app.require_approval, record_session: app.record_session,
    })
    setShowAppDialog(true)
  }

  const openNew = () => { setEditingId(null); setForm(emptyApp); setShowAppDialog(true) }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <AppWindow className="h-6 w-6" /> Windows Apps
          </h1>
          <p className="text-muted-foreground">
            Publish single Windows applications (SSMS, etc.) to the browser — passwordless,
            recorded, and placed across a host pool. No full desktop.
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => setShowImport(true)}>
            <Download className="h-4 w-4 mr-1" /> Import from host
          </Button>
          <Button onClick={openNew}>
            <Plus className="h-4 w-4 mr-1" /> Add app
          </Button>
        </div>
      </div>

      {/* Prominent host-posture warning — the allowlist bypass defeats containment. */}
      {insecureHosts.length > 0 && (
        <Card className="border-destructive bg-destructive/5">
          <CardContent className="flex items-start gap-3 py-4">
            <ShieldAlert className="h-5 w-5 text-destructive shrink-0 mt-0.5" />
            <div className="text-sm">
              <p className="font-semibold text-destructive">
                {insecureHosts.length} host{insecureHosts.length > 1 ? 's' : ''} allow unlisted programs
              </p>
              <p className="text-muted-foreground">
                These hosts have <code>fAllowUnlistedRemotePrograms</code> enabled, which lets a
                published app launch <strong>any</strong> program (including cmd.exe) — defeating
                RemoteApp containment. Re-run the host prep script to disable it, then rediscover.
              </p>
            </div>
          </CardContent>
        </Card>
      )}

      {isLoading ? (
        <div className="flex justify-center py-12"><LoadingSpinner /></div>
      ) : apps.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center space-y-3">
            <AppWindow className="h-10 w-10 mx-auto text-muted-foreground" />
            <p className="font-medium">No published apps yet</p>
            <p className="text-sm text-muted-foreground max-w-md mx-auto">
              First add a Windows RDP host under <strong>Connections</strong>, publish apps on it with the
              host prep script, then <strong>Import from host</strong> to pull the published list — or
              <strong> Add app</strong> to enter one manually.
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {apps.map((app) => (
            <AppCard
              key={app.id}
              app={app}
              launching={launch.isPending}
              onLaunch={() => launch.mutate({ app })}
              onEdit={() => openEdit(app)}
              onDelete={() => setDeleteApp(app)}
            />
          ))}
        </div>
      )}

      {/* Pools summary — capacity at a glance. */}
      {pools.length > 0 && (
        <div>
          <h2 className="text-sm font-semibold text-muted-foreground mb-2 flex items-center gap-1.5">
            <Layers className="h-4 w-4" /> Host pools
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {pools.map((pool) => {
              const used = pool.members.reduce((n, m) => n + m.active_sessions, 0)
              const cap = pool.members.reduce((n, m) => n + m.max_sessions, 0)
              return (
                <Card key={pool.id}>
                  <CardContent className="py-3">
                    <div className="flex items-center justify-between">
                      <span className="font-medium">{pool.name}</span>
                      <Badge variant="outline">{used}/{cap} sessions</Badge>
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">
                      {pool.members.length} host{pool.members.length !== 1 ? 's' : ''} · placement: {pool.placement.replace('_', ' ')}
                    </p>
                  </CardContent>
                </Card>
              )
            })}
          </div>
        </div>
      )}

      {/* Discovery sources — bind an agent per host for auto-sync, or fall back
          to the paste import. Only dedicated app hosts appear here. */}
      {appHosts.length > 0 && (
        <div>
          <h2 className="text-sm font-semibold text-muted-foreground mb-2 flex items-center gap-1.5">
            <Rss className="h-4 w-4" /> Discovery
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {appHosts.map((host) => {
              const bound = agentByHost.get(host.id)
              return (
                <Card key={host.id}>
                  <CardContent className="py-3 space-y-2">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-medium flex items-center gap-1.5 min-w-0 truncate">
                        <Server className="h-4 w-4 shrink-0" /> {host.name}
                      </span>
                      {bound ? (
                        <Badge variant="outline" className="text-emerald-700 border-emerald-300 shrink-0">
                          <Link2 className="h-3 w-3 mr-1" /> agent linked
                        </Badge>
                      ) : (
                        <Badge variant="outline" className="text-muted-foreground shrink-0">manual paste</Badge>
                      )}
                    </div>
                    {bound ? (
                      <div className="flex items-center justify-between gap-2 text-xs text-muted-foreground">
                        <span className="truncate">
                          {bound.agent_id}{bound.last_seen_at ? ` · seen ${new Date(bound.last_seen_at).toLocaleString()}` : ''}
                        </span>
                        <Button size="sm" variant="ghost" disabled={unlinkAgent.isPending}
                          onClick={() => unlinkAgent.mutate(host.id)} title="Unlink agent">
                          <Unlink className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    ) : (
                      <div className="flex items-center gap-1.5">
                        <Input
                          className="h-8 text-sm"
                          placeholder="Enrolled agent ID (e.g. agent-1a2b3c4d)"
                          value={linkInputs[host.id] ?? ''}
                          onChange={(e) => setLinkInputs((s) => ({ ...s, [host.id]: e.target.value }))}
                        />
                        <Button size="sm" variant="outline" disabled={linkAgent.isPending || !(linkInputs[host.id] ?? '').trim()}
                          onClick={() => linkAgent.mutate({ hostId: host.id, agentId: (linkInputs[host.id] ?? '').trim() })}>
                          <Link2 className="h-3.5 w-3.5 mr-1" /> Link
                        </Button>
                      </div>
                    )}
                    <p className="text-[11px] text-muted-foreground">
                      {bound
                        ? 'The agent runs the host-prep report on a schedule and posts the catalog automatically.'
                        : 'Link the enrolled agent on this host for automatic sync, or use “Import from host” to paste once.'}
                    </p>
                  </CardContent>
                </Card>
              )
            })}
          </div>
        </div>
      )}

      {/* Add/edit app dialog */}
      <Dialog open={showAppDialog} onOpenChange={setShowAppDialog}>
        <DialogContent className="max-w-lg">
          <DialogHeader><DialogTitle>{editingId ? 'Edit app' : 'Add Windows app'}</DialogTitle></DialogHeader>
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-sm font-medium">Display name</label>
                <Input value={form.display_name} onChange={(e) => setForm((f) => ({ ...f, display_name: e.target.value }))} placeholder="SQL Server Management Studio" />
              </div>
              <div>
                <label className="text-sm font-medium">Program alias</label>
                <Input value={form.alias} onChange={(e) => setForm((f) => ({ ...f, alias: e.target.value }))} placeholder="SSMS" />
                <p className="text-xs text-muted-foreground mt-0.5">Must match the TSAppAllowList alias on the host.</p>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-sm font-medium">Host</label>
                <Select
                  value={form.pool_id ? `pool:${form.pool_id}` : (form.host_entry_id ? `host:${form.host_entry_id}` : '')}
                  onValueChange={(v) => {
                    if (v.startsWith('pool:')) setForm((f) => ({ ...f, pool_id: v.slice(5), host_entry_id: '' }))
                    else setForm((f) => ({ ...f, host_entry_id: v.slice(5), pool_id: '' }))
                  }}
                >
                  <SelectTrigger><SelectValue placeholder="Choose a host or pool" /></SelectTrigger>
                  <SelectContent>
                    {pools.map((p) => (
                      <SelectItem key={p.id} value={`pool:${p.id}`}>Pool: {p.name}</SelectItem>
                    ))}
                    {hostEntries.map((e) => (
                      <SelectItem key={e.id} value={`host:${e.id}`}>{e.name}{e.hostname ? ` (${e.hostname})` : ''}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <label className="text-sm font-medium">Working directory (optional)</label>
                <Input value={form.working_dir ?? ''} onChange={(e) => setForm((f) => ({ ...f, working_dir: e.target.value }))} placeholder="C:\Users\Public" />
              </div>
            </div>

            <div>
              <label className="text-sm font-medium">Command-line arguments (optional)</label>
              <Input
                value={form.args ?? ''}
                onChange={(e) => setForm((f) => ({ ...f, args: e.target.value }))}
                placeholder="-S sql01.corp.local -E"
                aria-invalid={remoteAppArgsLookSecret(form.args)}
                className={remoteAppArgsLookSecret(form.args) ? 'border-destructive' : undefined}
              />
              {remoteAppArgsLookSecret(form.args) && (
                <p className="mt-1 flex items-start gap-1.5 text-xs text-destructive">
                  <AlertTriangle className="h-3.5 w-3.5 shrink-0 mt-px" />
                  <span>{REMOTE_APP_SECRET_HINT}</span>
                </p>
              )}
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowAppDialog(false)}>Cancel</Button>
            <Button
              onClick={() => saveApp.mutate()}
              disabled={saveApp.isPending || !form.display_name || !form.alias
                || (!form.host_entry_id && !form.pool_id) || remoteAppArgsLookSecret(form.args)}
            >
              {editingId ? 'Save' : 'Add'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Import-from-host dialog (paste the host prep / discovery JSON) */}
      <Dialog open={showImport} onOpenChange={setShowImport}>
        <DialogContent className="max-w-lg">
          <DialogHeader><DialogTitle>Import apps from a host</DialogTitle></DialogHeader>
          <div className="space-y-3">
            <p className="text-sm text-muted-foreground">
              Run <code>Prepare-OpenIDXAppHost.ps1 -Report</code> on the host and paste its JSON
              output. Published apps (in TSAppAllowList) import as verified; installed-but-unpublished
              apps import for reference.
            </p>
            <div>
              <label className="text-sm font-medium">Host</label>
              <Select value={importHost} onValueChange={setImportHost}>
                <SelectTrigger><SelectValue placeholder="Choose the host this report is from" /></SelectTrigger>
                <SelectContent>
                  {hostEntries.map((e) => (
                    <SelectItem key={e.id} value={e.id}>{e.name}{e.hostname ? ` (${e.hostname})` : ''}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <Textarea rows={8} value={importData} onChange={(e) => setImportData(e.target.value)} placeholder='{"host": {...}, "apps": [...]}' />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowImport(false)}>Cancel</Button>
            <Button onClick={() => importDiscovery.mutate()} disabled={importDiscovery.isPending || !importHost || !importData.trim()}>
              Import
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete confirm */}
      <AlertDialog open={!!deleteApp} onOpenChange={(o) => { if (!o) setDeleteApp(null) }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Remove “{deleteApp?.display_name}”?</AlertDialogTitle>
            <AlertDialogDescription>
              This removes the app from the OpenIDX catalog. It does not unpublish it on the Windows host.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={() => deleteApp && removeApp.mutate(deleteApp.id)}>Remove</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Placement conflict — explicit, never a silent disconnect */}
      <ConflictDialog
        conflict={conflict}
        launching={launch.isPending}
        onCancel={() => setConflict(null)}
        onReplace={(sessionId) => conflict && launch.mutate({ app: conflict.app, replaceSessionId: sessionId })}
      />
    </div>
  )
}

// AppCard — one published app tile. Verified state and launchability are the
// two things an admin needs to see at a glance.
function AppCard({ app, launching, onLaunch, onEdit, onDelete }: {
  app: WindowsApp
  launching: boolean
  onLaunch: () => void
  onEdit: () => void
  onDelete: () => void
}) {
  const launchable = app.status === 'active'
  return (
    <Card className="hover:border-primary/40 transition-colors">
      <CardContent className="py-4 space-y-3">
        <div className="flex items-start gap-3">
          {app.has_icon ? (
            <img src={api.windowsApps.iconURL(app.id)} alt="" className="h-8 w-8 rounded shrink-0" />
          ) : (
            <div className="h-8 w-8 rounded bg-muted flex items-center justify-center shrink-0">
              <AppWindow className="h-4 w-4 text-muted-foreground" />
            </div>
          )}
          <div className="min-w-0 flex-1">
            <p className="font-medium truncate">{app.display_name}</p>
            <p className="text-xs text-muted-foreground truncate">
              {app.pool_name ? `Pool: ${app.pool_name}` : app.host_name} · {app.alias}
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          {app.verified ? (
            <Badge variant="outline" className="text-emerald-700 border-emerald-300" title="Alias found in the host's TSAppAllowList — published and launchable">
              <ShieldCheck className="h-3 w-3 mr-1" /> published
            </Badge>
          ) : (
            <Badge variant="outline" className="text-amber-700 border-amber-300" title="Installed but not confirmed in TSAppAllowList — may fail to launch until published">
              <HelpCircle className="h-3 w-3 mr-1" /> unverified
            </Badge>
          )}
          {app.status === 'inconsistent' && (
            <Badge variant="outline" className="text-destructive border-destructive" title="Pool members disagree on what this alias resolves to — launch blocked to avoid starting the wrong app">
              <AlertTriangle className="h-3 w-3 mr-1" /> inconsistent
            </Badge>
          )}
          {app.record_session && <Badge variant="outline">rec</Badge>}
          {app.require_approval && <Badge variant="outline">approval</Badge>}
        </div>

        <div className="flex items-center gap-1">
          <Button size="sm" className="flex-1" onClick={onLaunch} disabled={!launchable || launching}>
            <Play className="h-4 w-4 mr-1" /> Launch
          </Button>
          <Button size="sm" variant="ghost" onClick={onEdit} title="Edit"><Pencil className="h-4 w-4" /></Button>
          <Button size="sm" variant="ghost" onClick={onDelete} title="Remove"><Trash2 className="h-4 w-4 text-destructive" /></Button>
        </div>
      </CardContent>
    </Card>
  )
}

// ConflictDialog — the GUACAMOLE-1951 placement contract, made human. When no
// host has capacity (or launching would kill the user's own session), we show
// what is in the way and let the user explicitly free a slot.
function ConflictDialog({ conflict, launching, onCancel, onReplace }: {
  conflict: Conflict | null
  launching: boolean
  onCancel: () => void
  onReplace: (sessionId: string) => void
}) {
  return (
    <Dialog open={!!conflict} onOpenChange={(o) => { if (!o) onCancel() }}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-amber-500" />
            {conflict?.body.reason === 'no_capacity' ? 'No free host' : 'You have an active session'}
          </DialogTitle>
        </DialogHeader>
        {conflict && (
          <div className="space-y-3">
            <p className="text-sm text-muted-foreground">{conflict.body.message}</p>
            <div className="space-y-2">
              {conflict.body.conflicts.map((c) => (
                <div key={c.session_id} className="flex items-center justify-between rounded-md border p-2 text-sm">
                  <div className="min-w-0">
                    <p className="font-medium flex items-center gap-1.5 truncate">
                      <Server className="h-3.5 w-3.5 shrink-0" /> {c.host_name}
                    </p>
                    <p className="text-xs text-muted-foreground truncate">
                      {c.app_name ? `${c.app_name} · ` : ''}since {new Date(c.started_at).toLocaleTimeString()}
                    </p>
                  </div>
                  <Button size="sm" variant="outline" disabled={launching} onClick={() => onReplace(c.session_id)}>
                    Disconnect &amp; launch here
                  </Button>
                </div>
              ))}
            </div>
            <p className="flex items-start gap-1.5 text-xs text-muted-foreground">
              <CheckCircle2 className="h-3.5 w-3.5 shrink-0 mt-px" />
              Nothing is disconnected unless you choose a session above.
            </p>
          </div>
        )}
        <DialogFooter>
          <Button variant="outline" onClick={onCancel}>Cancel</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
