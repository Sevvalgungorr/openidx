import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { AppWindow, Play, Layers, Server, AlertTriangle, CheckCircle2, ShieldCheck } from 'lucide-react'
import { Card, CardContent } from '../components/ui/card'
import { Button } from '../components/ui/button'
import { Badge } from '../components/ui/badge'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from '../components/ui/dialog'
import { api, MyWindowsApp, WindowsAppLaunchConflict } from '../lib/api'
import { useToast } from '../hooks/use-toast'
import { isAxiosError } from 'axios'

// A launch conflict the user must resolve (server replied 409).
type Conflict = { app: MyWindowsApp; body: WindowsAppLaunchConflict }

// MyWindowsAppsPage — the end-user portal surface: the Windows apps this user
// may launch, as tiles. Distinct from the admin catalog page: no editing, no
// hosts/pools internals — just launch. Launching runs the same placement +
// approval gates server-side, and a placement conflict opens the same explicit
// "disconnect & launch here" resolution the admin page uses.
export function MyWindowsAppsPage() {
  const { toast } = useToast()
  const [conflict, setConflict] = useState<Conflict | null>(null)

  const { data, isLoading } = useQuery({
    queryKey: ['my-windows-apps'],
    queryFn: () => api.windowsApps.listMine(),
  })
  const apps = data?.apps ?? []

  const launch = useMutation({
    mutationFn: (v: { app: MyWindowsApp; replaceSessionId?: string }) =>
      api.windowsApps.launch(v.app.id, v.replaceSessionId),
    onSuccess: (r) => {
      setConflict(null)
      window.open(r.connect_url, '_blank', 'noopener')
      toast({ title: 'Launching', description: `${r.host_name} — session ${r.recorded ? 'recorded' : 'live'}` })
    },
    onError: (e: unknown, v) => {
      if (isAxiosError(e) && e.response?.status === 409 && e.response.data) {
        setConflict({ app: v.app, body: e.response.data as WindowsAppLaunchConflict })
        return
      }
      toast({ title: 'Launch failed', description: (e as Error).message, variant: 'destructive' })
    },
  })

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <AppWindow className="h-6 w-6" /> My Apps
        </h1>
        <p className="text-muted-foreground">
          Windows applications published to you. Launch one in your browser — no install, no full desktop.
        </p>
      </div>

      {isLoading ? (
        <div className="flex justify-center py-12"><LoadingSpinner /></div>
      ) : apps.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center space-y-2">
            <AppWindow className="h-10 w-10 mx-auto text-muted-foreground" />
            <p className="font-medium">No apps available</p>
            <p className="text-sm text-muted-foreground">
              An administrator hasn't published any Windows apps to your account yet.
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {apps.map((app) => (
            <Card key={app.id} className="hover:border-primary/40 transition-colors">
              <CardContent className="py-4 space-y-3">
                <div className="flex items-start gap-3">
                  {app.has_icon ? (
                    <img src={api.windowsApps.iconURL(app.id)} alt="" className="h-9 w-9 rounded shrink-0" />
                  ) : (
                    <div className="h-9 w-9 rounded bg-muted flex items-center justify-center shrink-0">
                      <AppWindow className="h-5 w-5 text-muted-foreground" />
                    </div>
                  )}
                  <div className="min-w-0 flex-1">
                    <p className="font-medium truncate">{app.display_name}</p>
                    <p className="text-xs text-muted-foreground truncate flex items-center gap-1">
                      {app.pool_name ? <Layers className="h-3 w-3" /> : <Server className="h-3 w-3" />}
                      {app.pool_name || app.host_name}
                    </p>
                  </div>
                </div>
                {app.require_approval && (
                  <Badge variant="outline" className="text-amber-700 border-amber-300">
                    <ShieldCheck className="h-3 w-3 mr-1" /> needs approval
                  </Badge>
                )}
                <Button className="w-full" onClick={() => launch.mutate({ app })} disabled={launch.isPending}>
                  <Play className="h-4 w-4 mr-1" /> Launch
                </Button>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Placement conflict — explicit, never a silent disconnect. Mirrors the
          admin page's contract so a user is never surprised by a killed session. */}
      <Dialog open={!!conflict} onOpenChange={(o) => { if (!o) setConflict(null) }}>
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
                    <Button
                      size="sm" variant="outline" disabled={launch.isPending}
                      onClick={() => conflict && launch.mutate({ app: conflict.app, replaceSessionId: c.session_id })}
                    >
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
            <Button variant="outline" onClick={() => setConflict(null)}>Cancel</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
