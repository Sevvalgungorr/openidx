import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { RefreshCw, ShieldAlert, Power, Activity } from 'lucide-react'
import { Button } from './ui/button'
import { Badge } from './ui/badge'
import { Input } from './ui/input'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table'
import {
  AlertDialog,
  AlertDialogContent,
  AlertDialogHeader,
  AlertDialogFooter,
  AlertDialogTitle,
  AlertDialogDescription,
  AlertDialogAction,
  AlertDialogCancel,
} from './ui/alert-dialog'
import { useToast } from '../hooks/use-toast'
import { QueryError } from './query-error'
import { api, SelfHealMode, SelfHealFinding } from '../lib/api'

const MODES: SelfHealMode[] = ['off', 'observe', 'tier0', 'tier1']

const MODE_HELP: Record<SelfHealMode, string> = {
  off: 'Detect nothing, take no action.',
  observe: 'Detect + record + report. No mutation. (safe default)',
  tier0: 'Auto-remediate ops issues (restart unit / nginx) inside the safety envelope.',
  tier1: 'Also allow autonomous code-fix (canary + rollback). Highest risk.',
}

function sevClass(s: string): string {
  switch (s) {
    case 'crit':
    case 'critical':
    case 'high':
      return 'bg-red-100 text-red-800 border-red-200'
    case 'warn':
    case 'warning':
      return 'bg-yellow-100 text-yellow-800 border-yellow-200'
    default:
      return 'bg-blue-100 text-blue-800 border-blue-200'
  }
}

// The self-heal control panel. Admin-only; mutations require selfheal:manage
// server-side. Reflects and drives the on-disk MODE/DISABLE the loop honors.
export function SelfHealPanel() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [tier1Open, setTier1Open] = useState(false)
  const [tier1Text, setTier1Text] = useState('')
  const [killOpen, setKillOpen] = useState(false)

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['selfheal-status'] })
    queryClient.invalidateQueries({ queryKey: ['selfheal-findings'] })
    queryClient.invalidateQueries({ queryKey: ['selfheal-history'] })
  }

  const status = useQuery({ queryKey: ['selfheal-status'], queryFn: () => api.selfheal.status(), refetchInterval: 30_000 })
  const findings = useQuery({ queryKey: ['selfheal-findings'], queryFn: () => api.selfheal.findings() })
  const history = useQuery({ queryKey: ['selfheal-history'], queryFn: () => api.selfheal.history(25) })

  const setMode = useMutation({
    mutationFn: ({ mode, confirm }: { mode: SelfHealMode; confirm?: string }) => api.selfheal.setMode(mode, confirm),
    onSuccess: (_d, v) => {
      toast({ title: `Mode → ${v.mode}`, variant: 'success' })
      invalidate()
    },
    onError: (e: Error) => toast({ title: 'Mode change failed', description: e.message, variant: 'destructive' }),
  })

  const killSwitch = useMutation({
    mutationFn: (enabled: boolean) => api.selfheal.killSwitch(enabled),
    onSuccess: (_d, enabled) => {
      toast({ title: enabled ? 'Kill-switch ENGAGED — all autonomy halted' : 'Kill-switch released', variant: enabled ? 'destructive' : 'success' })
      invalidate()
    },
    onError: (e: Error) => toast({ title: 'Kill-switch failed', description: e.message, variant: 'destructive' }),
  })

  const sweep = useMutation({
    mutationFn: () => api.selfheal.sweep(),
    onSuccess: () => {
      toast({ title: 'Sweep complete', variant: 'success' })
      invalidate()
    },
    onError: (e: Error) => toast({ title: 'Sweep failed', description: e.message, variant: 'destructive' }),
  })

  if (status.isError) return <QueryError error={status.error} resource="self-heal status" />

  const s = status.data
  const mode = s?.mode ?? 'observe'
  const killed = s?.kill_switch ?? false
  const rows: SelfHealFinding[] = findings.data?.findings ?? []

  const pickMode = (m: SelfHealMode) => {
    if (m === mode) return
    if (m === 'tier1') {
      setTier1Text('')
      setTier1Open(true)
      return
    }
    setMode.mutate({ mode: m })
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-lg font-semibold flex items-center gap-2">
            <Activity className="h-5 w-5" /> Self-Heal Loop
          </h3>
          <p className="text-sm text-muted-foreground">
            Automated detection + remediation. {s?.stale && <span className="text-yellow-600">(no snapshot yet — run a sweep)</span>}
          </p>
        </div>
        <Button variant="outline" onClick={() => sweep.mutate()} disabled={sweep.isPending}>
          <RefreshCw className={`mr-2 h-4 w-4 ${sweep.isPending ? 'animate-spin' : ''}`} />
          {sweep.isPending ? 'Sweeping…' : 'Sweep now'}
        </Button>
      </div>

      {/* Controls */}
      <Card className={killed ? 'border-red-300' : ''}>
        <CardHeader className="pb-3">
          <CardTitle className="text-base flex items-center justify-between">
            <span>Autonomy mode</span>
            {killed && <Badge className="bg-red-100 text-red-800 border-red-200">KILL-SWITCH ENGAGED</Badge>}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-wrap gap-2">
            {MODES.map(m => (
              <Button
                key={m}
                size="sm"
                variant={m === mode ? 'default' : 'outline'}
                disabled={setMode.isPending || killed}
                onClick={() => pickMode(m)}
              >
                {m}
              </Button>
            ))}
          </div>
          <p className="text-xs text-muted-foreground">{MODE_HELP[mode]}</p>

          <div className="flex items-center justify-between border-t pt-3">
            <div className="flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-red-500" />
              <span className="text-sm font-medium">Kill-switch</span>
              <span className="text-xs text-muted-foreground">halts ALL autonomy immediately</span>
            </div>
            {killed ? (
              <Button size="sm" variant="outline" disabled={killSwitch.isPending} onClick={() => killSwitch.mutate(false)}>
                <Power className="mr-1.5 h-3.5 w-3.5" /> Release
              </Button>
            ) : (
              <Button size="sm" variant="destructive" disabled={killSwitch.isPending} onClick={() => setKillOpen(true)}>
                <Power className="mr-1.5 h-3.5 w-3.5" /> Engage
              </Button>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Findings */}
      <div className="mt-6">
        <h4 className="font-semibold mb-2">Findings ({rows.length})</h4>
        {findings.isError ? (
          <QueryError error={findings.error} resource="findings" />
        ) : rows.length === 0 ? (
          <Card><CardContent className="py-6 text-center text-sm text-muted-foreground">No open findings.</CardContent></Card>
        ) : (
          <Card>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Severity</TableHead>
                  <TableHead>Class</TableHead>
                  <TableHead>Service</TableHead>
                  <TableHead>Message</TableHead>
                  <TableHead className="text-right">Count</TableHead>
                  <TableHead>Last seen</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map(f => (
                  <TableRow key={f.fingerprint}>
                    <TableCell>
                      <span className={`text-xs font-medium px-2 py-0.5 rounded-full border ${sevClass(f.severity)}`}>{f.severity}</span>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1">
                        <Badge variant="outline">{f.class}</Badge>
                        {f.class === 'security' && <span className="text-[10px] text-muted-foreground">no auto-action</span>}
                      </div>
                    </TableCell>
                    <TableCell className="font-mono text-xs">{f.service}</TableCell>
                    <TableCell className="max-w-md truncate" title={f.message}>{f.message}</TableCell>
                    <TableCell className="text-right">{f.count ?? 1}</TableCell>
                    <TableCell className="text-xs">{f.last_seen}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Card>
        )}
      </div>

      {/* Remediation history */}
      <div className="mt-6">
        <h4 className="font-semibold mb-2">Recent remediations</h4>
        {(history.data?.actions ?? []).length === 0 ? (
          <p className="text-sm text-muted-foreground">No remediation actions recorded.</p>
        ) : (
          <div className="space-y-1">
            {(history.data?.actions ?? []).map((a, i) => (
              <div key={`${a.ts}-${i}`} className="flex items-center gap-3 text-xs border-b py-1">
                <span className="text-muted-foreground w-40 shrink-0">{a.ts}</span>
                <Badge variant="outline">{a.action}</Badge>
                <span className={a.result === 'recovered' ? 'text-green-600' : a.result === 'still-bad' || a.result === 'escalated' ? 'text-red-600' : 'text-muted-foreground'}>{a.result}</span>
                <code className="text-[10px] bg-muted px-1 rounded truncate">{a.fingerprint}</code>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* tier1 typed-confirm */}
      <AlertDialog open={tier1Open} onOpenChange={setTier1Open}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Enable tier1 (autonomous code-fix)?</AlertDialogTitle>
            <AlertDialogDescription>
              tier1 lets the loop change code and deploy behind a canary + rollback. This is the highest-risk mode.
              Type <strong>tier1</strong> to confirm.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <Input value={tier1Text} onChange={e => setTier1Text(e.target.value)} placeholder="tier1" autoFocus />
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              disabled={tier1Text !== 'tier1'}
              onClick={() => {
                setMode.mutate({ mode: 'tier1', confirm: 'tier1' })
                setTier1Open(false)
              }}
            >
              Enable tier1
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* kill-switch confirm */}
      <AlertDialog open={killOpen} onOpenChange={setKillOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Engage kill-switch?</AlertDialogTitle>
            <AlertDialogDescription>
              This halts ALL self-heal autonomy immediately (no remediation until released). Use in an incident.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                killSwitch.mutate(true)
                setKillOpen(false)
              }}
            >
              Engage
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
