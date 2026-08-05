import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { FileText, Download, Clock, Trash2, Pencil } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Badge } from '../components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table'
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '../components/ui/dialog'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

interface ReportExport {
  id: string
  name: string
  report_type: string
  framework: string
  format: string
  status: string
  file_size: number
  row_count: number
  error_message: string
  generated_by: string
  created_at: string
  completed_at?: string
}

interface ScheduledReport {
  id: string
  name: string
  description: string
  report_type: string
  framework: string
  schedule: string
  format: string
  enabled: boolean
  last_run_at?: string
  next_run_at?: string
  created_at: string
}

export function ReportsPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [tab, setTab] = useState<'exports' | 'scheduled'>('exports')
  const [generateOpen, setGenerateOpen] = useState(false)
  const [scheduleOpen, setScheduleOpen] = useState(false)
  const [editSchedule, setEditSchedule] = useState<ScheduledReport | null>(null)

  const [genForm, setGenForm] = useState({ report_type: 'user_access', framework: '', format: 'csv' })
  const [schedForm, setSchedForm] = useState({ name: '', report_type: 'user_access', framework: '', schedule: '0 0 * * 1', format: 'csv', enabled: true })

  const { data: exportsData, isLoading: exportsLoading } = useQuery({
    queryKey: ['report-exports'],
    queryFn: () => api.get<{ exports: ReportExport[]; total: number }>('/api/v1/audit/reports/exports'),
    refetchInterval: 5000,
  })
  const exports = exportsData?.exports || []

  const { data: scheduledData, isLoading: scheduledLoading } = useQuery({
    queryKey: ['scheduled-reports'],
    queryFn: () => api.get<{ reports: ScheduledReport[] }>('/api/v1/audit/reports/scheduled'),
  })
  const scheduled = scheduledData?.reports || []

  const generateMutation = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.post('/api/v1/audit/reports/generate', body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['report-exports'] })
      toast({ title: 'Report generation started' })
      setGenerateOpen(false)
    },
    onError: () => toast({ title: 'Failed to generate report', variant: 'destructive' }),
  })

  // Download an export through the authenticated api client (blob), not a bare
  // window.open — the download endpoint requires the Authorization header, so a
  // plain URL opened in a new tab returned {"error":"missing authorization
  // header"} instead of the file. Fetch the bytes with the bearer token, then
  // save via a temporary object-URL anchor.
  const downloadMutation = useMutation({
    mutationFn: async (exp: ReportExport) => {
      const blob = await api.get<Blob>(
        `/api/v1/audit/reports/exports/${exp.id}/download`,
        { responseType: 'blob' },
      )
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      const ext = (exp.format || 'csv').toLowerCase()
      const safeName = (exp.name || 'report').replace(/[^\w.-]+/g, '_')
      a.download = safeName.endsWith(`.${ext}`) ? safeName : `${safeName}.${ext}`
      document.body.appendChild(a)
      a.click()
      a.remove()
      // Revoke on the next tick so the click has consumed the URL.
      setTimeout(() => URL.revokeObjectURL(url), 1000)
    },
    onError: () => toast({ title: 'Download failed', variant: 'destructive' }),
  })

  const createScheduleMutation = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.post('/api/v1/audit/reports/scheduled', body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scheduled-reports'] })
      toast({ title: editSchedule ? 'Schedule updated' : 'Schedule created' })
      setScheduleOpen(false)
    },
    onError: () => toast({ title: 'Failed to save schedule', variant: 'destructive' }),
  })

  const updateScheduleMutation = useMutation({
    mutationFn: ({ id, body }: { id: string; body: Record<string, unknown> }) =>
      api.put(`/api/v1/audit/reports/scheduled/${id}`, body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scheduled-reports'] })
      toast({ title: 'Schedule updated' })
      setScheduleOpen(false)
    },
  })

  const deleteScheduleMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/audit/reports/scheduled/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scheduled-reports'] })
      toast({ title: 'Schedule deleted' })
    },
  })

  const openGenerate = () => {
    setGenForm({ report_type: 'user_access', framework: '', format: 'csv' })
    setGenerateOpen(true)
  }

  const openSchedule = (s?: ScheduledReport) => {
    setEditSchedule(s || null)
    setSchedForm(s ? { name: s.name, report_type: s.report_type, framework: s.framework, schedule: s.schedule, format: s.format, enabled: s.enabled } :
      { name: '', report_type: 'user_access', framework: '', schedule: '0 0 * * 1', format: 'csv', enabled: true })
    setScheduleOpen(true)
  }

  const handleSaveSchedule = () => {
    if (editSchedule) {
      updateScheduleMutation.mutate({ id: editSchedule.id, body: schedForm })
    } else {
      createScheduleMutation.mutate(schedForm)
    }
  }

  const formatSize = (bytes: number) => {
    if (!bytes) return '-'
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  }

  const statusColor = (s: string) => {
    switch (s) {
      case 'completed': return 'default'
      case 'generating': return 'secondary'
      case 'failed': return 'destructive'
      default: return 'outline'
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Reports & Exports</h1>
          <p className="text-muted-foreground">Generate, download, and schedule reports</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => openSchedule()}><Clock className="mr-2 h-4 w-4" />Schedule Report</Button>
          <Button onClick={openGenerate}><FileText className="mr-2 h-4 w-4" />Generate Report</Button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 border-b pb-2">
        <Button variant={tab === 'exports' ? 'default' : 'ghost'} size="sm" onClick={() => setTab('exports')}>Report History</Button>
        <Button variant={tab === 'scheduled' ? 'default' : 'ghost'} size="sm" onClick={() => setTab('scheduled')}>Scheduled Reports</Button>
      </div>

      {tab === 'exports' && (
        <Card>
          <CardHeader><CardTitle>Generated Reports</CardTitle></CardHeader>
          <CardContent>
            {exportsLoading ? <p className="text-center py-8 text-muted-foreground">Loading...</p> :
             exports.length === 0 ? <p className="text-center py-8 text-muted-foreground">No reports generated yet</p> : (
              <Table>
                <TableHeader><TableRow>
                  <TableHead>Name</TableHead><TableHead>Type</TableHead><TableHead>Format</TableHead>
                  <TableHead>Status</TableHead><TableHead>Size</TableHead><TableHead>Rows</TableHead>
                  <TableHead>Created</TableHead><TableHead>Actions</TableHead>
                </TableRow></TableHeader>
                <TableBody>
                  {exports.map(exp => (
                    <TableRow key={exp.id}>
                      <TableCell className="font-medium">{exp.name}</TableCell>
                      <TableCell><Badge variant="outline">{exp.report_type}</Badge></TableCell>
                      <TableCell>{exp.format.toUpperCase()}</TableCell>
                      <TableCell><Badge variant={statusColor(exp.status) as 'default' | 'secondary' | 'destructive' | 'outline'}>{exp.status}</Badge></TableCell>
                      <TableCell>{formatSize(exp.file_size)}</TableCell>
                      <TableCell>{exp.row_count || '-'}</TableCell>
                      <TableCell>{new Date(exp.created_at).toLocaleString()}</TableCell>
                      <TableCell>
                        {exp.status === 'completed' && (
                          <Button size="sm" variant="ghost" disabled={downloadMutation.isPending} onClick={() => downloadMutation.mutate(exp)}>
                            <Download className="h-4 w-4" />
                          </Button>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      )}

      {tab === 'scheduled' && (
        <Card>
          <CardHeader><CardTitle>Scheduled Reports</CardTitle></CardHeader>
          <CardContent>
            {scheduledLoading ? <p className="text-center py-8 text-muted-foreground">Loading...</p> :
             scheduled.length === 0 ? <p className="text-center py-8 text-muted-foreground">No scheduled reports</p> : (
              <Table>
                <TableHeader><TableRow>
                  <TableHead>Name</TableHead><TableHead>Type</TableHead><TableHead>Schedule</TableHead>
                  <TableHead>Format</TableHead><TableHead>Status</TableHead><TableHead>Last Run</TableHead><TableHead>Actions</TableHead>
                </TableRow></TableHeader>
                <TableBody>
                  {scheduled.map(s => (
                    <TableRow key={s.id}>
                      <TableCell className="font-medium">{s.name}</TableCell>
                      <TableCell><Badge variant="outline">{s.report_type}</Badge></TableCell>
                      <TableCell className="font-mono text-sm">{s.schedule}</TableCell>
                      <TableCell>{s.format.toUpperCase()}</TableCell>
                      <TableCell><Badge variant={s.enabled ? 'default' : 'secondary'}>{s.enabled ? 'Active' : 'Disabled'}</Badge></TableCell>
                      <TableCell>{s.last_run_at ? new Date(s.last_run_at).toLocaleString() : 'Never'}</TableCell>
                      <TableCell>
                        <div className="flex gap-1">
                          <Button variant="ghost" size="sm" onClick={() => openSchedule(s)}><Pencil className="h-4 w-4" /></Button>
                          <Button variant="ghost" size="sm" onClick={() => deleteScheduleMutation.mutate(s.id)}><Trash2 className="h-4 w-4 text-red-500" /></Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      )}

      {/* Generate Report Dialog */}
      <Dialog open={generateOpen} onOpenChange={setGenerateOpen}>
        <DialogContent>
          <DialogHeader><DialogTitle>Generate Report</DialogTitle></DialogHeader>
          <div className="space-y-4">
            <div>
              <label className="text-sm font-medium">Report Type</label>
              <Select value={genForm.report_type} onValueChange={v => setGenForm(f => ({ ...f, report_type: v }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="user_access">User Access</SelectItem>
                  <SelectItem value="compliance">Compliance</SelectItem>
                  <SelectItem value="entitlement">Entitlement</SelectItem>
                  <SelectItem value="activity">Activity</SelectItem>
                </SelectContent>
              </Select>
            </div>
            {genForm.report_type === 'compliance' && (
              <div>
                <label className="text-sm font-medium">Framework</label>
                <Select value={genForm.framework} onValueChange={v => setGenForm(f => ({ ...f, framework: v }))}>
                  <SelectTrigger><SelectValue placeholder="Select framework" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="SOC2">SOC 2</SelectItem>
                    <SelectItem value="ISO27001">ISO 27001</SelectItem>
                    <SelectItem value="HIPAA">HIPAA</SelectItem>
                    <SelectItem value="PCI-DSS">PCI-DSS</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            )}
            <div>
              <label className="text-sm font-medium">Format</label>
              <Select value={genForm.format} onValueChange={v => setGenForm(f => ({ ...f, format: v }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="csv">CSV</SelectItem>
                  <SelectItem value="json">JSON</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setGenerateOpen(false)}>Cancel</Button>
            <Button onClick={() => generateMutation.mutate(genForm)} disabled={generateMutation.isPending}>Generate</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Schedule Report Dialog */}
      <Dialog open={scheduleOpen} onOpenChange={setScheduleOpen}>
        <DialogContent>
          <DialogHeader><DialogTitle>{editSchedule ? 'Edit Schedule' : 'Create Scheduled Report'}</DialogTitle></DialogHeader>
          <div className="space-y-4">
            <div>
              <label className="text-sm font-medium">Name</label>
              <Input value={schedForm.name} onChange={e => setSchedForm(f => ({ ...f, name: e.target.value }))} placeholder="Weekly User Access Report" />
            </div>
            <div>
              <label className="text-sm font-medium">Report Type</label>
              <Select value={schedForm.report_type} onValueChange={v => setSchedForm(f => ({ ...f, report_type: v }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="user_access">User Access</SelectItem>
                  <SelectItem value="compliance">Compliance</SelectItem>
                  <SelectItem value="entitlement">Entitlement</SelectItem>
                  <SelectItem value="activity">Activity</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <label className="text-sm font-medium">Cron Schedule</label>
              <Input value={schedForm.schedule} onChange={e => setSchedForm(f => ({ ...f, schedule: e.target.value }))} placeholder="0 0 * * 1" />
              <p className="text-xs text-muted-foreground mt-1">Cron format: minute hour day month weekday</p>
            </div>
            <div>
              <label className="text-sm font-medium">Format</label>
              <Select value={schedForm.format} onValueChange={v => setSchedForm(f => ({ ...f, format: v }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="csv">CSV</SelectItem>
                  <SelectItem value="json">JSON</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" checked={schedForm.enabled} onChange={e => setSchedForm(f => ({ ...f, enabled: e.target.checked }))} />
              Enabled
            </label>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setScheduleOpen(false)}>Cancel</Button>
            <Button disabled={!schedForm.name} onClick={handleSaveSchedule}>
              {editSchedule ? 'Update' : 'Create'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
