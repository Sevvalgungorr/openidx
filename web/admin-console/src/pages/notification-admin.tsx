import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Bell, Plus, Trash2, Send, BarChart3, Route, Megaphone, Edit } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../components/ui/table'
import { Button } from '../components/ui/button'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'
import { ConfirmAction } from '../components/confirm-action'

// ── Interfaces ──────────────────────────────────────────────────────────────

interface RoutingRule {
  id: string
  name: string
  event_type: string
  conditions: Record<string, unknown>
  channels: string[]
  template_overrides: Record<string, unknown>
  priority: number
  enabled: boolean
}

interface Broadcast {
  id: string
  title: string
  body: string
  channel: string
  target_type: string
  target_ids: string[]
  priority: string
  scheduled_at: string
  sent_at: string
  status: string
  total_recipients: number
  delivered_count: number
  read_count: number
}

interface NotificationStats {
  total_sent: number
  total_read: number
  total_unread: number
  channel_breakdown: Record<string, number>
  routing_rules_count: number
}

type AdminTab = 'routing' | 'broadcasts' | 'stats'

const CHANNELS = ['in_app', 'email', 'sms', 'push']

const statusBadgeClass = (status: string) => {
  const map: Record<string, string> = {
    draft: 'bg-muted text-foreground',
    scheduled: 'bg-yellow-100 text-yellow-800',
    sent: 'bg-green-100 text-green-800',
  }
  return map[status] || 'bg-muted text-foreground'
}

// ── Component ───────────────────────────────────────────────────────────────

export function NotificationAdminPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [activeTab, setActiveTab] = useState<AdminTab>('routing')

  // ── Routing Rules State ─────────────────────────────────────────────────
  const [showRuleForm, setShowRuleForm] = useState(false)
  const [editingRule, setEditingRule] = useState<RoutingRule | null>(null)
  const [ruleForm, setRuleForm] = useState({
    name: '',
    event_type: '',
    channels: [] as string[],
    priority: 0,
  })

  // ── Broadcasts State ────────────────────────────────────────────────────
  const [showBroadcastForm, setShowBroadcastForm] = useState(false)
  const [broadcastForm, setBroadcastForm] = useState({
    title: '',
    body: '',
    channel: 'in_app',
    target_type: 'all',
    target_ids: '',
    priority: 'normal',
  })

  // ── Queries ─────────────────────────────────────────────────────────────

  const { data: rulesData, isLoading: rulesLoading, isError: rulesIsError, error: rulesError } = useQuery({
    queryKey: ['routing-rules'],
    queryFn: () => api.get<{ data: RoutingRule[] }>('/api/v1/notifications/routing-rules'),
  })
  const rules = rulesData?.data || []

  const { data: broadcastsData, isLoading: broadcastsLoading, isError: broadcastsIsError, error: broadcastsError } = useQuery({
    queryKey: ['broadcasts'],
    queryFn: () => api.get<{ data: Broadcast[] }>('/api/v1/notifications/broadcasts'),
  })
  const broadcasts = broadcastsData?.data || []

  const { data: statsData, isLoading: statsLoading, isError: statsIsError, error: statsError } = useQuery({
    queryKey: ['notification-stats'],
    queryFn: () => api.get<NotificationStats>('/api/v1/notifications/stats'),
  })

  // ── Routing Rules Mutations ─────────────────────────────────────────────

  const createRuleMutation = useMutation({
    mutationFn: (data: typeof ruleForm) =>
      api.post('/api/v1/notifications/routing-rules', {
        ...data,
        conditions: {},
        template_overrides: {},
        enabled: true,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['routing-rules'] })
      toast({ title: 'Routing rule created' })
      resetRuleForm()
    },
    onError: () => toast({ title: 'Failed to create routing rule', variant: 'destructive' }),
  })

  const updateRuleMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<RoutingRule> }) =>
      api.put(`/api/v1/notifications/routing-rules/${id}`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['routing-rules'] })
      toast({ title: 'Routing rule updated' })
      resetRuleForm()
    },
    onError: () => toast({ title: 'Failed to update routing rule', variant: 'destructive' }),
  })

  const deleteRuleMutation = useMutation({
    mutationFn: (id: string) =>
      api.delete(`/api/v1/notifications/routing-rules/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['routing-rules'] })
      toast({ title: 'Routing rule deleted' })
    },
    onError: () => toast({ title: 'Failed to delete routing rule', variant: 'destructive' }),
  })

  const toggleRuleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      api.put(`/api/v1/notifications/routing-rules/${id}`, { enabled }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['routing-rules'] })
      toast({ title: 'Rule status updated' })
    },
    onError: () => toast({ title: 'Failed to update rule', variant: 'destructive' }),
  })

  // ── Broadcast Mutations ─────────────────────────────────────────────────

  const createBroadcastMutation = useMutation({
    mutationFn: (data: typeof broadcastForm) =>
      api.post('/api/v1/notifications/broadcasts', {
        ...data,
        target_ids: data.target_type === 'all' ? [] : data.target_ids.split('\n').map(s => s.trim()).filter(Boolean),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['broadcasts'] })
      toast({ title: 'Broadcast created' })
      resetBroadcastForm()
    },
    onError: () => toast({ title: 'Failed to create broadcast', variant: 'destructive' }),
  })

  const sendBroadcastMutation = useMutation({
    mutationFn: (id: string) =>
      api.post(`/api/v1/notifications/broadcasts/${id}/send`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['broadcasts'] })
      toast({ title: 'Broadcast sent' })
    },
    onError: () => toast({ title: 'Failed to send broadcast', variant: 'destructive' }),
  })

  const deleteBroadcastMutation = useMutation({
    mutationFn: (id: string) =>
      api.delete(`/api/v1/notifications/broadcasts/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['broadcasts'] })
      toast({ title: 'Broadcast deleted' })
    },
    onError: () => toast({ title: 'Failed to delete broadcast', variant: 'destructive' }),
  })

  // ── Helpers ─────────────────────────────────────────────────────────────

  const resetRuleForm = () => {
    setShowRuleForm(false)
    setEditingRule(null)
    setRuleForm({ name: '', event_type: '', channels: [], priority: 0 })
  }

  const resetBroadcastForm = () => {
    setShowBroadcastForm(false)
    setBroadcastForm({ title: '', body: '', channel: 'in_app', target_type: 'all', target_ids: '', priority: 'normal' })
  }

  const startEditRule = (rule: RoutingRule) => {
    setEditingRule(rule)
    setRuleForm({ name: rule.name, event_type: rule.event_type, channels: rule.channels, priority: rule.priority })
    setShowRuleForm(true)
  }

  const handleRuleSubmit = () => {
    if (editingRule) {
      updateRuleMutation.mutate({ id: editingRule.id, data: { ...ruleForm, conditions: editingRule.conditions, template_overrides: editingRule.template_overrides } })
    } else {
      createRuleMutation.mutate(ruleForm)
    }
  }

  const toggleChannel = (channel: string) => {
    setRuleForm(prev => ({
      ...prev,
      channels: prev.channels.includes(channel)
        ? prev.channels.filter(c => c !== channel)
        : [...prev.channels, channel],
    }))
  }

  const readRate = statsData && statsData.total_sent > 0
    ? Math.round((statsData.total_read / statsData.total_sent) * 100)
    : 0

  // ── Render ──────────────────────────────────────────────────────────────

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Notification Administration</h1>
        <p className="text-muted-foreground">Manage routing rules, broadcasts, and delivery statistics</p>
      </div>

      {/* Tab Navigation */}
      <div className="flex gap-2 border-b pb-2">
        <button
          onClick={() => setActiveTab('routing')}
          className={`flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-t-md transition-colors ${
            activeTab === 'routing' ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:text-foreground hover:bg-muted'
          }`}
        >
          <Route className="h-4 w-4" />
          Routing Rules
        </button>
        <button
          onClick={() => setActiveTab('broadcasts')}
          className={`flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-t-md transition-colors ${
            activeTab === 'broadcasts' ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:text-foreground hover:bg-muted'
          }`}
        >
          <Megaphone className="h-4 w-4" />
          Broadcasts
        </button>
        <button
          onClick={() => setActiveTab('stats')}
          className={`flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-t-md transition-colors ${
            activeTab === 'stats' ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:text-foreground hover:bg-muted'
          }`}
        >
          <BarChart3 className="h-4 w-4" />
          Delivery Stats
        </button>
      </div>

      {/* ── Tab 1: Routing Rules ──────────────────────────────────────────── */}
      {activeTab === 'routing' && (
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle>Routing Rules</CardTitle>
              <Button onClick={() => { resetRuleForm(); setShowRuleForm(true) }}>
                <Plus className="mr-2 h-4 w-4" />
                Create Rule
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            {/* Create/Edit Form */}
            {showRuleForm && (
              <div className="mb-6 p-4 rounded-lg border bg-muted/30 space-y-4">
                <h3 className="font-semibold text-sm">
                  {editingRule ? 'Edit Routing Rule' : 'Create Routing Rule'}
                </h3>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="text-sm font-medium">Name</label>
                    <input
                      className="w-full mt-1 px-3 py-2 border rounded-md text-sm"
                      placeholder="Rule name"
                      value={ruleForm.name}
                      onChange={e => setRuleForm(p => ({ ...p, name: e.target.value }))}
                    />
                  </div>
                  <div>
                    <label className="text-sm font-medium">Event Type</label>
                    <input
                      className="w-full mt-1 px-3 py-2 border rounded-md text-sm"
                      placeholder="e.g. security_alert"
                      value={ruleForm.event_type}
                      onChange={e => setRuleForm(p => ({ ...p, event_type: e.target.value }))}
                    />
                  </div>
                </div>
                <div>
                  <label className="text-sm font-medium">Channels</label>
                  <div className="flex gap-4 mt-1">
                    {CHANNELS.map(ch => (
                      <label key={ch} className="flex items-center gap-2 text-sm">
                        <input
                          type="checkbox"
                          checked={ruleForm.channels.includes(ch)}
                          onChange={() => toggleChannel(ch)}
                        />
                        {ch}
                      </label>
                    ))}
                  </div>
                </div>
                <div>
                  <label className="text-sm font-medium">Priority</label>
                  <input
                    type="number"
                    className="w-32 mt-1 px-3 py-2 border rounded-md text-sm"
                    value={ruleForm.priority}
                    onChange={e => setRuleForm(p => ({ ...p, priority: parseInt(e.target.value) || 0 }))}
                  />
                </div>
                <div className="flex gap-2">
                  <Button
                    size="sm"
                    onClick={handleRuleSubmit}
                    disabled={!ruleForm.name || !ruleForm.event_type || ruleForm.channels.length === 0 || createRuleMutation.isPending || updateRuleMutation.isPending}
                  >
                    {editingRule ? 'Update Rule' : 'Create Rule'}
                  </Button>
                  <Button size="sm" variant="outline" onClick={resetRuleForm}>
                    Cancel
                  </Button>
                </div>
              </div>
            )}

            {/* Rules Table */}
            {rulesLoading ? (
              <div className="flex flex-col items-center justify-center py-12">
                <LoadingSpinner size="lg" />
                <p className="mt-4 text-sm text-muted-foreground">Loading routing rules...</p>
              </div>
            ) : rulesIsError ? (
              <QueryError error={rulesError} resource="routing rules" />
            ) : rules.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                <Route className="h-12 w-12 text-muted-foreground/40 mb-3" />
                <p className="font-medium">No routing rules</p>
                <p className="text-sm">Create a routing rule to define how notifications are delivered</p>
              </div>
            ) : (
              <div className="rounded-md border">
                <Table>
                  <TableHeader>
                    <TableRow className="border-b bg-muted/50">
                      <TableHead className="text-left py-3 px-4 text-sm font-medium">Name</TableHead>
                      <TableHead className="text-left py-3 px-4 text-sm font-medium">Event Type</TableHead>
                      <TableHead className="text-left py-3 px-4 text-sm font-medium">Channels</TableHead>
                      <TableHead className="text-left py-3 px-4 text-sm font-medium">Priority</TableHead>
                      <TableHead className="text-left py-3 px-4 text-sm font-medium">Enabled</TableHead>
                      <TableHead className="text-left py-3 px-4 text-sm font-medium">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {rules.map(rule => (
                      <TableRow key={rule.id} className="border-b last:border-0">
                        <TableCell className="py-3 px-4 text-sm font-medium">{rule.name}</TableCell>
                        <TableCell className="py-3 px-4 text-sm">
                          <Badge variant="outline">{rule.event_type}</Badge>
                        </TableCell>
                        <TableCell className="py-3 px-4">
                          <div className="flex gap-1 flex-wrap">
                            {rule.channels.map(ch => (
                              <Badge key={ch} className="text-xs bg-blue-100 text-blue-800">{ch}</Badge>
                            ))}
                          </div>
                        </TableCell>
                        <TableCell className="py-3 px-4 text-sm">{rule.priority}</TableCell>
                        <TableCell className="py-3 px-4">
                          <button
                            onClick={() => toggleRuleMutation.mutate({ id: rule.id, enabled: !rule.enabled })}
                            className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                              rule.enabled ? 'bg-primary' : 'bg-muted'
                            }`}
                          >
                            <span className={`inline-block h-4 w-4 transform rounded-full bg-background transition-transform ${
                              rule.enabled ? 'translate-x-6' : 'translate-x-1'
                            }`} />
                          </button>
                        </TableCell>
                        <TableCell className="py-3 px-4">
                          <div className="flex gap-1">
                            <Button variant="ghost" size="sm" className="h-8 w-8 p-0" title="Edit" onClick={() => startEditRule(rule)}>
                              <Edit className="h-4 w-4" />
                            </Button>
                            <ConfirmAction
                              title="Delete this routing rule?"
                              description={`This deletes the "${rule.name}" notification routing rule. Notifications for the "${rule.event_type}" event will no longer be routed by this rule.`}
                              destructive
                              confirmLabel="Delete"
                              onConfirm={() => deleteRuleMutation.mutateAsync(rule.id)}
                            >
                              {(open) => (
                                <Button variant="ghost" size="sm" className="h-8 w-8 p-0" title="Delete" onClick={open}>
                                  <Trash2 className="h-4 w-4 text-red-500" />
                                </Button>
                              )}
                            </ConfirmAction>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* ── Tab 2: Broadcasts ─────────────────────────────────────────────── */}
      {activeTab === 'broadcasts' && (
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle>Broadcasts</CardTitle>
              <Button onClick={() => { resetBroadcastForm(); setShowBroadcastForm(true) }}>
                <Plus className="mr-2 h-4 w-4" />
                Create Broadcast
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            {/* Create Form */}
            {showBroadcastForm && (
              <div className="mb-6 p-4 rounded-lg border bg-muted/30 space-y-4">
                <h3 className="font-semibold text-sm">Create Broadcast</h3>
                <div>
                  <label className="text-sm font-medium">Title</label>
                  <input
                    className="w-full mt-1 px-3 py-2 border rounded-md text-sm"
                    placeholder="Broadcast title"
                    value={broadcastForm.title}
                    onChange={e => setBroadcastForm(p => ({ ...p, title: e.target.value }))}
                  />
                </div>
                <div>
                  <label className="text-sm font-medium">Body</label>
                  <textarea
                    className="w-full mt-1 px-3 py-2 border rounded-md text-sm min-h-[80px]"
                    placeholder="Broadcast message body"
                    value={broadcastForm.body}
                    onChange={e => setBroadcastForm(p => ({ ...p, body: e.target.value }))}
                  />
                </div>
                <div className="grid grid-cols-3 gap-4">
                  <div>
                    <label className="text-sm font-medium">Channel</label>
                    <select
                      className="w-full mt-1 px-3 py-2 border rounded-md text-sm"
                      value={broadcastForm.channel}
                      onChange={e => setBroadcastForm(p => ({ ...p, channel: e.target.value }))}
                    >
                      <option value="in_app">In-App</option>
                      <option value="email">Email</option>
                    </select>
                  </div>
                  <div>
                    <label className="text-sm font-medium">Target Type</label>
                    <select
                      className="w-full mt-1 px-3 py-2 border rounded-md text-sm"
                      value={broadcastForm.target_type}
                      onChange={e => setBroadcastForm(p => ({ ...p, target_type: e.target.value }))}
                    >
                      <option value="all">All Users</option>
                      <option value="role">By Role</option>
                      <option value="group">By Group</option>
                    </select>
                  </div>
                  <div>
                    <label className="text-sm font-medium">Priority</label>
                    <select
                      className="w-full mt-1 px-3 py-2 border rounded-md text-sm"
                      value={broadcastForm.priority}
                      onChange={e => setBroadcastForm(p => ({ ...p, priority: e.target.value }))}
                    >
                      <option value="low">Low</option>
                      <option value="normal">Normal</option>
                      <option value="high">High</option>
                      <option value="urgent">Urgent</option>
                    </select>
                  </div>
                </div>
                {(broadcastForm.target_type === 'role' || broadcastForm.target_type === 'group') && (
                  <div>
                    <label className="text-sm font-medium">
                      Target IDs ({broadcastForm.target_type === 'role' ? 'Role' : 'Group'} names, one per line)
                    </label>
                    <textarea
                      className="w-full mt-1 px-3 py-2 border rounded-md text-sm min-h-[60px]"
                      placeholder={`Enter ${broadcastForm.target_type} names, one per line`}
                      value={broadcastForm.target_ids}
                      onChange={e => setBroadcastForm(p => ({ ...p, target_ids: e.target.value }))}
                    />
                  </div>
                )}
                <div className="flex gap-2">
                  <Button
                    size="sm"
                    onClick={() => createBroadcastMutation.mutate(broadcastForm)}
                    disabled={!broadcastForm.title || !broadcastForm.body || createBroadcastMutation.isPending}
                  >
                    {createBroadcastMutation.isPending ? 'Creating...' : 'Create Broadcast'}
                  </Button>
                  <Button size="sm" variant="outline" onClick={resetBroadcastForm}>
                    Cancel
                  </Button>
                </div>
              </div>
            )}

            {/* Broadcasts Table */}
            {broadcastsLoading ? (
              <div className="flex flex-col items-center justify-center py-12">
                <LoadingSpinner size="lg" />
                <p className="mt-4 text-sm text-muted-foreground">Loading broadcasts...</p>
              </div>
            ) : broadcastsIsError ? (
              <QueryError error={broadcastsError} resource="broadcasts" />
            ) : broadcasts.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                <Megaphone className="h-12 w-12 text-muted-foreground/40 mb-3" />
                <p className="font-medium">No broadcasts</p>
                <p className="text-sm">Create a broadcast to send notifications to users</p>
              </div>
            ) : (
              <div className="rounded-md border">
                <Table>
                  <TableHeader>
                    <TableRow className="border-b bg-muted/50">
                      <TableHead className="text-left py-3 px-4 text-sm font-medium">Title</TableHead>
                      <TableHead className="text-left py-3 px-4 text-sm font-medium">Channel</TableHead>
                      <TableHead className="text-left py-3 px-4 text-sm font-medium">Target</TableHead>
                      <TableHead className="text-left py-3 px-4 text-sm font-medium">Status</TableHead>
                      <TableHead className="text-left py-3 px-4 text-sm font-medium">Recipients</TableHead>
                      <TableHead className="text-left py-3 px-4 text-sm font-medium">Delivered</TableHead>
                      <TableHead className="text-left py-3 px-4 text-sm font-medium">Read</TableHead>
                      <TableHead className="text-left py-3 px-4 text-sm font-medium">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {broadcasts.map(broadcast => (
                      <TableRow key={broadcast.id} className="border-b last:border-0">
                        <TableCell className="py-3 px-4 text-sm font-medium">{broadcast.title}</TableCell>
                        <TableCell className="py-3 px-4 text-sm">
                          <Badge variant="outline">{broadcast.channel}</Badge>
                        </TableCell>
                        <TableCell className="py-3 px-4 text-sm">
                          <Badge variant="outline">{broadcast.target_type}</Badge>
                        </TableCell>
                        <TableCell className="py-3 px-4">
                          <Badge className={statusBadgeClass(broadcast.status)}>
                            {broadcast.status}
                          </Badge>
                        </TableCell>
                        <TableCell className="py-3 px-4 text-sm">{broadcast.total_recipients}</TableCell>
                        <TableCell className="py-3 px-4 text-sm">{broadcast.delivered_count}</TableCell>
                        <TableCell className="py-3 px-4 text-sm">{broadcast.read_count}</TableCell>
                        <TableCell className="py-3 px-4">
                          <div className="flex gap-1">
                            {broadcast.status === 'draft' && (
                              <>
                                <ConfirmAction
                                  title="Send this broadcast to all targeted users?"
                                  description={`This sends the broadcast "${broadcast.title}" to ${broadcast.total_recipients || 'all targeted'} recipients immediately. Delivered notifications cannot be recalled.`}
                                  destructive
                                  requireReason
                                  confirmLabel="Send Broadcast"
                                  onConfirm={() => sendBroadcastMutation.mutateAsync(broadcast.id)}
                                >
                                  {(open) => (
                                    <Button
                                      variant="ghost"
                                      size="sm"
                                      className="h-8 w-8 p-0"
                                      title="Send"
                                      onClick={open}
                                      disabled={sendBroadcastMutation.isPending}
                                    >
                                      <Send className="h-4 w-4 text-green-600" />
                                    </Button>
                                  )}
                                </ConfirmAction>
                                <ConfirmAction
                                  title="Delete this broadcast?"
                                  description={`This permanently deletes the draft broadcast "${broadcast.title}". It has not been sent, and this cannot be undone.`}
                                  destructive
                                  confirmLabel="Delete"
                                  onConfirm={() => deleteBroadcastMutation.mutateAsync(broadcast.id)}
                                >
                                  {(open) => (
                                    <Button
                                      variant="ghost"
                                      size="sm"
                                      className="h-8 w-8 p-0"
                                      title="Delete"
                                      onClick={open}
                                      disabled={deleteBroadcastMutation.isPending}
                                    >
                                      <Trash2 className="h-4 w-4 text-red-500" />
                                    </Button>
                                  )}
                                </ConfirmAction>
                              </>
                            )}
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* ── Tab 3: Delivery Stats ─────────────────────────────────────────── */}
      {activeTab === 'stats' && (
        <div className="space-y-6">
          {statsLoading ? (
            <div className="flex flex-col items-center justify-center py-12">
              <LoadingSpinner size="lg" />
              <p className="mt-4 text-sm text-muted-foreground">Loading delivery statistics...</p>
            </div>
          ) : statsIsError ? (
            <QueryError error={statsError} resource="delivery statistics" />
          ) : !statsData ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <BarChart3 className="h-12 w-12 text-muted-foreground/40 mb-3" />
              <p className="font-medium">No statistics available</p>
              <p className="text-sm">Statistics will appear once notifications have been sent</p>
            </div>
          ) : (
            <>
              {/* Summary Cards */}
              <div className="grid gap-4 md:grid-cols-4">
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-medium">Total Sent</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="text-2xl font-bold">{statsData.total_sent}</div>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-medium">Read Rate</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="text-2xl font-bold text-green-600">{readRate}%</div>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-medium">Unread</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="text-2xl font-bold text-yellow-600">{statsData.total_unread}</div>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-medium">Active Rules</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="text-2xl font-bold">{statsData.routing_rules_count}</div>
                  </CardContent>
                </Card>
              </div>

              {/* Channel Breakdown */}
              <Card>
                <CardHeader>
                  <CardTitle>Channel Breakdown</CardTitle>
                </CardHeader>
                <CardContent>
                  {statsData.channel_breakdown && Object.keys(statsData.channel_breakdown).length > 0 ? (
                    <div className="space-y-3">
                      {Object.entries(statsData.channel_breakdown).map(([channel, count]) => {
                        const percentage = statsData.total_sent > 0
                          ? Math.round((count / statsData.total_sent) * 100)
                          : 0
                        return (
                          <div key={channel} className="flex items-center gap-4">
                            <div className="w-24 text-sm font-medium flex items-center gap-2">
                              <Bell className="h-4 w-4 text-muted-foreground" />
                              {channel}
                            </div>
                            <div className="flex-1">
                              <div className="w-full bg-muted rounded-full h-2.5">
                                <div
                                  className="bg-primary h-2.5 rounded-full transition-all"
                                  style={{ width: `${percentage}%` }}
                                />
                              </div>
                            </div>
                            <div className="w-20 text-right text-sm text-muted-foreground">
                              {count} ({percentage}%)
                            </div>
                          </div>
                        )
                      })}
                    </div>
                  ) : (
                    <p className="text-sm text-muted-foreground py-4 text-center">
                      No channel data available yet
                    </p>
                  )}
                </CardContent>
              </Card>
            </>
          )}
        </div>
      )}
    </div>
  )
}
