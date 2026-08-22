import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { ConfirmAction } from '../components/confirm-action'
import { Bot, Plus, RotateCw, Pause, Play, Trash2, Shield, Activity, Key, Clock } from 'lucide-react'

interface AIAgent {
  id: string
  name: string
  description: string
  agent_type: string
  owner_id: string | null
  owner_email: string
  status: string
  capabilities: string[]
  trust_level: string
  rate_limits: { requests_per_minute: number; requests_per_hour: number }
  allowed_scopes: string[]
  ip_allowlist: string[]
  metadata: Record<string, unknown>
  last_active_at: string | null
  created_at: string
  updated_at: string
}

interface AIAgentCredential {
  id: string
  credential_type: string
  key_prefix: string
  status: string
  expires_at: string | null
  last_used_at: string | null
  created_at: string
}

interface AgentAnalytics {
  total_agents: number
  active_agents: number
  suspended_agents: number
  by_type: Array<{ type: string; count: number }>
  top_agents_24h: Array<{ id: string; name: string; type: string; activity_count: number }>
  expiring_credentials_30d: number
  recent_failures_24h: number
}

const typeColors: Record<string, string> = {
  assistant: 'bg-blue-100 text-blue-800',
  autonomous: 'bg-purple-100 text-purple-800',
  workflow: 'bg-green-100 text-green-800',
  integration: 'bg-orange-100 text-orange-800',
}

const trustColors: Record<string, string> = {
  low: 'bg-gray-100 text-gray-800',
  medium: 'bg-yellow-100 text-yellow-800',
  high: 'bg-red-100 text-red-800',
}

const statusColors: Record<string, string> = {
  active: 'bg-green-100 text-green-800',
  suspended: 'bg-red-100 text-red-800',
  inactive: 'bg-gray-100 text-gray-800',
}

export function AIAgentsPage() {
  const queryClient = useQueryClient()
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null)
  const [showCreate, setShowCreate] = useState(false)
  const [newAgent, setNewAgent] = useState({ name: '', description: '', agent_type: 'assistant', trust_level: 'low' })
  const [newApiKey, setNewApiKey] = useState<string | null>(null)

  const { data: agentsData, isLoading, isError, error } = useQuery({
    queryKey: ['ai-agents'],
    queryFn: () => api.get<{ data: AIAgent[]; total: number }>('/api/v1/ai-agents'),
  })

  const { data: analytics } = useQuery<AgentAnalytics>({
    queryKey: ['ai-agents-analytics'],
    queryFn: () => api.get<AgentAnalytics>('/api/v1/ai-agents/analytics'),
  })

  const { data: agentDetail } = useQuery({
    queryKey: ['ai-agent', selectedAgent],
    queryFn: () => api.get<{ data: AIAgent; credentials: AIAgentCredential[] }>(`/api/v1/ai-agents/${selectedAgent}`),
    enabled: !!selectedAgent,
  })

  const createMutation = useMutation({
    mutationFn: (data: typeof newAgent) => api.post<{ data: AIAgent; api_key: string }>('/api/v1/ai-agents', data),
    onSuccess: (resp) => {
      queryClient.invalidateQueries({ queryKey: ['ai-agents'] })
      queryClient.invalidateQueries({ queryKey: ['ai-agents-analytics'] })
      setShowCreate(false)
      setNewApiKey(resp.api_key)
      setNewAgent({ name: '', description: '', agent_type: 'assistant', trust_level: 'low' })
    },
  })

  const suspendMutation = useMutation({
    mutationFn: (id: string) => api.post(`/api/v1/ai-agents/${id}/suspend`, {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ai-agents'] })
      queryClient.invalidateQueries({ queryKey: ['ai-agents-analytics'] })
    },
  })

  const activateMutation = useMutation({
    mutationFn: (id: string) => api.post(`/api/v1/ai-agents/${id}/activate`, {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ai-agents'] })
      queryClient.invalidateQueries({ queryKey: ['ai-agents-analytics'] })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/ai-agents/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ai-agents'] })
      queryClient.invalidateQueries({ queryKey: ['ai-agents-analytics'] })
      setSelectedAgent(null)
    },
  })

  const rotateMutation = useMutation({
    mutationFn: (id: string) => api.post<{ api_key: string }>(`/api/v1/ai-agents/${id}/rotate-credentials`, {}),
    onSuccess: (resp) => {
      queryClient.invalidateQueries({ queryKey: ['ai-agent', selectedAgent] })
      setNewApiKey(resp.api_key)
    },
  })

  if (isLoading) {
    return <div className="flex justify-center py-12"><LoadingSpinner size="lg" /></div>
  }

  if (isError) {
    return <QueryError error={error} resource="AI agents" />
  }

  const agents = agentsData?.data || []

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">AI Agent Management</h1>
          <p className="text-muted-foreground">Manage AI agent identities, credentials, and permissions</p>
        </div>
        <Button onClick={() => setShowCreate(true)}><Plus className="h-4 w-4 mr-2" />Create Agent</Button>
      </div>

      {newApiKey && (
        <Card className="border-yellow-300 bg-yellow-50">
          <CardContent className="pt-4">
            <p className="font-medium text-yellow-800 mb-2">New API Key Generated - Copy it now, it won't be shown again:</p>
            <code className="block bg-white p-3 rounded border text-sm break-all">{newApiKey}</code>
            <Button variant="outline" className="mt-2" onClick={() => setNewApiKey(null)}>Dismiss</Button>
          </CardContent>
        </Card>
      )}

      {/* Analytics Summary */}
      {analytics && (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
          <Card><CardContent className="pt-4 text-center">
            <Bot className="h-5 w-5 mx-auto mb-1 text-blue-600" />
            <p className="text-2xl font-bold">{analytics.total_agents}</p>
            <p className="text-xs text-muted-foreground">Total Agents</p>
          </CardContent></Card>
          <Card><CardContent className="pt-4 text-center">
            <Play className="h-5 w-5 mx-auto mb-1 text-green-600" />
            <p className="text-2xl font-bold">{analytics.active_agents}</p>
            <p className="text-xs text-muted-foreground">Active</p>
          </CardContent></Card>
          <Card><CardContent className="pt-4 text-center">
            <Pause className="h-5 w-5 mx-auto mb-1 text-red-600" />
            <p className="text-2xl font-bold">{analytics.suspended_agents}</p>
            <p className="text-xs text-muted-foreground">Suspended</p>
          </CardContent></Card>
          <Card><CardContent className="pt-4 text-center">
            <Key className="h-5 w-5 mx-auto mb-1 text-orange-600" />
            <p className="text-2xl font-bold">{analytics.expiring_credentials_30d}</p>
            <p className="text-xs text-muted-foreground">Expiring Keys</p>
          </CardContent></Card>
          <Card><CardContent className="pt-4 text-center">
            <Activity className="h-5 w-5 mx-auto mb-1 text-purple-600" />
            <p className="text-2xl font-bold">{(analytics.top_agents_24h || []).reduce((s, a) => s + a.activity_count, 0)}</p>
            <p className="text-xs text-muted-foreground">Actions (24h)</p>
          </CardContent></Card>
          <Card><CardContent className="pt-4 text-center">
            <Shield className="h-5 w-5 mx-auto mb-1 text-red-600" />
            <p className="text-2xl font-bold">{analytics.recent_failures_24h}</p>
            <p className="text-xs text-muted-foreground">Failures (24h)</p>
          </CardContent></Card>
        </div>
      )}

      {/* Create Modal */}
      {showCreate && (
        <Card>
          <CardHeader><CardTitle>Create New AI Agent</CardTitle></CardHeader>
          <CardContent className="space-y-4">
            <div>
              <label className="text-sm font-medium">Name</label>
              <input className="w-full border rounded px-3 py-2 mt-1" value={newAgent.name}
                onChange={(e) => setNewAgent({ ...newAgent, name: e.target.value })} placeholder="e.g., CI/CD Pipeline Bot" />
            </div>
            <div>
              <label className="text-sm font-medium">Description</label>
              <input className="w-full border rounded px-3 py-2 mt-1" value={newAgent.description}
                onChange={(e) => setNewAgent({ ...newAgent, description: e.target.value })} placeholder="What does this agent do?" />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-sm font-medium">Type</label>
                <select className="w-full border rounded px-3 py-2 mt-1" value={newAgent.agent_type}
                  onChange={(e) => setNewAgent({ ...newAgent, agent_type: e.target.value })}>
                  <option value="assistant">Assistant</option>
                  <option value="autonomous">Autonomous</option>
                  <option value="workflow">Workflow</option>
                  <option value="integration">Integration</option>
                </select>
              </div>
              <div>
                <label className="text-sm font-medium">Trust Level</label>
                <select className="w-full border rounded px-3 py-2 mt-1" value={newAgent.trust_level}
                  onChange={(e) => setNewAgent({ ...newAgent, trust_level: e.target.value })}>
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                </select>
              </div>
            </div>
            <div className="flex gap-2">
              <Button onClick={() => createMutation.mutate(newAgent)} disabled={!newAgent.name || createMutation.isPending}>
                {createMutation.isPending ? 'Creating...' : 'Create Agent'}
              </Button>
              <Button variant="outline" onClick={() => setShowCreate(false)}>Cancel</Button>
            </div>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Agent List */}
        <div className="lg:col-span-2">
          <Card>
            <CardHeader><CardTitle>Agents ({agents.length})</CardTitle></CardHeader>
            <CardContent>
              <div className="divide-y">
                {agents.map((agent) => (
                  <div key={agent.id} className={`py-3 flex items-center justify-between cursor-pointer hover:bg-gray-50 px-2 rounded ${selectedAgent === agent.id ? 'bg-blue-50' : ''}`}
                    onClick={() => setSelectedAgent(agent.id)}>
                    <div className="flex items-center gap-3">
                      <Bot className="h-8 w-8 text-gray-400" />
                      <div>
                        <p className="font-medium">{agent.name}</p>
                        <p className="text-sm text-muted-foreground">{agent.description || 'No description'}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge className={typeColors[agent.agent_type] || 'bg-gray-100'}>{agent.agent_type}</Badge>
                      <Badge className={trustColors[agent.trust_level] || 'bg-gray-100'}>Trust: {agent.trust_level}</Badge>
                      <Badge className={statusColors[agent.status] || 'bg-gray-100'}>{agent.status}</Badge>
                    </div>
                  </div>
                ))}
                {agents.length === 0 && <p className="text-center text-muted-foreground py-8">No AI agents configured</p>}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Agent Detail */}
        <div>
          {selectedAgent && agentDetail ? (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Bot className="h-5 w-5" />{agentDetail.data.name}
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <p className="text-sm text-muted-foreground">Type</p>
                  <Badge className={typeColors[agentDetail.data.agent_type] || ''}>{agentDetail.data.agent_type}</Badge>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Trust Level</p>
                  <Badge className={trustColors[agentDetail.data.trust_level] || ''}>{agentDetail.data.trust_level}</Badge>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Status</p>
                  <Badge className={statusColors[agentDetail.data.status] || ''}>{agentDetail.data.status}</Badge>
                </div>
                {agentDetail.data.owner_email && (
                  <div>
                    <p className="text-sm text-muted-foreground">Owner</p>
                    <p className="text-sm">{agentDetail.data.owner_email}</p>
                  </div>
                )}
                {agentDetail.data.last_active_at && (
                  <div>
                    <p className="text-sm text-muted-foreground">Last Active</p>
                    <p className="text-sm flex items-center gap-1"><Clock className="h-3 w-3" />{new Date(agentDetail.data.last_active_at).toLocaleString()}</p>
                  </div>
                )}
                {agentDetail.data.allowed_scopes?.length > 0 && (
                  <div>
                    <p className="text-sm text-muted-foreground mb-1">Scopes</p>
                    <div className="flex flex-wrap gap-1">
                      {agentDetail.data.allowed_scopes.map((s) => (
                        <Badge key={s} variant="outline" className="text-xs">{s}</Badge>
                      ))}
                    </div>
                  </div>
                )}

                {/* Credentials */}
                <div>
                  <p className="text-sm font-medium mb-2">Credentials</p>
                  {(agentDetail.credentials || []).map((cred) => (
                    <div key={cred.id} className="flex items-center justify-between text-sm border rounded p-2 mb-1">
                      <div>
                        <span className="font-mono">{cred.key_prefix}...</span>
                        <Badge className="ml-2" variant={cred.status === 'active' ? 'default' : 'destructive'}>{cred.status}</Badge>
                      </div>
                      {cred.expires_at && <span className="text-xs text-muted-foreground">Exp: {new Date(cred.expires_at).toLocaleDateString()}</span>}
                    </div>
                  ))}
                </div>

                {/* Actions */}
                <div className="flex flex-wrap gap-2 pt-2 border-t">
                  <ConfirmAction
                    title="Rotate this agent's key?"
                    description="A new credential is issued and the agent's current key stops working immediately. Update anything using the old key before rotating."
                    destructive
                    confirmLabel="Rotate"
                    onConfirm={() => rotateMutation.mutate(selectedAgent)}
                  >
                    {(open) => (
                      <Button size="sm" variant="outline" onClick={open}>
                        <RotateCw className="h-3 w-3 mr-1" />Rotate Key
                      </Button>
                    )}
                  </ConfirmAction>
                  {agentDetail.data.status === 'active' ? (
                    <Button size="sm" variant="outline" onClick={() => suspendMutation.mutate(selectedAgent)}>
                      <Pause className="h-3 w-3 mr-1" />Suspend
                    </Button>
                  ) : (
                    <Button size="sm" variant="outline" onClick={() => activateMutation.mutate(selectedAgent)}>
                      <Play className="h-3 w-3 mr-1" />Activate
                    </Button>
                  )}
                  <ConfirmAction
                    title="Delete this agent?"
                    description="This permanently removes the AI agent and its issued credentials. This cannot be undone."
                    destructive
                    confirmLabel="Delete"
                    onConfirm={() => selectedAgent ? deleteMutation.mutateAsync(selectedAgent) : undefined}
                  >
                    {(open) => (
                      <Button size="sm" variant="destructive" onClick={open}>
                        <Trash2 className="h-3 w-3 mr-1" />Delete
                      </Button>
                    )}
                  </ConfirmAction>
                </div>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent className="pt-6 text-center text-muted-foreground">
                <Bot className="h-12 w-12 mx-auto mb-3 text-gray-300" />
                <p>Select an agent to view details</p>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  )
}
