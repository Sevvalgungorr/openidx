import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { api } from '../lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { ClipboardCheck, Plus, Rocket, CheckCircle, X, ArrowRight, BarChart3 } from 'lucide-react'
import { ConfirmAction } from '../components/confirm-action'
import { RelatedLinks } from '../components/related-links'

interface AttestationCampaign {
  id: string
  name: string
  description: string
  campaign_type: string
  scope: Record<string, unknown>
  reviewer_strategy: string
  status: string
  due_date: string | null
  escalation_after_days: number
  auto_revoke_on_expiry: boolean
  created_at: string
  completed_at: string | null
  total_items: number
  certified_count: number
  revoked_count: number
  pending_count: number
}

interface AttestationItem {
  id: string
  campaign_id: string
  reviewer_id: string | null
  reviewer_name: string
  user_id: string | null
  user_name: string
  resource_type: string
  resource_id: string | null
  resource_name: string
  decision: string
  delegated_to: string | null
  comments: string
  decided_at: string | null
  created_at: string
}

const typeLabels: Record<string, string> = {
  manager_review: 'Manager Review',
  application_access: 'Application Access',
  role_certification: 'Role Certification',
  entitlement_review: 'Entitlement Review',
}

const statusColors: Record<string, string> = {
  draft: 'bg-muted text-foreground',
  active: 'bg-blue-100 text-blue-800',
  completed: 'bg-green-100 text-green-800',
  expired: 'bg-red-100 text-red-800',
}

const decisionColors: Record<string, string> = {
  pending: 'bg-yellow-100 text-yellow-800',
  certified: 'bg-green-100 text-green-800',
  revoked: 'bg-red-100 text-red-800',
  delegated: 'bg-purple-100 text-purple-800',
}

export function AttestationCampaignsPage() {
  const queryClient = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [selectedCampaign, setSelectedCampaign] = useState<string | null>(null)

  // Form state
  const [formName, setFormName] = useState('')
  const [formDesc, setFormDesc] = useState('')
  const [formType, setFormType] = useState('role_certification')
  const [formStrategy, setFormStrategy] = useState('manager')
  const [formEscalation, setFormEscalation] = useState(14)
  const [formAutoRevoke, setFormAutoRevoke] = useState(false)

  const { data: campaignsData, isLoading, isError, error } = useQuery({
    queryKey: ['attestation-campaigns'],
    queryFn: () => api.get<{ data: AttestationCampaign[] }>('/api/v1/attestation-campaigns'),
  })

  const { data: itemsData } = useQuery({
    queryKey: ['attestation-items', selectedCampaign],
    queryFn: () => api.get<{ data: AttestationItem[] }>(`/api/v1/attestation-campaigns/${selectedCampaign}/items`),
    enabled: !!selectedCampaign,
  })

  const { data: progressData } = useQuery({
    queryKey: ['attestation-progress', selectedCampaign],
    queryFn: () => api.get<{ total: number; certified: number; revoked: number; pending: number; delegated: number; completion_pct: number }>(
      `/api/v1/attestation-campaigns/${selectedCampaign}/progress`),
    enabled: !!selectedCampaign,
    refetchInterval: 5000,
  })

  const createMutation = useMutation({
    mutationFn: (data: Record<string, unknown>) => api.post('/api/v1/attestation-campaigns', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['attestation-campaigns'] })
      setShowCreate(false)
      setFormName('')
      setFormDesc('')
    },
  })

  const launchMutation = useMutation({
    mutationFn: (id: string) => api.post(`/api/v1/attestation-campaigns/${id}/launch`, {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['attestation-campaigns'] })
      queryClient.invalidateQueries({ queryKey: ['attestation-items'] })
    },
  })

  const decideMutation = useMutation({
    mutationFn: ({ campaignId, itemId, decision, comments }: { campaignId: string; itemId: string; decision: string; comments: string }) =>
      api.post(`/api/v1/attestation-campaigns/${campaignId}/items/${itemId}/decide`, { decision, comments }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['attestation-items'] })
      queryClient.invalidateQueries({ queryKey: ['attestation-progress'] })
      queryClient.invalidateQueries({ queryKey: ['attestation-campaigns'] })
    },
  })

  const handleCreate = () => {
    createMutation.mutate({
      name: formName, description: formDesc, campaign_type: formType,
      reviewer_strategy: formStrategy, escalation_after_days: formEscalation,
      auto_revoke_on_expiry: formAutoRevoke,
    })
  }

  if (isLoading) return <div className="flex justify-center py-12"><LoadingSpinner size="lg" /></div>
  if (isError) return <QueryError error={error} resource="attestation campaigns" />

  const campaigns = campaignsData?.data || []
  const items = itemsData?.data || []
  const progress = progressData

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Attestation Campaigns</h1>
          <p className="text-muted-foreground">Certify user access through periodic review campaigns</p>
        </div>
        <Button onClick={() => setShowCreate(!showCreate)}>
          <Plus className="h-4 w-4 mr-2" />{showCreate ? 'Cancel' : 'New Campaign'}
        </Button>
      </div>

      <RelatedLinks
        links={[
          { to: '/access-reviews', label: 'Access Reviews' },
          { to: '/certification-campaigns', label: 'Cert Campaigns' },
        ]}
      />

      {/* Create Form */}
      {showCreate && (
        <Card>
          <CardHeader><CardTitle>New Attestation Campaign</CardTitle></CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-sm font-medium">Campaign Name</label>
                <input className="w-full border rounded px-3 py-2 mt-1 text-sm" value={formName} onChange={e => setFormName(e.target.value)} />
              </div>
              <div>
                <label className="text-sm font-medium">Campaign Type</label>
                <select className="w-full border rounded px-3 py-2 mt-1 text-sm" value={formType} onChange={e => setFormType(e.target.value)}>
                  {Object.entries(typeLabels).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
                </select>
              </div>
              <div>
                <label className="text-sm font-medium">Reviewer Strategy</label>
                <select className="w-full border rounded px-3 py-2 mt-1 text-sm" value={formStrategy} onChange={e => setFormStrategy(e.target.value)}>
                  <option value="manager">Manager</option>
                  <option value="owner">Resource Owner</option>
                  <option value="specific_user">Specific User</option>
                </select>
              </div>
              <div>
                <label className="text-sm font-medium">Escalation After (days)</label>
                <input type="number" className="w-full border rounded px-3 py-2 mt-1 text-sm" value={formEscalation} onChange={e => setFormEscalation(Number(e.target.value))} />
              </div>
            </div>
            <div>
              <label className="text-sm font-medium">Description</label>
              <textarea className="w-full border rounded px-3 py-2 mt-1 text-sm h-16" value={formDesc} onChange={e => setFormDesc(e.target.value)} />
            </div>
            <div className="flex items-center gap-2">
              <input type="checkbox" id="autoRevoke" checked={formAutoRevoke} onChange={e => setFormAutoRevoke(e.target.checked)} />
              <label htmlFor="autoRevoke" className="text-sm">Auto-revoke uncertified access when campaign expires</label>
            </div>
            <Button onClick={handleCreate} disabled={!formName || createMutation.isPending}>
              {createMutation.isPending ? 'Creating...' : 'Create Campaign'}
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Campaign List */}
      <Card>
        <CardHeader><CardTitle className="flex items-center gap-2"><ClipboardCheck className="h-5 w-5" />Campaigns ({campaigns.length})</CardTitle></CardHeader>
        <CardContent>
          <div className="divide-y">
            {campaigns.map(c => {
              const pct = c.total_items > 0 ? ((c.certified_count + c.revoked_count) / c.total_items * 100) : 0
              return (
                <div key={c.id} className="py-3">
                  <div className="flex items-center justify-between">
                    <div className="flex-1 cursor-pointer" onClick={() => setSelectedCampaign(selectedCampaign === c.id ? null : c.id)}>
                      <div className="flex items-center gap-2">
                        <p className="font-medium text-sm">{c.name}</p>
                        <Badge variant="outline">{typeLabels[c.campaign_type] || c.campaign_type}</Badge>
                        <Badge className={statusColors[c.status] || ''}>{c.status}</Badge>
                      </div>
                      <p className="text-xs text-muted-foreground mt-0.5">{c.description}</p>
                      {c.total_items > 0 && (
                        <div className="flex items-center gap-3 mt-2">
                          <div className="flex-1 h-2 bg-muted rounded-full max-w-xs">
                            <div className="h-2 bg-green-500 rounded-full" style={{ width: `${pct}%` }} />
                          </div>
                          <span className="text-xs text-muted-foreground">{pct.toFixed(0)}% complete</span>
                          <span className="text-xs text-green-600">{c.certified_count} certified</span>
                          <span className="text-xs text-red-600">{c.revoked_count} revoked</span>
                          <span className="text-xs text-yellow-600">{c.pending_count} pending</span>
                        </div>
                      )}
                    </div>
                    <div className="flex gap-2 ml-4">
                      {c.status === 'draft' && (
                        <Button size="sm" onClick={() => launchMutation.mutate(c.id)} disabled={launchMutation.isPending}>
                          <Rocket className="h-3 w-3 mr-1" />Launch
                        </Button>
                      )}
                    </div>
                  </div>
                </div>
              )
            })}
            {campaigns.length === 0 && <p className="py-8 text-center text-muted-foreground">No attestation campaigns yet</p>}
          </div>
        </CardContent>
      </Card>

      {/* Campaign Detail */}
      {selectedCampaign && progress && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              <span className="flex items-center gap-2"><BarChart3 className="h-5 w-5" />Campaign Progress</span>
              <Button variant="ghost" size="sm" onClick={() => setSelectedCampaign(null)}><X className="h-4 w-4" /></Button>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-5 gap-4 mb-6">
              <div className="text-center">
                <p className="text-2xl font-bold">{progress.total}</p>
                <p className="text-xs text-muted-foreground">Total</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-green-600">{progress.certified}</p>
                <p className="text-xs text-muted-foreground">Certified</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-red-600">{progress.revoked}</p>
                <p className="text-xs text-muted-foreground">Revoked</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-yellow-600">{progress.pending}</p>
                <p className="text-xs text-muted-foreground">Pending</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-purple-600">{progress.delegated}</p>
                <p className="text-xs text-muted-foreground">Delegated</p>
              </div>
            </div>

            {/* Items table */}
            <div className="divide-y max-h-96 overflow-y-auto">
              {items.map(item => (
                <div key={item.id} className="py-2 flex items-center justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium">{item.user_name}</span>
                      <ArrowRight className="h-3 w-3 text-muted-foreground" />
                      <span className="text-sm">{item.resource_name}</span>
                      <Badge variant="outline" className="text-xs">{item.resource_type}</Badge>
                    </div>
                    {item.reviewer_name && <p className="text-xs text-muted-foreground">Reviewer: {item.reviewer_name}</p>}
                  </div>
                  <div className="flex items-center gap-2">
                    {item.decision === 'pending' ? (
                      <>
                        <Button size="sm" variant="outline"
                          onClick={() => decideMutation.mutate({ campaignId: selectedCampaign, itemId: item.id, decision: 'certified', comments: '' })}>
                          <CheckCircle className="h-3 w-3 mr-1" />Certify
                        </Button>
                        <ConfirmAction
                          title="Revoke this access?"
                          description={`This revokes ${item.user_name}'s access to "${item.resource_name}". The access will be removed as part of this attestation campaign. Provide the reason; it is recorded with the decision and in the audit log.`}
                          destructive
                          requireReason
                          confirmLabel="Revoke"
                          onConfirm={(reason) => decideMutation.mutateAsync({ campaignId: selectedCampaign, itemId: item.id, decision: 'revoked', comments: reason! })}
                        >
                          {(open) => (
                            <Button size="sm" variant="outline" onClick={open}>
                              <X className="h-3 w-3 mr-1" />Revoke
                            </Button>
                          )}
                        </ConfirmAction>
                      </>
                    ) : (
                      <Badge className={decisionColors[item.decision] || ''}>{item.decision}</Badge>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
