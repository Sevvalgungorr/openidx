import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Shield,
  FileCheck,
  Clock,
  Trash2,
  Plus,
  Play,
  AlertTriangle,
  CheckCircle,
} from 'lucide-react'
import { Card, CardContent } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Label } from '../components/ui/label'
import { Textarea } from '../components/ui/textarea'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '../components/ui/dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '../components/ui/select'
import { Switch } from '../components/ui/switch'
import { api } from '../lib/api'
import { ConfirmAction } from '../components/confirm-action'
import { useToast } from '../hooks/use-toast'
import { QueryError } from '../components/query-error'

// --- Interfaces ---

interface Consent {
  id: string
  user_id: string
  username: string
  consent_type: string
  version: string
  granted: boolean
  granted_at: string
  revoked_at: string | null
}

interface DSAR {
  id: string
  user_id: string
  username: string
  request_type: string
  status: string
  reason: string
  due_date: string
  created_at: string
  completed_at: string | null
}

interface RetentionPolicy {
  id: string
  name: string
  data_category: string
  retention_days: number
  action: string
  enabled: boolean
  created_at: string
}

interface ImpactAssessment {
  id: string
  title: string
  description: string
  risk_level: string
  status: string
  assessor: string
  data_categories: string[]
  processing_purposes: string[]
  created_at: string
}

// --- Helpers ---

const tabs = [
  { key: 'consents', label: 'User Consents', icon: Shield },
  { key: 'dsars', label: 'Data Subject Requests', icon: FileCheck },
  { key: 'retention', label: 'Retention Policies', icon: Clock },
  { key: 'assessments', label: 'Impact Assessments', icon: AlertTriangle },
] as const

type TabKey = (typeof tabs)[number]['key']

// A DSAR's user_id is a uuid column server-side, so the create form must submit
// a real UUID (not a username or email) or the backend rejects it. Validate on
// the client so we fail fast with a clear hint instead of a round-trip error.
const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
function isUuid(value: string): boolean {
  return UUID_RE.test(value)
}

function getStatusBadge(status: string) {
  const styles: Record<string, string> = {
    pending: 'bg-yellow-100 text-yellow-800',
    in_progress: 'bg-blue-100 text-blue-800',
    completed: 'bg-green-100 text-green-800',
    rejected: 'bg-red-100 text-red-800',
    draft: 'bg-gray-100 text-gray-800',
    in_review: 'bg-blue-100 text-blue-800',
    approved: 'bg-green-100 text-green-800',
  }
  const labels: Record<string, string> = {
    pending: 'Pending',
    in_progress: 'In Progress',
    completed: 'Completed',
    rejected: 'Rejected',
    draft: 'Draft',
    in_review: 'In Review',
    approved: 'Approved',
  }
  return (
    <Badge className={styles[status] || 'bg-gray-100 text-gray-800'}>
      {labels[status] || status}
    </Badge>
  )
}

function getRiskBadge(level: string) {
  const styles: Record<string, string> = {
    low: 'bg-green-100 text-green-800',
    medium: 'bg-yellow-100 text-yellow-800',
    high: 'bg-orange-100 text-orange-800',
    critical: 'bg-red-100 text-red-800',
  }
  return (
    <Badge className={styles[level] || 'bg-gray-100 text-gray-800'}>
      {level.charAt(0).toUpperCase() + level.slice(1)}
    </Badge>
  )
}

function formatDate(dateStr: string | null): string {
  if (!dateStr) return '-'
  const date = new Date(dateStr)
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  })
}

function formatRequestType(type: string): string {
  const labels: Record<string, string> = {
    export: 'Data Export',
    delete: 'Data Deletion',
    restrict: 'Restrict Processing',
    access: 'Data Access',
    rectify: 'Rectification',
    portability: 'Data Portability',
  }
  return labels[type] || type
}

// --- Tab Components ---

function UserConsentsTab() {
  const [filterType, setFilterType] = useState<string>('all')

  const { data: consentsData, isLoading, isError, error } = useQuery({
    queryKey: ['privacy-consents'],
    queryFn: () => api.get<{ data: Consent[] }>('/api/v1/privacy/consents'),
  })

  const consents = consentsData?.data || []
  const filtered = filterType === 'all'
    ? consents
    : consents.filter((c) => c.consent_type === filterType)

  const consentTypes = Array.from(new Set(consents.map((c) => c.consent_type)))

  if (isLoading) {
    return (
      <div className="flex justify-center py-12">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  if (isError) return <QueryError error={error} resource="user consents" />

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <Label className="text-sm font-medium">Filter by type:</Label>
        <Select value={filterType} onValueChange={setFilterType}>
          <SelectTrigger className="w-48">
            <SelectValue placeholder="All types" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Types</SelectItem>
            {consentTypes.map((type) => (
              <SelectItem key={type} value={type}>
                {type.replace(/_/g, ' ')}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {filtered.length === 0 ? (
        <p className="text-sm text-muted-foreground py-8 text-center">No consent records found</p>
      ) : (
        <div className="overflow-x-auto rounded-md border">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b bg-gray-50">
                <th className="text-left py-3 px-4 font-medium text-gray-500">User</th>
                <th className="text-left py-3 px-4 font-medium text-gray-500">Type</th>
                <th className="text-left py-3 px-4 font-medium text-gray-500">Version</th>
                <th className="text-left py-3 px-4 font-medium text-gray-500">Granted</th>
                <th className="text-left py-3 px-4 font-medium text-gray-500">Granted At</th>
                <th className="text-left py-3 px-4 font-medium text-gray-500">Revoked At</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((consent) => (
                <tr key={consent.id} className="border-b last:border-0 hover:bg-gray-50">
                  <td className="py-3 px-4 font-medium">{consent.username}</td>
                  <td className="py-3 px-4 capitalize">{consent.consent_type.replace(/_/g, ' ')}</td>
                  <td className="py-3 px-4 text-gray-500">{consent.version}</td>
                  <td className="py-3 px-4">
                    <Badge className={consent.granted ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}>
                      {consent.granted ? 'Yes' : 'No'}
                    </Badge>
                  </td>
                  <td className="py-3 px-4 text-gray-500">{formatDate(consent.granted_at)}</td>
                  <td className="py-3 px-4 text-gray-500">{formatDate(consent.revoked_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function DSARsTab() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [showCreate, setShowCreate] = useState(false)
  const [formUserId, setFormUserId] = useState('')
  const [formType, setFormType] = useState('export')
  const [formReason, setFormReason] = useState('')

  const { data: dsarsData, isLoading, isError, error } = useQuery({
    queryKey: ['privacy-dsars'],
    queryFn: () => api.get<{ data: DSAR[] }>('/api/v1/privacy/dsars'),
  })

  const createMutation = useMutation({
    mutationFn: (data: { user_id: string; request_type: string; reason: string }) =>
      api.post('/api/v1/privacy/dsars', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['privacy-dsars'] })
      queryClient.invalidateQueries({ queryKey: ['privacy-dashboard'] })
      setShowCreate(false)
      setFormUserId('')
      setFormType('export')
      setFormReason('')
      toast({ title: 'DSAR created successfully' })
    },
    onError: () => {
      toast({ title: 'Failed to create DSAR', variant: 'destructive' })
    },
  })

  const processMutation = useMutation({
    mutationFn: (id: string) =>
      api.put(`/api/v1/privacy/dsars/${id}`, { status: 'in_progress' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['privacy-dsars'] })
      queryClient.invalidateQueries({ queryKey: ['privacy-dashboard'] })
      toast({ title: 'DSAR status updated to In Progress' })
    },
    onError: () => {
      toast({ title: 'Failed to update DSAR', variant: 'destructive' })
    },
  })

  const executeMutation = useMutation({
    mutationFn: (id: string) =>
      api.post(`/api/v1/privacy/dsars/${id}/execute`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['privacy-dsars'] })
      queryClient.invalidateQueries({ queryKey: ['privacy-dashboard'] })
      toast({ title: 'DSAR executed successfully' })
    },
    onError: () => {
      toast({ title: 'Failed to execute DSAR', variant: 'destructive' })
    },
  })

  const dsars = dsarsData?.data || []

  if (isLoading) {
    return (
      <div className="flex justify-center py-12">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  if (isError) return <QueryError error={error} resource="data subject requests" />

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-medium">Data Subject Access Requests</h3>
        <Button onClick={() => setShowCreate(true)}>
          <Plus className="h-4 w-4 mr-2" />
          Create DSAR
        </Button>
      </div>

      {dsars.length === 0 ? (
        <p className="text-sm text-muted-foreground py-8 text-center">No DSARs found</p>
      ) : (
        <div className="overflow-x-auto rounded-md border">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b bg-gray-50">
                <th className="text-left py-3 px-4 font-medium text-gray-500">ID</th>
                <th className="text-left py-3 px-4 font-medium text-gray-500">User</th>
                <th className="text-left py-3 px-4 font-medium text-gray-500">Type</th>
                <th className="text-left py-3 px-4 font-medium text-gray-500">Status</th>
                <th className="text-left py-3 px-4 font-medium text-gray-500">Due Date</th>
                <th className="text-left py-3 px-4 font-medium text-gray-500">Created</th>
                <th className="text-left py-3 px-4 font-medium text-gray-500">Actions</th>
              </tr>
            </thead>
            <tbody>
              {dsars.map((dsar) => (
                <tr key={dsar.id} className="border-b last:border-0 hover:bg-gray-50">
                  <td className="py-3 px-4 font-mono text-xs">{dsar.id.slice(0, 8)}...</td>
                  <td className="py-3 px-4 font-medium">{dsar.username}</td>
                  <td className="py-3 px-4">{formatRequestType(dsar.request_type)}</td>
                  <td className="py-3 px-4">{getStatusBadge(dsar.status)}</td>
                  <td className="py-3 px-4 text-gray-500">{formatDate(dsar.due_date)}</td>
                  <td className="py-3 px-4 text-gray-500">{formatDate(dsar.created_at)}</td>
                  <td className="py-3 px-4">
                    <div className="flex items-center gap-2">
                      {dsar.status === 'pending' && (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => processMutation.mutate(dsar.id)}
                          disabled={processMutation.isPending}
                        >
                          <Play className="h-3 w-3 mr-1" />
                          Process
                        </Button>
                      )}
                      {dsar.status === 'in_progress' && (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => executeMutation.mutate(dsar.id)}
                          disabled={executeMutation.isPending}
                        >
                          <CheckCircle className="h-3 w-3 mr-1" />
                          Execute
                        </Button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Create DSAR Dialog */}
      <Dialog open={showCreate} onOpenChange={setShowCreate}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create Data Subject Access Request</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="dsar-user-id">User ID</Label>
              <Input
                id="dsar-user-id"
                placeholder="e.g. 00000000-0000-0000-0000-000000000000"
                value={formUserId}
                onChange={(e) => setFormUserId(e.target.value)}
              />
              <p className="text-xs text-muted-foreground">
                The data subject's user UUID. Copy it from the Users page.
              </p>
              {formUserId.trim() !== '' && !isUuid(formUserId.trim()) && (
                <p className="text-xs text-destructive">
                  This must be a user UUID, not a username or email.
                </p>
              )}
            </div>
            <div className="space-y-2">
              <Label htmlFor="dsar-type">Request Type</Label>
              <Select value={formType} onValueChange={setFormType}>
                <SelectTrigger>
                  <SelectValue placeholder="Select type" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="export">Data Export</SelectItem>
                  <SelectItem value="delete">Data Deletion</SelectItem>
                  <SelectItem value="restrict">Restrict Processing</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="dsar-reason">Reason</Label>
              <Textarea
                id="dsar-reason"
                placeholder="Enter reason for the request"
                value={formReason}
                onChange={(e) => setFormReason(e.target.value)}
                rows={3}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowCreate(false)}>
              Cancel
            </Button>
            <Button
              onClick={() =>
                createMutation.mutate({
                  user_id: formUserId,
                  request_type: formType,
                  reason: formReason,
                })
              }
              disabled={!isUuid(formUserId.trim()) || !formReason || createMutation.isPending}
            >
              {createMutation.isPending ? 'Creating...' : 'Create DSAR'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}

function RetentionPoliciesTab() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [showCreate, setShowCreate] = useState(false)
  const [formName, setFormName] = useState('')
  const [formCategory, setFormCategory] = useState('')
  const [formDays, setFormDays] = useState(365)
  const [formAction, setFormAction] = useState('delete')

  const { data: retentionData, isLoading, isError, error } = useQuery({
    queryKey: ['privacy-retention'],
    queryFn: () => api.get<{ data: RetentionPolicy[] }>('/api/v1/privacy/retention'),
  })

  const createMutation = useMutation({
    mutationFn: (data: {
      name: string
      data_category: string
      retention_days: number
      action: string
    }) => api.post('/api/v1/privacy/retention', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['privacy-retention'] })
      setShowCreate(false)
      setFormName('')
      setFormCategory('')
      setFormDays(365)
      setFormAction('delete')
      toast({ title: 'Retention policy created successfully' })
    },
    onError: () => {
      toast({ title: 'Failed to create retention policy', variant: 'destructive' })
    },
  })

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      api.put(`/api/v1/privacy/retention/${id}`, { enabled }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['privacy-retention'] })
      toast({ title: 'Policy updated' })
    },
    onError: () => {
      toast({ title: 'Failed to update policy', variant: 'destructive' })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/privacy/retention/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['privacy-retention'] })
      toast({ title: 'Policy deleted' })
    },
    onError: () => {
      toast({ title: 'Failed to delete policy', variant: 'destructive' })
    },
  })

  const policies = retentionData?.data || []

  if (isLoading) {
    return (
      <div className="flex justify-center py-12">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  if (isError) return <QueryError error={error} resource="retention policies" />

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-medium">Data Retention Policies</h3>
        <Button onClick={() => setShowCreate(true)}>
          <Plus className="h-4 w-4 mr-2" />
          Create Policy
        </Button>
      </div>

      {policies.length === 0 ? (
        <p className="text-sm text-muted-foreground py-8 text-center">No retention policies configured</p>
      ) : (
        <div className="overflow-x-auto rounded-md border">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b bg-gray-50">
                <th className="text-left py-3 px-4 font-medium text-gray-500">Name</th>
                <th className="text-left py-3 px-4 font-medium text-gray-500">Category</th>
                <th className="text-right py-3 px-4 font-medium text-gray-500">Retention (Days)</th>
                <th className="text-left py-3 px-4 font-medium text-gray-500">Action</th>
                <th className="text-center py-3 px-4 font-medium text-gray-500">Enabled</th>
                <th className="text-left py-3 px-4 font-medium text-gray-500">Actions</th>
              </tr>
            </thead>
            <tbody>
              {policies.map((policy) => (
                <tr key={policy.id} className="border-b last:border-0 hover:bg-gray-50">
                  <td className="py-3 px-4 font-medium">{policy.name}</td>
                  <td className="py-3 px-4 capitalize">{policy.data_category.replace(/_/g, ' ')}</td>
                  <td className="py-3 px-4 text-right">{policy.retention_days}</td>
                  <td className="py-3 px-4">
                    <Badge className={policy.action === 'delete' ? 'bg-red-100 text-red-800' : 'bg-blue-100 text-blue-800'}>
                      {policy.action === 'delete' ? 'Delete' : 'Anonymize'}
                    </Badge>
                  </td>
                  <td className="py-3 px-4 text-center">
                    <Switch
                      checked={policy.enabled}
                      onCheckedChange={(checked) =>
                        toggleMutation.mutate({ id: policy.id, enabled: checked })
                      }
                    />
                  </td>
                  <td className="py-3 px-4">
                    <ConfirmAction
                      title="Delete this retention policy?"
                      description={`This removes the retention policy ${policy.name}. Data in the ${policy.data_category} category will no longer be governed by it.`}
                      destructive
                      confirmLabel="Delete"
                      onConfirm={() => deleteMutation.mutateAsync(policy.id)}
                    >
                      {(open) => (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={open}
                          disabled={deleteMutation.isPending}
                        >
                          <Trash2 className="h-4 w-4 text-red-500" />
                        </Button>
                      )}
                    </ConfirmAction>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Create Policy Dialog */}
      <Dialog open={showCreate} onOpenChange={setShowCreate}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create Retention Policy</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="retention-name">Policy Name</Label>
              <Input
                id="retention-name"
                placeholder="e.g., Audit Log Retention"
                value={formName}
                onChange={(e) => setFormName(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="retention-category">Data Category</Label>
              <Input
                id="retention-category"
                placeholder="e.g., audit_logs, session_data, user_profiles"
                value={formCategory}
                onChange={(e) => setFormCategory(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="retention-days">Retention Period (Days)</Label>
              <Input
                id="retention-days"
                type="number"
                min={1}
                value={formDays}
                onChange={(e) => setFormDays(parseInt(e.target.value) || 365)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="retention-action">Action</Label>
              <Select value={formAction} onValueChange={setFormAction}>
                <SelectTrigger>
                  <SelectValue placeholder="Select action" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="delete">Delete</SelectItem>
                  <SelectItem value="anonymize">Anonymize</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowCreate(false)}>
              Cancel
            </Button>
            <Button
              onClick={() =>
                createMutation.mutate({
                  name: formName,
                  data_category: formCategory,
                  retention_days: formDays,
                  action: formAction,
                })
              }
              disabled={!formName || !formCategory || createMutation.isPending}
            >
              {createMutation.isPending ? 'Creating...' : 'Create Policy'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}

function ImpactAssessmentsTab() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [showCreate, setShowCreate] = useState(false)
  const [formTitle, setFormTitle] = useState('')
  const [formDescription, setFormDescription] = useState('')
  const [formRiskLevel, setFormRiskLevel] = useState('medium')
  const [formCategories, setFormCategories] = useState('')
  const [formPurposes, setFormPurposes] = useState('')

  const { data: assessmentsData, isLoading, isError, error } = useQuery({
    queryKey: ['privacy-assessments'],
    queryFn: () => api.get<{ data: ImpactAssessment[] }>('/api/v1/privacy/assessments'),
  })

  const createMutation = useMutation({
    mutationFn: (data: {
      title: string
      description: string
      risk_level: string
      data_categories: string[]
      processing_purposes: string[]
    }) => api.post('/api/v1/privacy/assessments', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['privacy-assessments'] })
      setShowCreate(false)
      setFormTitle('')
      setFormDescription('')
      setFormRiskLevel('medium')
      setFormCategories('')
      setFormPurposes('')
      toast({ title: 'Impact assessment created successfully' })
    },
    onError: () => {
      toast({ title: 'Failed to create assessment', variant: 'destructive' })
    },
  })

  const assessments = assessmentsData?.data || []

  if (isLoading) {
    return (
      <div className="flex justify-center py-12">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  if (isError) return <QueryError error={error} resource="impact assessments" />

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-medium">Data Protection Impact Assessments</h3>
        <Button onClick={() => setShowCreate(true)}>
          <Plus className="h-4 w-4 mr-2" />
          Create Assessment
        </Button>
      </div>

      {assessments.length === 0 ? (
        <p className="text-sm text-muted-foreground py-8 text-center">No impact assessments found</p>
      ) : (
        <div className="overflow-x-auto rounded-md border">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b bg-gray-50">
                <th className="text-left py-3 px-4 font-medium text-gray-500">Title</th>
                <th className="text-left py-3 px-4 font-medium text-gray-500">Risk Level</th>
                <th className="text-left py-3 px-4 font-medium text-gray-500">Status</th>
                <th className="text-left py-3 px-4 font-medium text-gray-500">Assessor</th>
                <th className="text-left py-3 px-4 font-medium text-gray-500">Created</th>
              </tr>
            </thead>
            <tbody>
              {assessments.map((assessment) => (
                <tr key={assessment.id} className="border-b last:border-0 hover:bg-gray-50">
                  <td className="py-3 px-4">
                    <div>
                      <p className="font-medium">{assessment.title}</p>
                      <p className="text-xs text-gray-400 mt-0.5 line-clamp-1">
                        {assessment.description}
                      </p>
                    </div>
                  </td>
                  <td className="py-3 px-4">{getRiskBadge(assessment.risk_level)}</td>
                  <td className="py-3 px-4">{getStatusBadge(assessment.status)}</td>
                  <td className="py-3 px-4 text-gray-600">{assessment.assessor}</td>
                  <td className="py-3 px-4 text-gray-500">{formatDate(assessment.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Create Assessment Dialog */}
      <Dialog open={showCreate} onOpenChange={setShowCreate}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Create Impact Assessment</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="assessment-title">Title</Label>
              <Input
                id="assessment-title"
                placeholder="e.g., User Analytics Processing Assessment"
                value={formTitle}
                onChange={(e) => setFormTitle(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="assessment-description">Description</Label>
              <Textarea
                id="assessment-description"
                placeholder="Describe the processing activity being assessed"
                value={formDescription}
                onChange={(e) => setFormDescription(e.target.value)}
                rows={3}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="assessment-risk">Risk Level</Label>
              <Select value={formRiskLevel} onValueChange={setFormRiskLevel}>
                <SelectTrigger>
                  <SelectValue placeholder="Select risk level" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="low">Low</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="critical">Critical</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="assessment-categories">Data Categories (comma-separated)</Label>
              <Input
                id="assessment-categories"
                placeholder="e.g., personal_data, behavioral_data, financial_data"
                value={formCategories}
                onChange={(e) => setFormCategories(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="assessment-purposes">Processing Purposes (comma-separated)</Label>
              <Input
                id="assessment-purposes"
                placeholder="e.g., analytics, fraud_detection, personalization"
                value={formPurposes}
                onChange={(e) => setFormPurposes(e.target.value)}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowCreate(false)}>
              Cancel
            </Button>
            <Button
              onClick={() =>
                createMutation.mutate({
                  title: formTitle,
                  description: formDescription,
                  risk_level: formRiskLevel,
                  data_categories: formCategories
                    .split(',')
                    .map((s) => s.trim())
                    .filter(Boolean),
                  processing_purposes: formPurposes
                    .split(',')
                    .map((s) => s.trim())
                    .filter(Boolean),
                })
              }
              disabled={!formTitle || !formDescription || createMutation.isPending}
            >
              {createMutation.isPending ? 'Creating...' : 'Create Assessment'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}

// --- Main Page ---

export function ConsentManagementPage() {
  const [activeTab, setActiveTab] = useState<TabKey>('consents')

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Consent Management</h1>
        <p className="text-muted-foreground">
          Manage user consents, data subject requests, retention policies, and impact assessments
        </p>
      </div>

      {/* Tab Navigation */}
      <div className="border-b">
        <nav className="flex gap-4" aria-label="Tabs">
          {tabs.map((tab) => {
            const Icon = tab.icon
            return (
              <button
                key={tab.key}
                onClick={() => setActiveTab(tab.key)}
                className={`flex items-center gap-2 py-3 px-1 border-b-2 text-sm font-medium transition-colors ${
                  activeTab === tab.key
                    ? 'border-blue-600 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                <Icon className="h-4 w-4" />
                {tab.label}
              </button>
            )
          })}
        </nav>
      </div>

      {/* Tab Content */}
      <Card>
        <CardContent className="pt-6">
          {activeTab === 'consents' && <UserConsentsTab />}
          {activeTab === 'dsars' && <DSARsTab />}
          {activeTab === 'retention' && <RetentionPoliciesTab />}
          {activeTab === 'assessments' && <ImpactAssessmentsTab />}
        </CardContent>
      </Card>
    </div>
  )
}
