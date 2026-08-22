import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Shield, Key, Smartphone, Mail, Fingerprint, Plus, Edit2, Trash2, CheckCircle2, XCircle, Users } from 'lucide-react'
import { Card, CardContent } from '../components/ui/card'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Badge } from '../components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table'
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '../components/ui/dialog'
import { Switch } from '../components/ui/switch'
import { Label } from '../components/ui/label'
import { Checkbox } from '../components/ui/checkbox'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { ConfirmAction } from '../components/confirm-action'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

interface EnrollmentStats {
  total_users: number
  mfa_enabled_count: number
  totp_count: number
  sms_count: number
  email_otp_count: number
  push_count: number
  webauthn_count: number
}

interface MFAPolicy {
  id: string
  name: string
  description: string
  enabled: boolean
  priority: number
  conditions: Record<string, unknown>
  required_methods: string[]
  grace_period_hours: number
  created_at: string
  updated_at: string
}

interface UserMFAStatus {
  user_id: string
  username: string
  email: string
  totp_enabled: boolean
  sms_enabled: boolean
  email_otp_enabled: boolean
  push_enabled: boolean
  webauthn_enabled: boolean
}

const emptyPolicy: Partial<MFAPolicy> = {
  name: '',
  description: '',
  enabled: true,
  priority: 100,
  conditions: {},
  required_methods: [],
  grace_period_hours: 24,
}

const methodLabels: Record<string, string> = {
  totp: 'TOTP',
  sms: 'SMS',
  email: 'Email OTP',
  push: 'Push',
  webauthn: 'WebAuthn',
}

export default function MFAManagement() {
  const { toast } = useToast()
  const queryClient = useQueryClient()

  // Policy dialog state
  const [policyDialogOpen, setPolicyDialogOpen] = useState(false)
  const [selectedPolicy, setSelectedPolicy] = useState<MFAPolicy | null>(null)
  const [formData, setFormData] = useState<Partial<MFAPolicy>>(emptyPolicy)


  // Pagination state for policies and users
  const [policyPage, setPolicyPage] = useState(1)
  const [userPage, setUserPage] = useState(1)
  const pageSize = 20

  // Fetch enrollment stats
  const { data: statsData, isLoading: statsLoading, isError: statsIsError, error: statsError } = useQuery({
    queryKey: ['mfa-enrollment-stats'],
    queryFn: () => api.get<EnrollmentStats>('/api/v1/mfa/enrollment-stats'),
  })

  const stats: EnrollmentStats = statsData || {
    total_users: 0,
    mfa_enabled_count: 0,
    totp_count: 0,
    sms_count: 0,
    email_otp_count: 0,
    push_count: 0,
    webauthn_count: 0,
  }

  const mfaPercentage = stats.total_users > 0
    ? Math.round((stats.mfa_enabled_count / stats.total_users) * 100)
    : 0

  // Fetch policies
  const { data: policiesData, isLoading: policiesLoading, isError: policiesIsError, error: policiesError } = useQuery({
    queryKey: ['mfa-policies', policyPage],
    queryFn: () =>
      api.get<{ policies: MFAPolicy[]; total: number; page: number; page_size: number }>(
        `/api/v1/mfa/policies?page=${policyPage}&page_size=${pageSize}`
      ),
  })

  const policies = policiesData?.policies || []
  const policiesTotalPages = Math.ceil((policiesData?.total || 0) / pageSize)

  // Fetch user MFA status
  const { data: usersData, isLoading: usersLoading, isError: usersIsError, error: usersError } = useQuery({
    queryKey: ['mfa-user-status', userPage],
    queryFn: () =>
      api.get<{ users: UserMFAStatus[]; total: number; page: number; page_size: number }>(
        `/api/v1/mfa/user-status?page=${userPage}&page_size=${pageSize}`
      ),
  })

  const users = usersData?.users || []
  const usersTotalPages = Math.ceil((usersData?.total || 0) / pageSize)

  // Mutations
  const createPolicyMutation = useMutation({
    mutationFn: (data: Partial<MFAPolicy>) => api.post('/api/v1/mfa/policies', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['mfa-policies'] })
      toast({ title: 'Success', description: 'MFA policy has been created.' })
      setPolicyDialogOpen(false)
      setFormData(emptyPolicy)
    },
    onError: (error: Error) => {
      toast({ variant: 'destructive', title: 'Error', description: error.message })
    },
  })

  const updatePolicyMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<MFAPolicy> }) =>
      api.put(`/api/v1/mfa/policies/${id}`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['mfa-policies'] })
      toast({ title: 'Success', description: 'MFA policy has been updated.' })
      setPolicyDialogOpen(false)
    },
    onError: (error: Error) => {
      toast({ variant: 'destructive', title: 'Error', description: error.message })
    },
  })

  const deletePolicyMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/mfa/policies/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['mfa-policies'] })
      toast({ title: 'Success', description: 'MFA policy has been deleted.' })
    },
    onError: (error: Error) => {
      toast({ variant: 'destructive', title: 'Error', description: error.message })
    },
  })

  const openCreatePolicy = () => {
    setSelectedPolicy(null)
    setFormData(emptyPolicy)
    setPolicyDialogOpen(true)
  }

  const openEditPolicy = (policy: MFAPolicy) => {
    setSelectedPolicy(policy)
    setFormData({
      name: policy.name,
      description: policy.description,
      enabled: policy.enabled,
      priority: policy.priority,
      conditions: policy.conditions,
      required_methods: [...policy.required_methods],
      grace_period_hours: policy.grace_period_hours,
    })
    setPolicyDialogOpen(true)
  }


  const handleSavePolicy = () => {
    if (selectedPolicy) {
      updatePolicyMutation.mutate({ id: selectedPolicy.id, data: formData })
    } else {
      createPolicyMutation.mutate(formData)
    }
  }

  const toggleMethod = (method: string, checked: boolean) => {
    const current = formData.required_methods || []
    const updated = checked
      ? [...current, method]
      : current.filter((m) => m !== method)
    setFormData({ ...formData, required_methods: updated })
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">MFA Management</h1>
        <p className="text-muted-foreground">Manage multi-factor authentication enrollment, policies, and user status</p>
      </div>

      <Tabs defaultValue="enrollment">
        <TabsList>
          <TabsTrigger value="enrollment">
            <Shield className="mr-2 h-4 w-4" />
            Enrollment Overview
          </TabsTrigger>
          <TabsTrigger value="policies">
            <Key className="mr-2 h-4 w-4" />
            MFA Policies
          </TabsTrigger>
          <TabsTrigger value="users">
            <Users className="mr-2 h-4 w-4" />
            User MFA Status
          </TabsTrigger>
        </TabsList>

        {/* Tab 1: Enrollment Overview */}
        <TabsContent value="enrollment">
          {statsLoading ? (
            <div className="flex flex-col items-center justify-center py-12">
              <LoadingSpinner size="lg" />
              <p className="mt-4 text-sm text-muted-foreground">Loading enrollment stats...</p>
            </div>
          ) : statsIsError ? (
            <QueryError error={statsError} resource="enrollment stats" />
          ) : (
            <div className="grid gap-4 md:grid-cols-4">
              <Card>
                <CardContent className="pt-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="text-2xl font-bold">{stats.total_users}</div>
                      <p className="text-xs text-muted-foreground">Total Users</p>
                    </div>
                    <Users className="h-8 w-8 text-muted-foreground" />
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="pt-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="text-2xl font-bold">{stats.mfa_enabled_count}</div>
                      <p className="text-xs text-muted-foreground">MFA Enabled ({mfaPercentage}%)</p>
                    </div>
                    <Shield className="h-8 w-8 text-green-500" />
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="pt-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="text-2xl font-bold">{stats.totp_count}</div>
                      <p className="text-xs text-muted-foreground">TOTP Enrolled</p>
                    </div>
                    <Key className="h-8 w-8 text-blue-500" />
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="pt-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="text-2xl font-bold">{stats.sms_count}</div>
                      <p className="text-xs text-muted-foreground">SMS Enrolled</p>
                    </div>
                    <Smartphone className="h-8 w-8 text-purple-500" />
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="pt-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="text-2xl font-bold">{stats.email_otp_count}</div>
                      <p className="text-xs text-muted-foreground">Email OTP Enrolled</p>
                    </div>
                    <Mail className="h-8 w-8 text-orange-500" />
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="pt-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="text-2xl font-bold">{stats.push_count}</div>
                      <p className="text-xs text-muted-foreground">Push Enrolled</p>
                    </div>
                    <Smartphone className="h-8 w-8 text-teal-500" />
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="pt-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="text-2xl font-bold">{stats.webauthn_count}</div>
                      <p className="text-xs text-muted-foreground">WebAuthn Enrolled</p>
                    </div>
                    <Fingerprint className="h-8 w-8 text-indigo-500" />
                  </div>
                </CardContent>
              </Card>
            </div>
          )}
        </TabsContent>

        {/* Tab 2: MFA Policies */}
        <TabsContent value="policies">
          <Card>
            <div className="flex items-center justify-between p-6 pb-0">
              <h2 className="text-lg font-semibold">MFA Policies</h2>
              <Button onClick={openCreatePolicy}>
                <Plus className="mr-2 h-4 w-4" />
                Create Policy
              </Button>
            </div>
            <CardContent className="pt-6">
              {policiesLoading ? (
                <div className="flex flex-col items-center justify-center py-12">
                  <LoadingSpinner size="lg" />
                  <p className="mt-4 text-sm text-muted-foreground">Loading policies...</p>
                </div>
              ) : policiesIsError ? (
                <QueryError error={policiesError} resource="MFA policies" />
              ) : policies.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                  <Key className="h-12 w-12 text-muted-foreground/40 mb-3" />
                  <p className="font-medium">No MFA policies configured</p>
                  <p className="text-sm">Create a policy to enforce multi-factor authentication</p>
                </div>
              ) : (
                <>
                  <div className="rounded-md border">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Name</TableHead>
                          <TableHead>Description</TableHead>
                          <TableHead>Required Methods</TableHead>
                          <TableHead>Grace Period</TableHead>
                          <TableHead>Priority</TableHead>
                          <TableHead>Enabled</TableHead>
                          <TableHead className="w-[100px]">Actions</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {policies.map((policy) => (
                          <TableRow key={policy.id}>
                            <TableCell className="font-medium">{policy.name}</TableCell>
                            <TableCell className="text-sm text-muted-foreground max-w-[200px] truncate">
                              {policy.description}
                            </TableCell>
                            <TableCell>
                              <div className="flex flex-wrap gap-1">
                                {policy.required_methods.map((method) => (
                                  <Badge key={method} variant="outline">
                                    {methodLabels[method] || method}
                                  </Badge>
                                ))}
                              </div>
                            </TableCell>
                            <TableCell>{policy.grace_period_hours}h</TableCell>
                            <TableCell>
                              <span className="text-xs font-mono bg-muted px-2 py-1 rounded">
                                #{policy.priority}
                              </span>
                            </TableCell>
                            <TableCell>
                              <Switch
                                checked={policy.enabled}
                                onCheckedChange={(checked) => {
                                  updatePolicyMutation.mutate({
                                    id: policy.id,
                                    data: { ...policy, enabled: checked },
                                  })
                                }}
                              />
                            </TableCell>
                            <TableCell>
                              <div className="flex items-center gap-1">
                                <Button variant="ghost" size="icon" onClick={() => openEditPolicy(policy)}>
                                  <Edit2 className="h-4 w-4" />
                                </Button>
                                <ConfirmAction
                                  title="Delete MFA Policy"
                                  description={`Are you sure you want to delete the MFA policy ${policy.name}? This action cannot be undone.`}
                                  destructive
                                  confirmLabel="Delete"
                                  onConfirm={() => deletePolicyMutation.mutateAsync(policy.id)}
                                >
                                  {(open) => (
                                    <Button variant="ghost" size="icon" onClick={open}>
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
                  {policiesTotalPages > 1 && (
                    <div className="flex items-center justify-between pt-4">
                      <p className="text-sm text-muted-foreground">
                        Page {policyPage} of {policiesTotalPages}
                      </p>
                      <div className="flex gap-2">
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={policyPage <= 1}
                          onClick={() => setPolicyPage((p) => p - 1)}
                        >
                          Previous
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={policyPage >= policiesTotalPages}
                          onClick={() => setPolicyPage((p) => p + 1)}
                        >
                          Next
                        </Button>
                      </div>
                    </div>
                  )}
                </>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Tab 3: User MFA Status */}
        <TabsContent value="users">
          <Card>
            <CardContent className="pt-6">
              {usersLoading ? (
                <div className="flex flex-col items-center justify-center py-12">
                  <LoadingSpinner size="lg" />
                  <p className="mt-4 text-sm text-muted-foreground">Loading user MFA status...</p>
                </div>
              ) : usersIsError ? (
                <QueryError error={usersError} resource="user MFA status" />
              ) : users.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                  <Users className="h-12 w-12 text-muted-foreground/40 mb-3" />
                  <p className="font-medium">No users found</p>
                  <p className="text-sm">User MFA enrollment status will appear here</p>
                </div>
              ) : (
                <>
                  <div className="rounded-md border">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Username</TableHead>
                          <TableHead>Email</TableHead>
                          <TableHead className="text-center">TOTP</TableHead>
                          <TableHead className="text-center">SMS</TableHead>
                          <TableHead className="text-center">Email OTP</TableHead>
                          <TableHead className="text-center">Push</TableHead>
                          <TableHead className="text-center">WebAuthn</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {users.map((user) => (
                          <TableRow key={user.user_id}>
                            <TableCell className="font-medium">{user.username}</TableCell>
                            <TableCell className="text-sm text-muted-foreground">{user.email}</TableCell>
                            <TableCell className="text-center">
                              {user.totp_enabled ? (
                                <CheckCircle2 className="h-5 w-5 text-green-500 mx-auto" />
                              ) : (
                                <XCircle className="h-5 w-5 text-muted-foreground mx-auto" />
                              )}
                            </TableCell>
                            <TableCell className="text-center">
                              {user.sms_enabled ? (
                                <CheckCircle2 className="h-5 w-5 text-green-500 mx-auto" />
                              ) : (
                                <XCircle className="h-5 w-5 text-muted-foreground mx-auto" />
                              )}
                            </TableCell>
                            <TableCell className="text-center">
                              {user.email_otp_enabled ? (
                                <CheckCircle2 className="h-5 w-5 text-green-500 mx-auto" />
                              ) : (
                                <XCircle className="h-5 w-5 text-muted-foreground mx-auto" />
                              )}
                            </TableCell>
                            <TableCell className="text-center">
                              {user.push_enabled ? (
                                <CheckCircle2 className="h-5 w-5 text-green-500 mx-auto" />
                              ) : (
                                <XCircle className="h-5 w-5 text-muted-foreground mx-auto" />
                              )}
                            </TableCell>
                            <TableCell className="text-center">
                              {user.webauthn_enabled ? (
                                <CheckCircle2 className="h-5 w-5 text-green-500 mx-auto" />
                              ) : (
                                <XCircle className="h-5 w-5 text-muted-foreground mx-auto" />
                              )}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                  {usersTotalPages > 1 && (
                    <div className="flex items-center justify-between pt-4">
                      <p className="text-sm text-muted-foreground">
                        Page {userPage} of {usersTotalPages}
                      </p>
                      <div className="flex gap-2">
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={userPage <= 1}
                          onClick={() => setUserPage((p) => p - 1)}
                        >
                          Previous
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={userPage >= usersTotalPages}
                          onClick={() => setUserPage((p) => p + 1)}
                        >
                          Next
                        </Button>
                      </div>
                    </div>
                  )}
                </>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Create/Edit Policy Dialog */}
      <Dialog open={policyDialogOpen} onOpenChange={setPolicyDialogOpen}>
        <DialogContent className="max-w-lg max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{selectedPolicy ? 'Edit MFA Policy' : 'Create MFA Policy'}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Policy Name *</Label>
              <Input
                value={formData.name || ''}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                placeholder="e.g., Enforce TOTP for All Users"
              />
            </div>
            <div className="space-y-2">
              <Label>Description</Label>
              <Input
                value={formData.description || ''}
                onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                placeholder="What does this policy enforce?"
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Priority (lower = first)</Label>
                <Input
                  type="number"
                  value={formData.priority ?? 100}
                  onChange={(e) => setFormData({ ...formData, priority: parseInt(e.target.value) || 0 })}
                />
              </div>
              <div className="space-y-2">
                <Label>Grace Period (hours)</Label>
                <Input
                  type="number"
                  value={formData.grace_period_hours ?? 24}
                  onChange={(e) => setFormData({ ...formData, grace_period_hours: parseInt(e.target.value) || 0 })}
                />
              </div>
            </div>
            <div className="space-y-2">
              <Label>Required Methods</Label>
              <div className="grid grid-cols-2 gap-3 pt-1">
                {Object.entries(methodLabels).map(([method, label]) => (
                  <div key={method} className="flex items-center space-x-2">
                    <Checkbox
                      id={`method-${method}`}
                      checked={(formData.required_methods || []).includes(method)}
                      onCheckedChange={(checked) => toggleMethod(method, checked === true)}
                    />
                    <label htmlFor={`method-${method}`} className="text-sm">
                      {label}
                    </label>
                  </div>
                ))}
              </div>
            </div>
            <div className="flex items-center space-x-2">
              <Switch
                id="policy-enabled"
                checked={formData.enabled ?? true}
                onCheckedChange={(checked) => setFormData({ ...formData, enabled: checked })}
              />
              <Label htmlFor="policy-enabled">Enabled</Label>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setPolicyDialogOpen(false)}>Cancel</Button>
            <Button
              onClick={handleSavePolicy}
              disabled={!formData.name || createPolicyMutation.isPending || updatePolicyMutation.isPending}
            >
              {createPolicyMutation.isPending || updatePolicyMutation.isPending
                ? 'Saving...'
                : selectedPolicy
                  ? 'Update Policy'
                  : 'Create Policy'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

    </div>
  )
}
