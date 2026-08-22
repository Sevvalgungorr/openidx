import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Search, MoreHorizontal, Globe, Smartphone, Server, ExternalLink, Edit, Trash2, Settings, Copy, RefreshCw, ChevronLeft, ChevronRight, AppWindow } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '../components/ui/dropdown-menu'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '../components/ui/dialog'
import { Label } from '../components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '../components/ui/alert-dialog'
import { useToast } from '../hooks/use-toast'

interface Application {
  id: string
  client_id: string
  name: string
  description: string
  type: string
  protocol: string
  base_url: string
  redirect_uris: string[]
  enabled: boolean
  pkce_required?: boolean
  created_at: string
  updated_at: string
}

const typeIcons: Record<string, React.ReactNode> = {
  web: <Globe className="h-5 w-5 text-blue-700" />,
  native: <Smartphone className="h-5 w-5 text-green-700" />,
  service: <Server className="h-5 w-5 text-orange-700" />,
}

const typeColors: Record<string, string> = {
  web: 'bg-blue-100',
  native: 'bg-green-100',
  service: 'bg-orange-100',
}

export function ApplicationsPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [search, setSearch] = useState('')
  const [registerAppModal, setRegisterAppModal] = useState(false)
  const [editAppModal, setEditAppModal] = useState(false)
  const [ssoSettingsModal, setSsoSettingsModal] = useState(false)
  const [selectedApp, setSelectedApp] = useState<Application | null>(null)
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    type: 'web',
    base_url: '',
    redirect_uris: '',
    grant_types: 'authorization_code,refresh_token',
    scopes: 'openid,profile,email,offline_access',
    pkce_required: true,
  })
  const [regenerateModal, setRegenerateModal] = useState(false)
  const [regenerateApp, setRegenerateApp] = useState<Application | null>(null)
  const [newSecret, setNewSecret] = useState<string | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<{id: string, name: string} | null>(null)
  const [page, setPage] = useState(0)
  const [totalCount, setTotalCount] = useState(0)
  const PAGE_SIZE = 20

  const [ssoSettings, setSsoSettings] = useState({
    enabled: true,
    refreshToken: true,
    accessTokenLifetime: '3600',
    refreshTokenLifetime: '86400',
    consentRequired: false,
  })

  const { data: applications, isLoading, isError, error } = useQuery({
    queryKey: ['applications', page, search],
    queryFn: async () => {
      const params = new URLSearchParams()
      params.set('offset', String(page * PAGE_SIZE))
      params.set('limit', String(PAGE_SIZE))
      if (search) params.set('search', search)
      const result = await api.getWithHeaders<Application[]>(`/api/v1/applications?${params.toString()}`)
      const total = parseInt(result.headers['x-total-count'] || '0', 10)
      if (!isNaN(total)) setTotalCount(total)
      return result.data
    },
  })

  // Create OAuth client mutation
  const createClientMutation = useMutation({
    mutationFn: (clientData: any) =>
      api.post('/api/v1/oauth/clients', clientData),
    onSuccess: (data: any) => {
      queryClient.invalidateQueries({ queryKey: ['applications'] })
      toast({
        title: 'Success',
        description: `OAuth client created! Client ID: ${data.client_id}`,
        variant: 'success',
      })
      setRegisterAppModal(false)
      setFormData({
        name: '',
        description: '',
        type: 'web',
        base_url: '',
        redirect_uris: '',
        grant_types: 'authorization_code,refresh_token',
        scopes: 'openid,profile,email,offline_access',
        pkce_required: true,
      })
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: `Failed to create OAuth client: ${error.message}`,
        variant: 'destructive',
      })
    },
  })

  // Update application mutation
  const updateApplicationMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<Application> }) =>
      api.put(`/api/v1/applications/${id}`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['applications'] })
      toast({
        title: 'Success',
        description: 'Application updated successfully!',
        variant: 'success',
      })
      setEditAppModal(false)
      setSelectedApp(null)
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: `Failed to update application: ${error.message}`,
        variant: 'destructive',
      })
    },
  })

  // Regenerate client secret mutation
  const regenerateSecretMutation = useMutation({
    mutationFn: (clientId: string) =>
      api.post<{ client_secret: string }>(`/api/v1/oauth/clients/${clientId}/regenerate-secret`),
    onSuccess: (data: { client_secret: string }) => {
      setNewSecret(data.client_secret)
      toast({
        title: 'Success',
        description: 'Client secret regenerated successfully!',
        variant: 'success',
      })
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: `Failed to regenerate secret: ${error.message}`,
        variant: 'destructive',
      })
    },
  })

  // Delete application mutation
  const deleteApplicationMutation = useMutation({
    mutationFn: (appId: string) =>
      api.delete(`/api/v1/applications/${appId}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['applications'] })
      toast({
        title: 'Success',
        description: 'Application deleted successfully!',
        variant: 'success',
      })
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: `Failed to delete application: ${error.message}`,
        variant: 'destructive',
      })
    },
  })

  // Applications are filtered server-side via search param
  const filteredApps = applications

  const handleEditApp = (app: Application) => {
    setSelectedApp(app)
    setFormData({
      name: app.name,
      description: app.description || '',
      type: app.type || 'web',
      base_url: app.base_url || '',
      redirect_uris: app.redirect_uris?.join('\n') || '',
      grant_types: 'authorization_code,refresh_token',
      scopes: 'openid,profile,email,offline_access',
      pkce_required: app.pkce_required ?? true,
    })
    setEditAppModal(true)
  }

  const handleCopyClientId = (clientId: string) => {
    navigator.clipboard.writeText(clientId)
    toast({
      title: 'Success',
      description: 'Client ID copied to clipboard!',
      variant: 'success',
    })
  }

  const handleSsoSettings = (app: Application) => {
    setSelectedApp(app)
    setSsoSettingsModal(true)
  }

  // Query to fetch SSO settings for the selected application
  const ssoSettingsQuery = useQuery({
    queryKey: ['sso-settings', selectedApp?.id],
    queryFn: () => selectedApp ? api.get(`/api/v1/applications/${selectedApp.id}/sso-settings`) : null,
    enabled: !!selectedApp && ssoSettingsModal, // Fetch when modal is open and app is selected
  })

  // Initialize SSO settings form when data is loaded
  React.useEffect(() => {
    if (ssoSettingsQuery.data && typeof ssoSettingsQuery.data === 'object') {
      const data = ssoSettingsQuery.data as any
      setSsoSettings({
        enabled: data.enabled ?? true,
        refreshToken: data.use_refresh_tokens ?? true,
        accessTokenLifetime: data.access_token_lifetime?.toString() ?? '3600',
        refreshTokenLifetime: data.refresh_token_lifetime?.toString() ?? '86400',
        consentRequired: data.require_consent ?? false,
      })
    }
  }, [ssoSettingsQuery.data])

  // Reset form when modal closes
  React.useEffect(() => {
    if (!ssoSettingsModal) {
      setSsoSettings({
        enabled: true,
        refreshToken: true,
        accessTokenLifetime: '3600',
        refreshTokenLifetime: '86400',
        consentRequired: false,
      })
      setSelectedApp(null)
    }
  }, [ssoSettingsModal])

  const handleDeleteApp = (appId: string, appName: string) => {
    setDeleteTarget({ id: appId, name: appName })
  }

  const handleRegisterSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    createClientMutation.mutate({
      name: formData.name,
      description: formData.description,
      type: formData.type,
      redirect_uris: formData.redirect_uris.split('\n').filter(uri => uri.trim()),
      grant_types: formData.grant_types.split(',').map(g => g.trim()),
      response_types: ['code'],
      scopes: formData.scopes.split(',').map(s => s.trim()),
      pkce_required: formData.pkce_required,
      allow_refresh_token: true,
      access_token_lifetime: 3600,
      refresh_token_lifetime: 86400,
    })
  }

  const handleFormSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (selectedApp) {
      updateApplicationMutation.mutate({
        id: selectedApp.id,
        data: {
          name: formData.name,
          description: formData.description,
          base_url: formData.base_url,
          redirect_uris: formData.redirect_uris.split('\n').filter(uri => uri.trim()),
          pkce_required: formData.pkce_required,
        },
      })
    }
  }

  const handleSsoSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (selectedApp) {
      updateSSOSettingsMutation.mutate({
        applicationId: selectedApp.id,
        enabled: ssoSettings.enabled,
        useRefreshTokens: ssoSettings.refreshToken,
        accessTokenLifetime: parseInt(ssoSettings.accessTokenLifetime),
        refreshTokenLifetime: parseInt(ssoSettings.refreshTokenLifetime),
        requireConsent: ssoSettings.consentRequired,
      })
    }
  }

  // Update SSO settings mutation
  const updateSSOSettingsMutation = useMutation({
    mutationFn: (settings: any) =>
      api.put(`/api/v1/applications/${settings.applicationId}/sso-settings`, {
        enabled: settings.enabled,
        use_refresh_tokens: settings.useRefreshTokens,
        access_token_lifetime: settings.accessTokenLifetime,
        refresh_token_lifetime: settings.refreshTokenLifetime,
        require_consent: settings.requireConsent,
      }),
    onSuccess: () => {
      // Invalidate the SSO settings query to refresh the data
      queryClient.invalidateQueries({
        queryKey: ['sso-settings', selectedApp?.id]
      })
      toast({
        title: 'Success',
        description: `SSO settings updated for "${selectedApp?.name}"`,
        variant: 'success',
      })
      setSsoSettingsModal(false)
      setSelectedApp(null)
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: `Failed to update SSO settings: ${error.message}`,
        variant: 'destructive',
      })
    },
  })

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    setFormData(prev => ({ ...prev, [e.target.name]: e.target.value }))
  }

  const handleSsoChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value, type, checked } = e.target
    setSsoSettings(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }))
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Applications</h1>
          <p className="text-muted-foreground">Manage registered applications and SSO configurations</p>
        </div>
        <Button onClick={() => setRegisterAppModal(true)}>
          <Plus className="mr-2 h-4 w-4" /> Register Application
        </Button>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" />
              <Input
                placeholder="Search applications..."
                value={search}
                onChange={(e) => { setSearch(e.target.value); setPage(0) }}
                className="pl-9"
              />
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex flex-col items-center justify-center py-12">
              <LoadingSpinner size="lg" />
              <p className="mt-4 text-sm text-muted-foreground">Loading applications...</p>
            </div>
          ) : isError ? (
            <QueryError error={error} resource="applications" />
          ) : !filteredApps || filteredApps.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <AppWindow className="h-12 w-12 text-muted-foreground/40 mb-3" />
              <p className="font-medium">No applications found</p>
              <p className="text-sm">Register an application to get started</p>
            </div>
          ) : (
          <div className="rounded-md border">
            <table className="w-full">
              <thead>
                <tr className="border-b bg-gray-50">
                  <th className="p-3 text-left text-sm font-medium">Application</th>
                  <th className="p-3 text-left text-sm font-medium">Client ID</th>
                  <th className="p-3 text-left text-sm font-medium">Type</th>
                  <th className="p-3 text-left text-sm font-medium">Protocol</th>
                  <th className="p-3 text-left text-sm font-medium">Status</th>
                  <th className="p-3 text-right text-sm font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredApps.map((app) => (
                    <tr key={app.id} className="border-b hover:bg-gray-50">
                      <td className="p-3">
                        <div className="flex items-center gap-3">
                          <div className={`h-10 w-10 rounded-lg ${typeColors[app.type] || 'bg-gray-100'} flex items-center justify-center`}>
                            {typeIcons[app.type] || <Globe className="h-5 w-5 text-gray-700" />}
                          </div>
                          <div>
                            <p className="font-medium">{app.name}</p>
                            <p className="text-sm text-gray-500 max-w-xs truncate">{app.description || '-'}</p>
                          </div>
                        </div>
                      </td>
                      <td className="p-3">
                        <code className="text-sm bg-gray-100 px-2 py-1 rounded">{app.client_id}</code>
                      </td>
                      <td className="p-3">
                        <Badge variant="outline" className="capitalize">
                          {app.type}
                        </Badge>
                      </td>
                      <td className="p-3">
                        <span className="text-sm text-gray-600 uppercase">{app.protocol}</span>
                      </td>
                      <td className="p-3">
                        <Badge variant={app.enabled ? 'default' : 'secondary'}>
                          {app.enabled ? 'Active' : 'Disabled'}
                        </Badge>
                      </td>
                      <td className="p-3 text-right">
                        <div className="flex items-center justify-end gap-1">
                          {app.base_url && (
                            <Button variant="ghost" size="icon" asChild>
                              <a href={app.base_url} target="_blank" rel="noopener noreferrer">
                                <ExternalLink className="h-4 w-4" />
                              </a>
                            </Button>
                          )}
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button variant="ghost" size="icon">
                                <MoreHorizontal className="h-4 w-4" />
                              </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                              <DropdownMenuItem onClick={() => handleEditApp(app)}>
                                <Edit className="mr-2 h-4 w-4" />
                                Edit Application
                              </DropdownMenuItem>
                              <DropdownMenuItem onClick={() => handleCopyClientId(app.client_id)}>
                                <Copy className="mr-2 h-4 w-4" />
                                Copy Client ID
                              </DropdownMenuItem>
                              <DropdownMenuItem onClick={() => {
                                setRegenerateApp(app)
                                setNewSecret(null)
                                setRegenerateModal(true)
                              }}>
                                <RefreshCw className="mr-2 h-4 w-4" />
                                Regenerate Secret
                              </DropdownMenuItem>
                              <DropdownMenuItem onClick={() => handleSsoSettings(app)}>
                                <Settings className="mr-2 h-4 w-4" />
                                SSO Settings
                              </DropdownMenuItem>
                              <DropdownMenuSeparator />
                              <DropdownMenuItem
                                className="text-red-600"
                                onClick={() => handleDeleteApp(app.id, app.name)}
                                disabled={deleteApplicationMutation.isPending}
                              >
                                <Trash2 className="mr-2 h-4 w-4" />
                                {deleteApplicationMutation.isPending ? 'Deleting...' : 'Delete Application'}
                              </DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </div>
                      </td>
                    </tr>
                  ))
                }
              </tbody>
            </table>
          </div>
          )}

          {/* Pagination Controls */}
          {totalCount > PAGE_SIZE && (
            <div className="flex items-center justify-between pt-4 px-1">
              <p className="text-sm text-gray-500">
                Showing {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, totalCount)} of {totalCount} applications
              </p>
              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPage(p => Math.max(0, p - 1))}
                  disabled={page === 0}
                >
                  <ChevronLeft className="h-4 w-4 mr-1" />
                  Previous
                </Button>
                <span className="text-sm text-gray-600">
                  Page {page + 1} of {Math.ceil(totalCount / PAGE_SIZE)}
                </span>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPage(p => p + 1)}
                  disabled={(page + 1) * PAGE_SIZE >= totalCount}
                >
                  Next
                  <ChevronRight className="h-4 w-4 ml-1" />
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Register OAuth Client Modal */}
      <Dialog open={registerAppModal} onOpenChange={setRegisterAppModal}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>Register OAuth/OIDC Application</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleRegisterSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="name">Application Name *</Label>
              <Input
                id="name"
                name="name"
                value={formData.name}
                onChange={handleInputChange}
                placeholder="My Application"
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="description">Description</Label>
              <Input
                id="description"
                name="description"
                value={formData.description}
                onChange={handleInputChange}
                placeholder="Application description"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="type">Application Type *</Label>
              <Select value={formData.type} onValueChange={(value) => setFormData(prev => ({ ...prev, type: value }))}>
                <SelectTrigger className="w-full">
                  <SelectValue placeholder="Select application type" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="web">Web Application</SelectItem>
                  <SelectItem value="native">Native/Mobile App</SelectItem>
                  <SelectItem value="service">Service/Machine-to-Machine</SelectItem>
                </SelectContent>
              </Select>
              <p className="text-xs text-gray-500">
                {formData.type === 'web' && 'Server-side web applications (confidential client)'}
                {formData.type === 'native' && 'Mobile or desktop applications (public client with PKCE)'}
                {formData.type === 'service' && 'Backend services using client credentials'}
              </p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="redirect_uris">Redirect URIs * (one per line)</Label>
              <textarea
                id="redirect_uris"
                name="redirect_uris"
                value={formData.redirect_uris}
                onChange={handleInputChange}
                rows={3}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="https://myapp.com/callback&#10;https://myapp.com/auth/callback"
                required
              />
              <p className="text-xs text-gray-500">
                Valid OAuth 2.0 redirect URIs for your application
              </p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="scopes">Scopes (comma-separated)</Label>
              <Input
                id="scopes"
                name="scopes"
                value={formData.scopes}
                onChange={handleInputChange}
                placeholder="openid,profile,email,offline_access"
              />
              <p className="text-xs text-gray-500">
                OAuth/OIDC scopes this client can request
              </p>
            </div>
            <div className="flex items-center space-x-2">
              <input
                type="checkbox"
                id="pkce_required"
                name="pkce_required"
                checked={formData.pkce_required}
                onChange={(e) => setFormData(prev => ({ ...prev, pkce_required: e.target.checked }))}
                className="rounded"
              />
              <Label htmlFor="pkce_required">Require PKCE (Recommended for mobile/SPA)</Label>
            </div>
            <div className="bg-blue-50 border border-blue-200 rounded-md p-3 text-sm">
              <p className="font-medium text-blue-900 mb-1">After registration:</p>
              <ul className="text-blue-800 space-y-1 list-disc list-inside">
                <li>You'll receive a <strong>Client ID</strong> and <strong>Client Secret</strong></li>
                <li>Store the Client Secret securely - it won't be shown again</li>
                <li>Use these credentials to integrate OAuth 2.0 / OIDC</li>
              </ul>
            </div>
            <div className="flex justify-end gap-2 pt-4">
              <Button
                type="button"
                variant="outline"
                onClick={() => setRegisterAppModal(false)}
                disabled={createClientMutation.isPending}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={createClientMutation.isPending}>
                {createClientMutation.isPending ? 'Registering...' : 'Register Application'}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Edit Application Modal */}
      <Dialog open={editAppModal} onOpenChange={setEditAppModal}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Edit Application</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleFormSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="name">Application Name</Label>
              <Input
                id="name"
                name="name"
                value={formData.name}
                onChange={handleInputChange}
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="description">Description</Label>
              <Input
                id="description"
                name="description"
                value={formData.description}
                onChange={handleInputChange}
                placeholder="Enter application description"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="base_url">Base URL</Label>
              <Input
                id="base_url"
                name="base_url"
                value={formData.base_url}
                onChange={handleInputChange}
                placeholder="https://example.com"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="redirect_uris">Redirect URIs (one per line)</Label>
              <textarea
                id="redirect_uris"
                name="redirect_uris"
                value={formData.redirect_uris}
                onChange={handleInputChange}
                rows={3}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="https://example.com/callback&#10;https://example.com/redirect"
              />
            </div>
            <div className="flex items-center space-x-2">
              <input
                type="checkbox"
                id="edit_pkce_required"
                name="pkce_required"
                checked={formData.pkce_required}
                onChange={(e) => setFormData(prev => ({ ...prev, pkce_required: e.target.checked }))}
                className="rounded"
              />
              <Label htmlFor="edit_pkce_required">Require PKCE (Recommended for mobile/SPA)</Label>
            </div>
            <div className="flex justify-end gap-2 pt-4">
              <Button
                type="button"
                variant="outline"
                onClick={() => setEditAppModal(false)}
                disabled={updateApplicationMutation.isPending}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={updateApplicationMutation.isPending}>
                {updateApplicationMutation.isPending ? 'Updating...' : 'Update Application'}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* SSO Settings Modal */}
      <Dialog open={ssoSettingsModal} onOpenChange={setSsoSettingsModal}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>SSO Settings - {selectedApp?.name}</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleSsoSubmit} className="space-y-4">
            <div className="space-y-3">
              <div className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  id="enabled"
                  name="enabled"
                  checked={ssoSettings.enabled}
                  onChange={handleSsoChange}
                  className="rounded"
                />
                <Label htmlFor="enabled">SSO Enabled</Label>
              </div>
              <div className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  id="refreshToken"
                  name="refreshToken"
                  checked={ssoSettings.refreshToken}
                  onChange={handleSsoChange}
                  className="rounded"
                />
                <Label htmlFor="refreshToken">Use Refresh Tokens</Label>
              </div>
              <div className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  id="consentRequired"
                  name="consentRequired"
                  checked={ssoSettings.consentRequired}
                  onChange={handleSsoChange}
                  className="rounded"
                />
                <Label htmlFor="consentRequired">Require User Consent</Label>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="accessTokenLifetime">Access Token Lifetime (seconds)</Label>
                <Input
                  id="accessTokenLifetime"
                  name="accessTokenLifetime"
                  type="number"
                  value={ssoSettings.accessTokenLifetime}
                  onChange={handleSsoChange}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="refreshTokenLifetime">Refresh Token Lifetime (seconds)</Label>
                <Input
                  id="refreshTokenLifetime"
                  name="refreshTokenLifetime"
                  type="number"
                  value={ssoSettings.refreshTokenLifetime}
                  onChange={handleSsoChange}
                />
              </div>
            </div>
            <div className="flex justify-end gap-2 pt-4">
              <Button type="button" variant="outline" onClick={() => setSsoSettingsModal(false)}>
                Cancel
              </Button>
              <Button type="submit">Save SSO Settings</Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Regenerate Client Secret Modal */}
      <Dialog open={regenerateModal} onOpenChange={(open) => {
        if (!open) {
          setRegenerateModal(false)
          setRegenerateApp(null)
          setNewSecret(null)
        }
      }}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Regenerate Client Secret</DialogTitle>
          </DialogHeader>
          {newSecret ? (
            <div className="space-y-4">
              <div className="bg-yellow-50 border border-yellow-200 rounded-md p-3 text-sm text-yellow-800">
                <p className="font-medium mb-1">Save this secret now!</p>
                <p>This is the only time the client secret will be shown. Store it securely.</p>
              </div>
              <div className="space-y-2">
                <Label>New Client Secret</Label>
                <div className="flex items-center gap-2">
                  <code className="flex-1 p-2 bg-gray-100 rounded text-sm break-all">{newSecret}</code>
                  <Button variant="outline" size="sm" onClick={() => {
                    navigator.clipboard.writeText(newSecret)
                    toast({ title: 'Copied', description: 'Secret copied to clipboard!', variant: 'success' })
                  }}>
                    <Copy className="h-4 w-4" />
                  </Button>
                </div>
              </div>
              <div className="flex justify-end">
                <Button onClick={() => { setRegenerateModal(false); setRegenerateApp(null); setNewSecret(null) }}>
                  Done
                </Button>
              </div>
            </div>
          ) : (
            <div className="space-y-4">
              <p className="text-sm text-gray-600">
                Are you sure you want to regenerate the client secret for <strong>{regenerateApp?.name}</strong>?
                This will invalidate the current secret and any integrations using it will stop working.
              </p>
              <div className="flex justify-end gap-2">
                <Button variant="outline" onClick={() => { setRegenerateModal(false); setRegenerateApp(null) }}>
                  Cancel
                </Button>
                <Button
                  variant="destructive"
                  disabled={regenerateSecretMutation.isPending}
                  onClick={() => regenerateApp && regenerateSecretMutation.mutate(regenerateApp.client_id)}
                >
                  {regenerateSecretMutation.isPending ? 'Regenerating...' : 'Regenerate Secret'}
                </Button>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Delete Application Confirmation */}
      <AlertDialog open={!!deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Are you sure?</AlertDialogTitle>
            <AlertDialogDescription>
              {deleteTarget ? `Are you sure you want to delete application "${deleteTarget.name}"? This action cannot be undone.` : ''}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={() => { if (deleteTarget) { deleteApplicationMutation.mutate(deleteTarget.id); setDeleteTarget(null) } }}>
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
