import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Smartphone, Monitor, Tablet, Shield, ShieldCheck, ShieldX, Trash2, Edit, Plus, MoreHorizontal, Network, Copy, Download, Wifi, WifiOff } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '../components/ui/dialog'
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
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '../components/ui/dropdown-menu'
import { Label } from '../components/ui/label'
import { Textarea } from '../components/ui/textarea'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

interface MyZitiIdentity {
  linked: boolean
  ziti_id?: string
  name?: string
  enrolled?: boolean
  attributes?: string[]
  enrollment_jwt?: string
}

interface Device {
  id: string
  user_id: string
  fingerprint: string
  name: string
  device_type: string
  ip_address: string
  user_agent?: string
  location?: string
  trusted: boolean
  trust_requested?: boolean
  last_seen_at?: string
  created_at: string
}

interface DevicePostureSummary {
  check_type: string
  status: string
  severity: string
}

interface CorrelatedDevice {
  source: 'linked' | 'iam' | 'ziti'
  iam?: { name: string; trusted: boolean; device_type: string }
  ziti?: {
    agent_id: string
    status: string
    platform?: string
    compliance_status: string
    compliance_score: number
    posture: DevicePostureSummary[]
  }
}

export function MyDevicesPage() {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [editDialog, setEditDialog] = useState(false)
  const [trustDialog, setTrustDialog] = useState(false)
  const [deleteDialog, setDeleteDialog] = useState(false)
  const [registerDialog, setRegisterDialog] = useState(false)
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null)
  const [editName, setEditName] = useState('')
  const [trustJustification, setTrustJustification] = useState('')
  const [newDeviceName, setNewDeviceName] = useState('')

  // Fetch devices
  const { data: devicesData, isLoading } = useQuery({
    queryKey: ['my-devices'],
    queryFn: async () => {
      const data = await api.get<{ devices: Device[] }>('/api/v1/identity/portal/devices')
      return data.devices
    }
  })

  const devices = devicesData || []

  // Correlated endpoint agents (Ziti compliance/posture) for the current user.
  const { data: correlatedData } = useQuery({
    queryKey: ['my-correlated-devices'],
    queryFn: () => api.get<{ devices: CorrelatedDevice[] }>('/api/v1/access/my-devices'),
  })
  const endpointAgents = (correlatedData?.devices || []).filter(d => d.ziti)

  // Register device mutation
  const registerMutation = useMutation({
    mutationFn: async (data: { name: string }) => {
      return api.post('/api/v1/identity/portal/devices', data)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['my-devices'] })
      toast({ title: 'Device registered', description: 'Your device has been registered successfully.' })
      setRegisterDialog(false)
      setNewDeviceName('')
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to register device.', variant: 'destructive' })
    }
  })

  // Update device mutation
  const updateMutation = useMutation({
    mutationFn: async ({ id, name }: { id: string; name: string }) => {
      return api.put(`/api/v1/identity/portal/devices/${id}`, { name })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['my-devices'] })
      toast({ title: 'Device updated', description: 'Device name has been updated.' })
      setEditDialog(false)
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to update device.', variant: 'destructive' })
    }
  })

  // Delete device mutation
  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      return api.delete(`/api/v1/identity/portal/devices/${id}`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['my-devices'] })
      toast({ title: 'Device removed', description: 'The device has been removed from your account.' })
      setDeleteDialog(false)
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to remove device.', variant: 'destructive' })
    }
  })

  // Request trust mutation
  const trustMutation = useMutation({
    mutationFn: async ({ id, justification }: { id: string; justification: string }) => {
      return api.post(`/api/v1/identity/portal/devices/${id}/trust`, { justification })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['my-devices'] })
      toast({ title: 'Trust requested', description: 'Your trust request has been submitted for review.' })
      setTrustDialog(false)
      setTrustJustification('')
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to submit trust request.', variant: 'destructive' })
    }
  })

  const handleEdit = (device: Device) => {
    setSelectedDevice(device)
    setEditName(device.name)
    setEditDialog(true)
  }

  const handleTrust = (device: Device) => {
    setSelectedDevice(device)
    setTrustJustification('')
    setTrustDialog(true)
  }

  const handleDelete = (device: Device) => {
    setSelectedDevice(device)
    setDeleteDialog(true)
  }

  const getDeviceIcon = (type: string) => {
    switch (type) {
      case 'mobile':
        return <Smartphone className="h-8 w-8" />
      case 'tablet':
        return <Tablet className="h-8 w-8" />
      default:
        return <Monitor className="h-8 w-8" />
    }
  }

  const formatDate = (dateString?: string) => {
    if (!dateString) return 'Never'
    return new Date(dateString).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    })
  }

  // Fetch Ziti identity for the current user
  const { data: zitiIdentity } = useQuery({
    queryKey: ['my-ziti-identity'],
    queryFn: () => api.get<MyZitiIdentity>('/api/v1/access/ziti/sync/my-identity'),
  })

  const [showJwt, setShowJwt] = useState(false)

  const downloadJwt = () => {
    if (!zitiIdentity?.enrollment_jwt) return
    const blob = new Blob([zitiIdentity.enrollment_jwt], { type: 'application/jwt' })
    const url = window.URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${zitiIdentity.name || 'identity'}.jwt`
    a.click()
    window.URL.revokeObjectURL(url)
  }

  // Summary stats
  const trustedCount = devices.filter(d => d.trusted).length
  const untrustedCount = devices.filter(d => !d.trusted).length

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">My Devices</h1>
          <p className="text-muted-foreground">
            Manage your devices and how they connect
          </p>
        </div>
        <Button onClick={() => setRegisterDialog(true)}>
          <Plus className="h-4 w-4 mr-2" />
          Register This Device
        </Button>
      </div>

      {/* Network access status — plain language. The underlying overlay identity
          is an implementation detail; users care whether this device can reach
          internal systems directly, and what to do if it can't. */}
      {zitiIdentity && (
        <Card className={zitiIdentity.linked ? 'border-green-200 bg-green-50/30' : 'border-amber-200 bg-amber-50/30'}>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-base">
              <Network className="h-5 w-5 text-blue-600" />
              Direct network access
            </CardTitle>
            <CardDescription>
              {!zitiIdentity.linked
                ? 'This account is not set up for direct network access yet. Most resources still open in your browser from My Network.'
                : zitiIdentity.enrolled
                  ? 'This device can reach internal systems directly.'
                  : 'Optional. Most resources already open in your browser from My Network — you only need this for a few tools that connect outside the browser.'}
            </CardDescription>
          </CardHeader>
          {zitiIdentity.linked && (
            <CardContent>
              <div className="flex flex-wrap items-center gap-4 text-sm">
                <Badge variant={zitiIdentity.enrolled ? 'default' : 'secondary'}>
                  {zitiIdentity.enrolled ? 'Active on this device' : 'Not set up on this device'}
                </Badge>
              </div>

              {/* Guided setup, only for the minority of cases that need it. The
                  raw token stays collapsed under "Advanced" so it is available
                  for support without being the first thing a user sees. */}
              {!zitiIdentity.enrolled && zitiIdentity.enrollment_jwt && (
                <div className="mt-4 p-3 bg-white rounded-lg border space-y-3">
                  <div>
                    <p className="text-sm font-medium">Set up this device</p>
                    <p className="text-xs text-muted-foreground mt-1">
                      Step 1 — install the OpenIDX network client for your operating system.
                      Step 2 — open it and paste the setup key below. You only do this once.
                    </p>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <Button
                      size="sm"
                      onClick={() => window.open('https://openziti.io/downloads', '_blank')}
                    >
                      <Download className="h-3.5 w-3.5 mr-1.5" /> Get the client
                    </Button>
                    <Button variant="outline" size="sm" onClick={() => {
                      navigator.clipboard.writeText(zitiIdentity.enrollment_jwt!)
                      toast({ title: 'Setup key copied', description: 'Paste it into the network client.' })
                    }}>
                      <Copy className="h-3.5 w-3.5 mr-1.5" /> Copy setup key
                    </Button>
                  </div>
                  <details className="text-xs text-muted-foreground">
                    <summary className="cursor-pointer select-none">Advanced</summary>
                    <div className="mt-2 flex gap-2">
                      <Button variant="outline" size="sm" onClick={() => setShowJwt(!showJwt)}>
                        {showJwt ? 'Hide key' : 'Show key'}
                      </Button>
                      <Button variant="outline" size="sm" onClick={downloadJwt}>
                        <Download className="h-3.5 w-3.5 mr-1.5" /> Download key file
                      </Button>
                    </div>
                    {showJwt && (
                      <textarea
                        readOnly
                        value={zitiIdentity.enrollment_jwt}
                        className="mt-2 w-full h-24 rounded-md border bg-muted p-2 text-xs font-mono"
                      />
                    )}
                  </details>
                </div>
              )}
            </CardContent>
          )}
        </Card>
      )}

      {/* Devices set up for direct access, with their live security posture. */}
      {endpointAgents.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-base">
              <Network className="h-4 w-4 text-green-600" />Devices with direct access
            </CardTitle>
            <CardDescription>
              Devices set up for direct network access, and whether they meet your security policy.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            {endpointAgents.map((d, i) => {
              const z = d.ziti!
              const failing = (z.posture || []).filter(p => p.status !== 'pass')
              const compliant = z.compliance_status === 'compliant'
              return (
                <div key={i} className="flex items-start justify-between gap-3 p-3 rounded-lg bg-muted/40">
                  <div className="min-w-0 space-y-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-medium truncate">{d.iam?.name || z.agent_id}</span>
                      {z.platform && <Badge variant="secondary" className="text-xs">{z.platform}</Badge>}
                      <Badge variant="outline" className={`text-xs ${compliant
                        ? 'bg-green-50 text-green-700 border-green-200'
                        : z.compliance_status === 'non_compliant'
                          ? 'bg-red-50 text-red-700 border-red-200'
                          : 'bg-yellow-50 text-yellow-700 border-yellow-200'}`}>
                        {compliant ? <ShieldCheck className="mr-1 h-3 w-3" /> : <ShieldX className="mr-1 h-3 w-3" />}
                        {z.compliance_status.replace('_', ' ')}
                      </Badge>
                      {d.source === 'linked' && (
                        <Badge variant="outline" className="text-xs bg-blue-50 text-blue-700 border-blue-200">
                          linked to trusted device
                        </Badge>
                      )}
                    </div>
                    {failing.length > 0 && (
                      <div className="flex flex-wrap gap-1">
                        {failing.map((p, j) => (
                          <Badge key={j} variant="outline" className="text-xs bg-red-50 text-red-700 border-red-200">
                            {p.check_type}: {p.status}
                          </Badge>
                        ))}
                      </div>
                    )}
                  </div>
                  <span className="text-sm font-semibold shrink-0">{Math.round(z.compliance_score)}%</span>
                </div>
              )
            })}
          </CardContent>
        </Card>
      )}

      {/* Summary Cards */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Devices</CardTitle>
            <Monitor className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{devices.length}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Trusted</CardTitle>
            <ShieldCheck className="h-4 w-4 text-green-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600">{trustedCount}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Untrusted</CardTitle>
            <ShieldX className="h-4 w-4 text-amber-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-amber-600">{untrustedCount}</div>
          </CardContent>
        </Card>
      </div>

      {/* Devices List */}
      <Card>
        <CardHeader>
          <CardTitle>Registered Devices</CardTitle>
          <CardDescription>
            Devices that have been used to access your account
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex flex-col items-center justify-center py-12">
              <LoadingSpinner size="lg" />
              <p className="mt-4 text-sm text-muted-foreground">Loading devices...</p>
            </div>
          ) : devices.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <Monitor className="h-12 w-12 text-muted-foreground/40 mb-3" />
              <p className="font-medium">No devices registered</p>
              <p className="text-sm">Register this device to get started</p>
            </div>
          ) : (
            <div className="space-y-4">
              {devices.map((device) => (
                <div
                  key={device.id}
                  className="flex items-center justify-between p-4 border rounded-lg hover:bg-muted/50 transition-colors"
                >
                  <div className="flex items-center gap-4">
                    <div className={`p-3 rounded-lg ${device.trusted ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-600'}`}>
                      {getDeviceIcon(device.device_type)}
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-medium">{device.name}</span>
                        {device.trusted ? (
                          <Badge className="bg-green-100 text-green-800">
                            <ShieldCheck className="h-3 w-3 mr-1" />
                            Trusted
                          </Badge>
                        ) : (
                          <Badge variant="secondary">
                            <Shield className="h-3 w-3 mr-1" />
                            Untrusted
                          </Badge>
                        )}
                        {device.trusted && zitiIdentity?.linked && zitiIdentity?.enrolled ? (
                          <Badge className="bg-emerald-100 text-emerald-800">
                            <Wifi className="h-3 w-3 mr-1" />
                            Network Active
                          </Badge>
                        ) : device.trusted && zitiIdentity?.linked && !zitiIdentity?.enrolled ? (
                          <Badge className="bg-yellow-100 text-yellow-800">
                            Setup not finished
                          </Badge>
                        ) : !device.trusted ? (
                          <Badge variant="outline" className="text-muted-foreground">
                            <WifiOff className="h-3 w-3 mr-1" />
                            No Network Access
                          </Badge>
                        ) : null}
                      </div>
                      <div className="text-sm text-muted-foreground">
                        {device.ip_address}
                        {device.location && ` - ${device.location}`}
                      </div>
                      <div className="text-xs text-muted-foreground mt-1">
                        Last seen: {formatDate(device.last_seen_at)} | Registered: {formatDate(device.created_at)}
                      </div>
                    </div>
                  </div>
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant="ghost" size="sm">
                        <MoreHorizontal className="h-4 w-4" />
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                      <DropdownMenuItem onClick={() => handleEdit(device)}>
                        <Edit className="h-4 w-4 mr-2" />
                        Rename
                      </DropdownMenuItem>
                      {!device.trusted && (
                        <DropdownMenuItem onClick={() => handleTrust(device)}>
                          <ShieldCheck className="h-4 w-4 mr-2" />
                          Request Trust
                        </DropdownMenuItem>
                      )}
                      <DropdownMenuSeparator />
                      <DropdownMenuItem
                        onClick={() => handleDelete(device)}
                        className="text-red-600 focus:text-red-600"
                      >
                        <Trash2 className="h-4 w-4 mr-2" />
                        Remove
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Register Device Dialog */}
      <Dialog open={registerDialog} onOpenChange={setRegisterDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Register This Device</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="device-name">Device Name</Label>
              <Input
                id="device-name"
                placeholder="e.g., Work Laptop, Personal Phone"
                value={newDeviceName}
                onChange={(e) => setNewDeviceName(e.target.value)}
              />
              <p className="text-xs text-muted-foreground">
                Give this device a friendly name to identify it later
              </p>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRegisterDialog(false)}>
              Cancel
            </Button>
            <Button onClick={() => registerMutation.mutate({ name: newDeviceName })}>
              Register Device
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Edit Device Dialog */}
      <Dialog open={editDialog} onOpenChange={setEditDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Rename Device</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="edit-name">Device Name</Label>
              <Input
                id="edit-name"
                value={editName}
                onChange={(e) => setEditName(e.target.value)}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditDialog(false)}>
              Cancel
            </Button>
            <Button onClick={() => selectedDevice && updateMutation.mutate({ id: selectedDevice.id, name: editName })}>
              Save Changes
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Request Trust Dialog */}
      <Dialog open={trustDialog} onOpenChange={setTrustDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Request Device Trust</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <p className="text-sm text-muted-foreground">
              Trusted devices get fewer MFA prompts and zero-trust network access. Once approved, this device will enable secure network connectivity.
            </p>
            <div className="space-y-2">
              <Label htmlFor="justification">Justification</Label>
              <Textarea
                id="justification"
                placeholder="This is my work laptop used for daily tasks..."
                value={trustJustification}
                onChange={(e) => setTrustJustification(e.target.value)}
                rows={3}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setTrustDialog(false)}>
              Cancel
            </Button>
            <Button onClick={() => selectedDevice && trustMutation.mutate({ id: selectedDevice.id, justification: trustJustification })}>
              Submit Request
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <AlertDialog open={deleteDialog} onOpenChange={setDeleteDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Remove Device?</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to remove "{selectedDevice?.name}" from your account?
              You may need to re-authenticate if you use this device again.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => selectedDevice && deleteMutation.mutate(selectedDevice.id)}
              className="bg-red-600 hover:bg-red-700"
            >
              Remove Device
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
