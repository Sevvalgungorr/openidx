import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { KeyRound, MonitorPlay, Play, Send, Timer, Undo2, Copy } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Badge } from '../components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '../components/ui/dialog'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger,
} from '../components/ui/alert-dialog'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

interface UserConnection {
  route_id: string
  name: string
  protocol: string
  hostname: string
  port: number
  require_approval: boolean
  record_session: boolean
  credential_injected: boolean
}

interface MySessionRequest {
  id: string
  route_id: string
  route_name: string
  protocol: string
  reason?: string
  status: string
  decided_at?: string
  expires_at?: string
  created_at: string
}

interface MyAccessRequest {
  id: string
  resource_name: string
  resource_type: string
  status: string
  expires_at?: string
  created_at: string
}

const statusBadge = (status: string) => {
  const map: Record<string, string> = {
    pending: 'bg-yellow-100 text-yellow-800',
    approved: 'bg-green-100 text-green-800',
    fulfilled: 'bg-green-100 text-green-800',
    denied: 'bg-red-100 text-red-800',
    consumed: 'bg-muted text-foreground',
    expired: 'bg-orange-100 text-orange-800',
  }
  return map[status] || 'bg-muted text-foreground'
}

const formatDate = (d: string) =>
  new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })

export function MyPrivilegedAccessPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [activeTab, setActiveTab] = useState('sessions')

  // Request-approval dialog state
  const [requestOpen, setRequestOpen] = useState(false)
  const [requestConn, setRequestConn] = useState<UserConnection | null>(null)
  const [requestReason, setRequestReason] = useState('')

  // Retrieve-credential dialog state (mirrors access-requests)
  const [retrieveOpen, setRetrieveOpen] = useState(false)
  const [selectedRetrieveId, setSelectedRetrieveId] = useState<string | null>(null)
  const [retrievedValue, setRetrievedValue] = useState<string | null>(null)

  const { data: connectionsData, isLoading: connsLoading, isError: connsIsError, error: connsError } = useQuery({
    queryKey: ['my-guac-connections'],
    queryFn: () => api.get<{ connections: UserConnection[] }>('/api/v1/access/guacamole/my-connections'),
  })
  const connections = connectionsData?.connections || []

  const { data: sessionRequestsData, isLoading: sessionReqsLoading, isError: sessionReqsIsError, error: sessionReqsError } = useQuery({
    queryKey: ['my-guac-session-requests'],
    queryFn: () => api.get<{ requests: MySessionRequest[] }>('/api/v1/access/guacamole/my-session-requests'),
  })
  const sessionRequests = sessionRequestsData?.requests || []

  const { data: myRequestsData, isLoading: checkoutsLoading, isError: checkoutsIsError, error: checkoutsError } = useQuery({
    queryKey: ['my-requests'],
    queryFn: () => api.get<{ requests: MyAccessRequest[] }>('/api/v1/governance/requests?requester_id=me'),
  })
  const credentialCheckouts = (myRequestsData?.requests || []).filter(
    (r) => r.resource_type === 'vault_credential',
  )

  const requestMutation = useMutation({
    mutationFn: ({ routeId, reason }: { routeId: string; reason: string }) =>
      api.post(`/api/v1/access/guacamole/connections/${routeId}/request`, { reason }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['my-guac-session-requests'] })
      toast({ title: 'Session request submitted' })
      setRequestOpen(false)
      setRequestReason('')
    },
    onError: (err: { response?: { data?: { error?: string } } }) => {
      toast({ title: err.response?.data?.error || 'Failed to request session', variant: 'destructive' })
    },
  })

  const connectMutation = useMutation({
    mutationFn: (routeId: string) =>
      api.post<{ connect_url: string }>(`/api/v1/access/guacamole/connections/${routeId}/connect`),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['my-guac-session-requests'] })
      window.open(data.connect_url, '_blank')
    },
    onError: (err: { response?: { data?: { error?: string } } }) => {
      toast({ title: err.response?.data?.error || 'Failed to start session', variant: 'destructive' })
    },
  })

  const retrieveMutation = useMutation({
    mutationFn: (id: string) => api.post<{ value: string }>(`/api/v1/governance/requests/${id}/credential`),
    onSuccess: (data) => setRetrievedValue(data.value),
    onError: (err: { response?: { data?: { error?: string } } }) => {
      toast({ title: err.response?.data?.error || 'Failed to retrieve credential', variant: 'destructive' })
    },
  })

  const returnMutation = useMutation({
    mutationFn: (id: string) => api.post(`/api/v1/governance/requests/${id}/return`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['my-requests'] })
      toast({ title: 'Credential returned' })
    },
    onError: (err: { response?: { data?: { error?: string } } }) => {
      toast({ title: err.response?.data?.error || 'Failed to return credential', variant: 'destructive' })
    },
  })

  const openRequest = (conn: UserConnection) => {
    setRequestConn(conn)
    setRequestReason('')
    setRequestOpen(true)
  }

  // Approved and unexpired → the connect handler can consume it.
  const hasApprovedRequest = (routeId: string) =>
    sessionRequests.some(
      (r) =>
        r.route_id === routeId &&
        r.status === 'approved' &&
        (!r.expires_at || new Date(r.expires_at) > new Date()),
    )

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">My Privileged Access</h1>
        <p className="text-muted-foreground">
          Launch brokered remote sessions and manage your credential checkouts
        </p>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="sessions">
            <MonitorPlay className="mr-2 h-4 w-4" />
            Remote Sessions
          </TabsTrigger>
          <TabsTrigger value="checkouts">
            <KeyRound className="mr-2 h-4 w-4" />
            Credential Checkouts
            {credentialCheckouts.filter((r) => r.status === 'fulfilled').length > 0 && (
              <Badge variant="secondary" className="ml-1">
                {credentialCheckouts.filter((r) => r.status === 'fulfilled').length}
              </Badge>
            )}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="sessions" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Available Connections</CardTitle>
              <CardDescription>
                Remote systems you can connect to through the session broker. Sessions may require
                approval and be recorded.
              </CardDescription>
            </CardHeader>
            <CardContent>
              {connsLoading ? (
                <p className="text-center py-8 text-muted-foreground">Loading...</p>
              ) : connsIsError ? (
                <QueryError error={connsError} resource="available connections" />
              ) : connections.length === 0 ? (
                <p className="text-center py-8 text-muted-foreground">No connections available</p>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Name</TableHead>
                      <TableHead>Protocol</TableHead>
                      <TableHead>Host</TableHead>
                      <TableHead>Controls</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {connections.map((conn) => (
                      <TableRow key={conn.route_id}>
                        <TableCell className="font-medium">{conn.name}</TableCell>
                        <TableCell>
                          <Badge variant="outline">{conn.protocol.toUpperCase()}</Badge>
                        </TableCell>
                        <TableCell className="font-mono text-sm">
                          {conn.hostname}:{conn.port}
                        </TableCell>
                        <TableCell>
                          <div className="flex flex-wrap gap-1">
                            {conn.require_approval && <Badge variant="secondary">Approval required</Badge>}
                            {conn.record_session && <Badge variant="secondary">Recorded</Badge>}
                            {conn.credential_injected && <Badge variant="secondary">Credential injected</Badge>}
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="flex gap-2">
                            {conn.require_approval && !hasApprovedRequest(conn.route_id) ? (
                              <Button variant="outline" size="sm" onClick={() => openRequest(conn)}>
                                <Send className="h-3 w-3 mr-1" />
                                Request Access
                              </Button>
                            ) : (
                              <Button
                                size="sm"
                                disabled={connectMutation.isPending}
                                onClick={() => connectMutation.mutate(conn.route_id)}
                              >
                                <Play className="h-3 w-3 mr-1" />
                                Launch
                              </Button>
                            )}
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>My Session Requests</CardTitle>
              <CardDescription>Status of your pre-session approval requests</CardDescription>
            </CardHeader>
            <CardContent>
              {sessionReqsLoading ? (
                <p className="text-center py-8 text-muted-foreground">Loading...</p>
              ) : sessionReqsIsError ? (
                <QueryError error={sessionReqsError} resource="your session requests" />
              ) : sessionRequests.length === 0 ? (
                <p className="text-center py-8 text-muted-foreground">No session requests</p>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Connection</TableHead>
                      <TableHead>Reason</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Requested</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {sessionRequests.map((r) => (
                      <TableRow key={r.id}>
                        <TableCell className="font-medium">
                          {r.route_name}
                          <Badge variant="outline" className="ml-2">{r.protocol.toUpperCase()}</Badge>
                        </TableCell>
                        <TableCell className="text-sm text-muted-foreground">{r.reason || '—'}</TableCell>
                        <TableCell>
                          <span className={`px-2 py-1 rounded-full text-xs font-medium ${statusBadge(r.status)}`}>
                            {r.status}
                          </span>
                          {r.expires_at && r.status === 'approved' && (
                            <span
                              className="ml-1 inline-flex items-center gap-0.5 text-xs text-orange-600"
                              title={`Expires ${new Date(r.expires_at).toLocaleString()}`}
                            >
                              <Timer className="h-3 w-3" />
                              {new Date(r.expires_at).toLocaleTimeString()}
                            </span>
                          )}
                        </TableCell>
                        <TableCell>{formatDate(r.created_at)}</TableCell>
                        <TableCell>
                          {r.status === 'approved' &&
                            (!r.expires_at || new Date(r.expires_at) > new Date()) && (
                              <Button
                                size="sm"
                                disabled={connectMutation.isPending}
                                onClick={() => connectMutation.mutate(r.route_id)}
                              >
                                <Play className="h-3 w-3 mr-1" />
                                Launch
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
        </TabsContent>

        <TabsContent value="checkouts">
          <Card>
            <CardHeader>
              <CardTitle>My Credential Checkouts</CardTitle>
              <CardDescription>
                Time-boxed vault credentials granted through access requests. Need a new credential?{' '}
                <Link to="/access-requests" className="text-primary hover:underline">
                  Submit an access request
                </Link>
                .
              </CardDescription>
            </CardHeader>
            <CardContent>
              {checkoutsLoading ? (
                <p className="text-center py-8 text-muted-foreground">Loading...</p>
              ) : checkoutsIsError ? (
                <QueryError error={checkoutsError} resource="your credential checkouts" />
              ) : credentialCheckouts.length === 0 ? (
                <p className="text-center py-8 text-muted-foreground">No credential checkouts</p>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Credential</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Requested</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {credentialCheckouts.map((r) => (
                      <TableRow key={r.id}>
                        <TableCell className="font-medium">{r.resource_name}</TableCell>
                        <TableCell>
                          <span className={`px-2 py-1 rounded-full text-xs font-medium ${statusBadge(r.status)}`}>
                            {r.status}
                          </span>
                          {r.expires_at && r.status !== 'expired' && (
                            <span
                              className="ml-1 inline-flex items-center gap-0.5 text-xs text-orange-600"
                              title={`Expires ${new Date(r.expires_at).toLocaleString()}`}
                            >
                              <Timer className="h-3 w-3" />
                              {new Date(r.expires_at).toLocaleDateString()}
                            </span>
                          )}
                        </TableCell>
                        <TableCell>{formatDate(r.created_at)}</TableCell>
                        <TableCell>
                          {r.status === 'fulfilled' && (
                            <div className="flex gap-2">
                              <Button
                                variant="outline"
                                size="sm"
                                onClick={() => {
                                  setSelectedRetrieveId(r.id)
                                  setRetrieveOpen(true)
                                }}
                              >
                                <KeyRound className="h-3 w-3 mr-1" />
                                Retrieve
                              </Button>
                              <AlertDialog>
                                <AlertDialogTrigger asChild>
                                  <Button variant="outline" size="sm">
                                    <Undo2 className="h-3 w-3 mr-1" />
                                    Return
                                  </Button>
                                </AlertDialogTrigger>
                                <AlertDialogContent>
                                  <AlertDialogHeader>
                                    <AlertDialogTitle>Return Credential?</AlertDialogTitle>
                                    <AlertDialogDescription>
                                      Return {r.resource_name} early? This immediately revokes access and
                                      triggers credential rotation.
                                    </AlertDialogDescription>
                                  </AlertDialogHeader>
                                  <AlertDialogFooter>
                                    <AlertDialogCancel>Keep</AlertDialogCancel>
                                    <AlertDialogAction onClick={() => returnMutation.mutate(r.id)}>
                                      Return
                                    </AlertDialogAction>
                                  </AlertDialogFooter>
                                </AlertDialogContent>
                              </AlertDialog>
                            </div>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Request-approval dialog */}
      <Dialog open={requestOpen} onOpenChange={setRequestOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Request Session Access</DialogTitle>
          </DialogHeader>
          {requestConn && (
            <div className="space-y-4">
              <div className="rounded-lg border p-3 text-sm space-y-1">
                <p>
                  <span className="font-medium">Connection:</span> {requestConn.name}
                </p>
                <p>
                  <span className="font-medium">Target:</span> {requestConn.protocol.toUpperCase()}{' '}
                  {requestConn.hostname}:{requestConn.port}
                </p>
              </div>
              <div>
                <label className="text-sm font-medium">Reason</label>
                <textarea
                  className="w-full rounded-md border p-2 text-sm"
                  rows={3}
                  placeholder="Why do you need this session?"
                  value={requestReason}
                  onChange={(e) => setRequestReason(e.target.value)}
                />
              </div>
              <div className="flex justify-end gap-2">
                <Button variant="outline" onClick={() => setRequestOpen(false)}>
                  Cancel
                </Button>
                <Button
                  disabled={requestMutation.isPending}
                  onClick={() =>
                    requestMutation.mutate({ routeId: requestConn.route_id, reason: requestReason })
                  }
                >
                  {requestMutation.isPending ? 'Submitting...' : 'Submit Request'}
                </Button>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Retrieve Credential dialog — one-shot reveal (mirrors access-requests) */}
      <Dialog
        open={retrieveOpen}
        onOpenChange={(open) => {
          if (!open) {
            setRetrievedValue(null)
            setSelectedRetrieveId(null)
          }
          setRetrieveOpen(open)
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Retrieve Credential</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            {!retrievedValue ? (
              <>
                <p className="text-sm text-muted-foreground">
                  The credential will be shown once. This action is audited.
                </p>
                <Button
                  onClick={() => selectedRetrieveId && retrieveMutation.mutate(selectedRetrieveId)}
                  disabled={retrieveMutation.isPending || !selectedRetrieveId}
                  className="w-full"
                >
                  {retrieveMutation.isPending ? 'Retrieving...' : 'Get Credential'}
                </Button>
              </>
            ) : (
              <div className="space-y-3">
                <div className="flex items-center gap-2 p-3 bg-amber-50 border border-amber-200 rounded-md">
                  <p className="text-xs text-amber-800 font-medium">
                    Value shown once — not stored after this dialog closes.
                  </p>
                </div>
                <div className="flex gap-2">
                  <Input
                    value={retrievedValue}
                    readOnly
                    className="font-mono text-sm"
                    type="text"
                    data-testid="retrieved-credential-value"
                  />
                  <Button
                    variant="outline"
                    size="icon"
                    onClick={() => {
                      navigator.clipboard.writeText(retrievedValue)
                      toast({ title: 'Copied' })
                    }}
                  >
                    <Copy className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            )}
          </div>
        </DialogContent>
      </Dialog>
    </div>
  )
}
