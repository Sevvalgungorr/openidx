import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Monitor, MonitorSmartphone, Trash2, Globe, Shield, AlertTriangle, Users } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Badge } from '../components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { ConfirmAction } from '../components/confirm-action'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'
import { useAuth } from '../lib/auth'

interface Session {
  id: string
  user_id: string
  username: string
  email: string
  client_id: string
  ip_address?: string
  user_agent?: string
  device_name?: string
  location?: string
  device_type?: string
  risk_score?: number
  auth_methods?: string[]
  device_trusted?: boolean
  started_at: string
  last_seen_at: string
  expires_at: string
  revoked: boolean
  revoked_at?: string
  revoke_reason?: string
}

export function SessionsAdminPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const { hasRole } = useAuth()
  // Admins/operators manage every session in the org; a regular user manages
  // only their own. This drives which endpoint we read and what actions show.
  const isAdmin = hasRole('admin') || hasRole('super_admin') || hasRole('operator')
  const [userIdFilter, setUserIdFilter] = useState('')
  const [activeOnly, setActiveOnly] = useState(true)

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['admin-sessions', isAdmin, userIdFilter, activeOnly],
    queryFn: () => {
      if (!isAdmin) {
        // Self-service: the caller's own sessions (server sources the user from
        // the JWT). No org-wide list, no user filter.
        return api.get<{ sessions: Session[]; total?: number }>(
          '/api/v1/identity/users/me/sessions'
        )
      }
      const params = new URLSearchParams()
      params.set('active_only', String(activeOnly))
      if (userIdFilter) params.set('user_id', userIdFilter)
      return api.get<{ sessions: Session[]; total: number }>(`/api/v1/sessions?${params.toString()}`)
    },
  })
  const sessions = data?.sessions || []
  const total = data?.total ?? sessions.length

  const revokeMutation = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      // Admins revoke via the admin endpoint; a user ends their own session via
      // the ownership-checked self endpoint.
      isAdmin
        ? api.delete(`/api/v1/sessions/${id}`, { data: { reason } })
        : api.delete(`/api/v1/identity/sessions/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin-sessions'] })
      toast({ title: isAdmin ? 'Session revoked' : 'Signed out of that session' })
    },
    onError: () => toast({ title: 'Failed to revoke session', variant: 'destructive' }),
  })

  const bulkRevokeMutation = useMutation({
    mutationFn: ({ userId, reason }: { userId: string; reason: string }) =>
      api.delete(`/api/v1/users/${userId}/sessions`, { data: { reason } }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin-sessions'] })
      toast({ title: 'All user sessions revoked' })
    },
    onError: () => toast({ title: 'Failed to revoke sessions', variant: 'destructive' }),
  })

  const formatDate = (d: string) => new Date(d).toLocaleString()

  // Calculate session stats
  const activeSessions = sessions.filter(s => !s.revoked && new Date(s.expires_at) > new Date())
  const highRiskSessions = sessions.filter(s => (s.risk_score || 0) >= 70)
  const trustedDeviceSessions = sessions.filter(s => s.device_trusted)
  const uniqueUsers = new Set(sessions.map(s => s.user_id)).size

  const getRiskBadge = (score?: number) => {
    if (!score) return null
    if (score >= 70) return <Badge className="bg-red-100 text-red-800 text-xs"><AlertTriangle className="h-3 w-3 mr-1" />{score}</Badge>
    if (score >= 50) return <Badge className="bg-amber-100 text-amber-800 text-xs">{score}</Badge>
    if (score >= 30) return <Badge className="bg-yellow-100 text-yellow-800 text-xs">{score}</Badge>
    return <Badge className="bg-green-100 text-green-800 text-xs">{score}</Badge>
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">
          {isAdmin ? 'Session Management' : 'My Sessions'}
        </h1>
        <p className="text-muted-foreground">
          {isAdmin
            ? 'View and manage active user sessions'
            : 'Devices and apps currently signed in to your account'}
        </p>
      </div>

      {/* Session Stats */}
      <div className={`grid gap-4 ${isAdmin ? 'md:grid-cols-4' : 'md:grid-cols-1'}`}>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Sessions</CardTitle>
            <Monitor className="h-4 w-4 text-green-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600">{activeSessions.length}</div>
            <p className="text-xs text-muted-foreground">of {total} total</p>
          </CardContent>
        </Card>
        {isAdmin && (
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Unique Users</CardTitle>
            <Users className="h-4 w-4 text-primary" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{uniqueUsers}</div>
          </CardContent>
        </Card>
        )}
        {isAdmin && (
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">High Risk</CardTitle>
            <AlertTriangle className="h-4 w-4 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-600">{highRiskSessions.length}</div>
            <p className="text-xs text-muted-foreground">Risk score &ge; 70</p>
          </CardContent>
        </Card>
        )}
        {isAdmin && (
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Trusted Devices</CardTitle>
            <Shield className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{trustedDeviceSessions.length}</div>
          </CardContent>
        </Card>
        )}
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-4">
            <CardTitle className="flex items-center gap-2"><Monitor className="h-5 w-5" />Sessions ({total})</CardTitle>
            {isAdmin && (
              <>
                <Input placeholder="Filter by user ID..." className="max-w-xs" value={userIdFilter}
                  onChange={e => setUserIdFilter(e.target.value)} />
                <label className="flex items-center gap-2 text-sm">
                  <input type="checkbox" checked={activeOnly} onChange={e => setActiveOnly(e.target.checked)} />
                  Active only
                </label>
              </>
            )}
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex flex-col items-center justify-center py-12">
              <LoadingSpinner size="lg" />
              <p className="mt-4 text-sm text-muted-foreground">Loading sessions...</p>
            </div>
          ) : isError ? (
            <QueryError error={error} resource="sessions" />
          ) : sessions.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <MonitorSmartphone className="h-12 w-12 text-muted-foreground/40 mb-3" />
              <p className="font-medium">No active sessions</p>
              <p className="text-sm">{isAdmin ? 'User sessions will appear here when users log in' : 'Your active sessions will appear here'}</p>
            </div>
          ) : (
            <Table>
              <TableHeader><TableRow>
                {isAdmin && <TableHead>User</TableHead>}<TableHead>Device</TableHead><TableHead>Location</TableHead>
                {isAdmin && <TableHead>Risk</TableHead>}<TableHead>Started</TableHead><TableHead>Last Active</TableHead>
                <TableHead>Status</TableHead><TableHead>Actions</TableHead>
              </TableRow></TableHeader>
              <TableBody>
                {sessions.map(s => (
                  <TableRow key={s.id} className={(s.risk_score || 0) >= 70 ? 'bg-red-50' : ''}>
                    {isAdmin && (
                    <TableCell>
                      <div>
                        <div className="font-medium">{s.username}</div>
                        <div className="text-xs text-muted-foreground">{s.email}</div>
                      </div>
                    </TableCell>
                    )}
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <div>
                          <div className="text-sm">{s.device_name || '-'}</div>
                          {s.device_type && <div className="text-xs text-muted-foreground">{s.device_type}</div>}
                        </div>
                        {s.device_trusted && (
                          <Shield className="h-4 w-4 text-green-500" />
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1">
                        <Globe className="h-3 w-3 text-muted-foreground" />
                        <span className="text-sm">{s.location || '-'}</span>
                      </div>
                      <div className="font-mono text-xs text-muted-foreground">{s.ip_address || '-'}</div>
                    </TableCell>
                    {isAdmin && (
                    <TableCell>
                      {getRiskBadge(s.risk_score)}
                      {s.auth_methods && s.auth_methods.length > 0 && (
                        <div className="text-xs text-muted-foreground mt-1">
                          {s.auth_methods.join(', ')}
                        </div>
                      )}
                    </TableCell>
                    )}
                    <TableCell className="text-sm">{formatDate(s.started_at)}</TableCell>
                    <TableCell className="text-sm">{formatDate(s.last_seen_at)}</TableCell>
                    <TableCell>
                      {s.revoked ? (
                        <Badge variant="secondary">Revoked</Badge>
                      ) : new Date(s.expires_at) < new Date() ? (
                        <Badge variant="secondary">Expired</Badge>
                      ) : (
                        <Badge className="bg-green-100 text-green-800">Active</Badge>
                      )}
                    </TableCell>
                    <TableCell>
                      <div className="flex gap-1">
                        {!s.revoked && new Date(s.expires_at) > new Date() && (
                          <ConfirmAction
                            title="Revoke Session"
                            description={`Revoke the session for ${s.username} from ${s.ip_address || 'unknown IP'}? The session will be signed out immediately.`}
                            destructive
                            requireReason
                            confirmLabel="Revoke"
                            onConfirm={(reason) => revokeMutation.mutateAsync({ id: s.id, reason: reason || '' })}
                          >
                            {(open) => (
                              <Button variant="ghost" size="sm" onClick={open}>
                                <Trash2 className="h-4 w-4 text-red-500" />
                              </Button>
                            )}
                          </ConfirmAction>
                        )}
                        {isAdmin && (
                          <ConfirmAction
                            title="Revoke All User Sessions"
                            description="This will revoke all active sessions for this user. They will be signed out of every device immediately."
                            destructive
                            requireReason
                            confirmLabel="Revoke All Sessions"
                            onConfirm={(reason) => bulkRevokeMutation.mutateAsync({ userId: s.user_id, reason: reason || '' })}
                          >
                            {(open) => (
                              <Button variant="outline" size="sm" onClick={open}>
                                Revoke All
                              </Button>
                            )}
                          </ConfirmAction>
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

    </div>
  )
}
