import { useState, useEffect } from 'react'
import { Activity, AlertCircle, CheckCircle, Clock, Globe, RefreshCw, Shield, TrendingUp, Wifi, WifiOff } from 'lucide-react'
import { Button } from '../../components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '../../components/ui/card'
import { Badge } from '../../components/ui/badge'
import { AuditStream } from '../../components/audit/AuditStream'
import { useAuditStreamStore, type ConnectionState } from '../../stores/audit-stream'

interface StreamStatistics {
  totalEvents: number
  eventsPerMinute: number
  connectedAt: string | null
  lastEventAt: string | null
  actorCounts: Record<string, number>
  actionCounts: Record<string, number>
}

export function AuditDashboard() {
  const [autoConnect] = useState(true)
  const [statistics, setStatistics] = useState<StreamStatistics>({
    totalEvents: 0,
    eventsPerMinute: 0,
    connectedAt: null,
    lastEventAt: null,
    actorCounts: {},
    actionCounts: {},
  })

  const {
    connectionState,
    isConnected,
    allowedOrigins,
    currentOrigin,
    events,
    clearEvents,
  } = useAuditStreamStore()

  // Calculate statistics from events
  useEffect(() => {
    if (events.length === 0) return

    const actorCounts: Record<string, number> = {}
    const actionCounts: Record<string, number> = {}

    events.forEach((event) => {
      // Count by actor
      const actorKey = `${event.actor_type}:${event.actor_id.substring(0, 8)}`
      actorCounts[actorKey] = (actorCounts[actorKey] || 0) + 1

      // Count by action
      actionCounts[event.action] = (actionCounts[event.action] || 0) + 1
    })

    // Calculate events per minute (using first and last event timestamps)
    let eventsPerMinute = 0
    if (events.length >= 2) {
      const firstEvent = events[events.length - 1]
      const lastEvent = events[0]
      const timeDiff = new Date(lastEvent.timestamp).getTime() - new Date(firstEvent.timestamp).getTime()
      const minutes = timeDiff / (1000 * 60)
      if (minutes > 0) {
        eventsPerMinute = Math.round(events.length / minutes)
      }
    }

    setStatistics({
      totalEvents: events.length,
      eventsPerMinute,
      connectedAt: isConnected ? statistics.connectedAt || new Date().toISOString() : null,
      lastEventAt: events[0]?.timestamp || null,
      actorCounts,
      actionCounts,
    })
  }, [events, isConnected])

  const handleStateChange = (state: ConnectionState) => {
    if (state === 'connected' && !statistics.connectedAt) {
      setStatistics((prev) => ({
        ...prev,
        connectedAt: new Date().toISOString(),
      }))
    } else if (state === 'disconnected') {
      setStatistics((prev) => ({
        ...prev,
        connectedAt: null,
      }))
    }
  }

  const handleError = (error: { code: string; message: string }) => {
    console.error('[AuditDashboard] Connection error:', error)
  }

  const formatTimestamp = (timestamp: string | null) => {
    if (!timestamp) return '-'
    const date = new Date(timestamp)
    return date.toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    })
  }

  const formatDuration = (start: string | null) => {
    if (!start) return '-'
    const diff = Date.now() - new Date(start).getTime()
    const seconds = Math.floor(diff / 1000)
    const minutes = Math.floor(seconds / 60)
    const hours = Math.floor(minutes / 60)

    if (hours > 0) {
      return `${hours}h ${minutes % 60}m`
    } else if (minutes > 0) {
      return `${minutes}m ${seconds % 60}s`
    }
    return `${seconds}s`
  }

  const topActions = Object.entries(statistics.actionCounts)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 5)

  const topActors = Object.entries(statistics.actorCounts)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 5)

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Audit Dashboard</h1>
          <p className="text-muted-foreground">
            Real-time audit event stream with origin validation
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => clearEvents()}
            disabled={events.length === 0}
          >
            <RefreshCw className="mr-2 h-4 w-4" />
            Clear Events
          </Button>
        </div>
      </div>

      {/* Connection Status Cards */}
      <div className="grid gap-4 md:grid-cols-4">
        {/* Connection State */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              {isConnected ? (
                <Wifi className="h-4 w-4 text-green-600" />
              ) : (
                <WifiOff className="h-4 w-4 text-muted-foreground" />
              )}
              Connection Status
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2">
              <Badge
                variant={
                  connectionState === 'connected'
                    ? 'default'
                    : connectionState === 'error' || connectionState === 'origin_rejected'
                      ? 'destructive'
                      : 'secondary'
                }
              >
                {connectionState.charAt(0).toUpperCase() + connectionState.slice(1)}
              </Badge>
            </div>
            {statistics.connectedAt && (
              <p className="text-xs text-muted-foreground mt-2">
                Connected for {formatDuration(statistics.connectedAt)}
              </p>
            )}
          </CardContent>
        </Card>

        {/* Total Events */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Activity className="h-4 w-4" />
              Total Events
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold">{statistics.totalEvents}</p>
            <p className="text-xs text-muted-foreground mt-1">
              {statistics.eventsPerMinute > 0 ? `${statistics.eventsPerMinute}/min` : 'In session'}
            </p>
          </CardContent>
        </Card>

        {/* Last Event */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Clock className="h-4 w-4" />
              Last Event
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-lg font-semibold">{formatTimestamp(statistics.lastEventAt)}</p>
            <p className="text-xs text-muted-foreground mt-1">
              {statistics.lastEventAt
                ? `${Math.round((Date.now() - new Date(statistics.lastEventAt).getTime()) / 1000)}s ago`
                : 'Waiting for events'}
            </p>
          </CardContent>
        </Card>

        {/* Origin Status */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Globe className="h-4 w-4" />
              Origin Status
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2">
              {isConnected ? (
                <CheckCircle className="h-4 w-4 text-green-600" />
              ) : connectionState === 'origin_rejected' ? (
                <AlertCircle className="h-4 w-4 text-red-600" />
              ) : (
                <Shield className="h-4 w-4 text-muted-foreground" />
              )}
              <span className="text-sm font-medium">
                {connectionState === 'origin_rejected' ? 'Not Allowed' : isConnected ? 'Validated' : 'Pending'}
              </span>
            </div>
            <p className="text-xs text-muted-foreground mt-1 truncate">
              {currentOrigin}
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Main Content Grid */}
      <div className="grid gap-6 lg:grid-cols-2">
        {/* Connection Panel */}
        <div className="space-y-4">
          <h2 className="text-lg font-semibold">Stream Connection</h2>
          <AuditStream
            autoConnect={autoConnect}
            onStateChange={handleStateChange}
            onError={handleError}
          />
        </div>

        {/* Live Events Feed */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold">Live Events Feed</h2>
            {events.length > 0 && (
              <Badge variant="secondary">{events.length} events</Badge>
            )}
          </div>
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium">Recent Events</CardTitle>
            </CardHeader>
            <CardContent>
              {events.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
                  <Activity className="h-8 w-8 mb-2 opacity-50" />
                  <p className="text-sm">No events yet</p>
                  <p className="text-xs">Connect to the stream to see real-time events</p>
                </div>
              ) : (
                <div className="space-y-2 max-h-[300px] overflow-y-auto">
                  {events.slice(0, 10).map((event) => (
                    <div
                      key={event.id}
                      className="flex items-start gap-3 p-2 rounded bg-muted/30 hover:bg-muted/50 transition-colors"
                    >
                      <div className={`mt-0.5 ${
                        event.outcome === 'success' ? 'text-green-600' :
                        event.outcome === 'failure' ? 'text-red-600' :
                        'text-yellow-600'
                      }`}>
                        {event.outcome === 'success' ? (
                          <CheckCircle className="h-3.5 w-3.5" />
                        ) : event.outcome === 'failure' ? (
                          <AlertCircle className="h-3.5 w-3.5" />
                        ) : (
                          <Clock className="h-3.5 w-3.5" />
                        )}
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium truncate">{event.action}</p>
                        <p className="text-xs text-muted-foreground">
                          {event.actor_type}:{event.actor_id.substring(0, 8)} → {event.resource_type}
                        </p>
                      </div>
                      <span className="text-xs text-muted-foreground whitespace-nowrap">
                        {new Date(event.timestamp).toLocaleTimeString()}
                      </span>
                    </div>
                  ))}
                  {events.length > 10 && (
                    <p className="text-xs text-center text-muted-foreground pt-2">
                      +{events.length - 10} more events
                    </p>
                  )}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Analytics Section */}
      {events.length > 0 && (
        <div className="grid gap-6 lg:grid-cols-2">
          {/* Top Actions */}
          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <TrendingUp className="h-4 w-4" />
                Top Actions
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {topActions.map(([action, count]) => {
                  const percentage = (count / statistics.totalEvents) * 100
                  return (
                    <div key={action}>
                      <div className="flex items-center justify-between text-sm mb-1">
                        <span className="truncate mr-2" title={action}>{action}</span>
                        <span className="text-muted-foreground whitespace-nowrap">{count}</span>
                      </div>
                      <div className="h-1.5 bg-muted rounded-full overflow-hidden">
                        <div
                          className="h-full bg-blue-500 rounded-full"
                          style={{ width: `${percentage}%` }}
                        />
                      </div>
                    </div>
                  )
                })}
              </div>
            </CardContent>
          </Card>

          {/* Top Actors */}
          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <Activity className="h-4 w-4" />
                Top Actors
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {topActors.map(([actor, count]) => {
                  const percentage = (count / statistics.totalEvents) * 100
                  const [type, id] = actor.split(':')
                  return (
                    <div key={actor}>
                      <div className="flex items-center justify-between text-sm mb-1">
                        <div className="flex items-center gap-2 min-w-0">
                          <Badge variant="outline" className="text-[10px] px-1">
                            {type}
                          </Badge>
                          <span className="truncate" title={actor}>{id}</span>
                        </div>
                        <span className="text-muted-foreground whitespace-nowrap">{count}</span>
                      </div>
                      <div className="h-1.5 bg-muted rounded-full overflow-hidden">
                        <div
                          className="h-full bg-purple-500 rounded-full"
                          style={{ width: `${percentage}%` }}
                        />
                      </div>
                    </div>
                  )
                })}
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Allowed Origins Information */}
      {(allowedOrigins.length > 0 || connectionState === 'origin_rejected') && (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Shield className="h-4 w-4" />
              Origin Validation Configuration
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div>
                <p className="text-sm font-medium">Current Origin</p>
                <code className="text-xs bg-muted px-2 py-1 rounded mt-1 inline-block">
                  {currentOrigin}
                </code>
              </div>

              {allowedOrigins.length > 0 && (
                <div>
                  <p className="text-sm font-medium">Allowed Origins ({allowedOrigins.length})</p>
                  <div className="mt-2 flex flex-wrap gap-2">
                    {allowedOrigins.map((origin) => (
                      <Badge
                        key={origin}
                        variant={origin === currentOrigin ? 'default' : 'outline'}
                        className="font-mono text-xs"
                      >
                        {origin === currentOrigin && <CheckCircle className="h-3 w-3 mr-1" />}
                        {origin}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}

              {connectionState === 'origin_rejected' && (
                <div className="rounded bg-destructive/10 p-3 border border-destructive/20">
                  <div className="flex items-start gap-2">
                    <AlertCircle className="h-4 w-4 text-destructive mt-0.5 shrink-0" />
                    <div>
                      <p className="text-sm font-medium text-destructive">
                        Origin Not Authorized
                      </p>
                      <p className="text-xs text-muted-foreground mt-1">
                        The current origin is not in the allowed origins list. Contact your administrator
                        to add this origin to the audit service configuration.
                      </p>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Security Notice */}
      <Card className="border-blue-200 dark:border-blue-800 bg-blue-50/50 dark:bg-blue-950/20">
        <CardContent className="pt-6">
          <div className="flex items-start gap-3">
            <Shield className="h-5 w-5 text-primary dark:text-blue-400 mt-0.5 shrink-0" />
            <div className="space-y-1">
              <p className="text-sm font-medium text-blue-900 dark:text-blue-100">
                WebSocket Origin Validation
              </p>
              <p className="text-xs text-blue-700 dark:text-blue-300">
                The audit stream enforces strict origin validation to prevent Cross-Site WebSocket Hijacking (CSWSH) attacks.
                Only origins explicitly configured in the audit service are allowed to connect.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
