import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { RefreshCw, Shield, Globe, Monitor, Server, ChevronLeft, ChevronRight } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '../components/ui/select'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../components/ui/table'
import { api } from '../lib/api'
import { QueryError } from '../components/query-error'

interface AuditEvent {
  id: string
  source: string
  event_type: string
  route_id?: string
  route_name?: string
  user_id?: string
  user_email?: string
  actor_ip?: string
  details?: Record<string, unknown>
  created_at: string
}

interface AuditQueryResult {
  events: AuditEvent[]
  total: number
  sources: string[]
}

interface AuditSummary {
  total_last_24h: number
  by_source: Record<string, number>
}

const SourceIcon = ({ source }: { source: string }) => {
  switch (source) {
    case 'openidx':
      return <Server className="h-4 w-4 text-blue-500" />
    case 'ziti':
      return <Shield className="h-4 w-4 text-purple-500" />
    case 'guacamole':
      return <Monitor className="h-4 w-4 text-green-500" />
    default:
      return <Globe className="h-4 w-4 text-muted-foreground" />
  }
}

const SourceBadge = ({ source }: { source: string }) => {
  const colors: Record<string, string> = {
    openidx: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
    ziti: 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200',
    guacamole: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
  }
  return (
    <Badge className={colors[source] || 'bg-muted text-foreground'}>
      <SourceIcon source={source} />
      <span className="ml-1 capitalize">{source}</span>
    </Badge>
  )
}

export function UnifiedAuditPage() {
  const [page, setPage] = useState(0)
  const [source, setSource] = useState<string>('all')
  const [eventType, setEventType] = useState<string>('')
  const pageSize = 50

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['unified-audit', page, source, eventType],
    queryFn: async () => {
      const params = new URLSearchParams({
        limit: pageSize.toString(),
        offset: (page * pageSize).toString(),
      })
      if (source && source !== 'all') {
        params.set('source', source)
      }
      if (eventType) {
        params.set('event_type', eventType)
      }
      return api.get<AuditQueryResult>(`/api/v1/access/audit/unified?${params}`)
    },
    refetchInterval: 30000,
  })

  const { data: summary } = useQuery({
    queryKey: ['unified-audit-summary'],
    queryFn: async () => {
      return api.get<AuditSummary>('/api/v1/access/audit/unified/summary')
    },
    refetchInterval: 60000,
  })

  const totalPages = Math.ceil((data?.total || 0) / pageSize)

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold">Unified Audit Log</h1>
          <p className="text-muted-foreground mt-1">
            Combined events from OpenIDX, Ziti, and Guacamole
          </p>
        </div>
        <Button variant="outline" onClick={() => refetch()}>
          <RefreshCw className="h-4 w-4 mr-2" />
          Refresh
        </Button>
      </div>

      {/* Summary Cards */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Total (24h)</CardDescription>
            <CardTitle className="text-2xl">{summary?.total_last_24h || 0}</CardTitle>
          </CardHeader>
        </Card>
        {summary?.by_source && Object.entries(summary.by_source).map(([src, count]) => (
          <Card key={src}>
            <CardHeader className="pb-2">
              <CardDescription className="flex items-center gap-2">
                <SourceIcon source={src} />
                <span className="capitalize">{src}</span>
              </CardDescription>
              <CardTitle className="text-2xl">{count as number}</CardTitle>
            </CardHeader>
          </Card>
        ))}
      </div>

      {/* Filters */}
      <Card>
        <CardContent className="pt-6">
          <div className="flex flex-wrap gap-4">
            <div className="flex-1 min-w-[200px]">
              <Select value={source} onValueChange={setSource}>
                <SelectTrigger>
                  <SelectValue placeholder="All Sources" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Sources</SelectItem>
                  <SelectItem value="openidx">OpenIDX</SelectItem>
                  <SelectItem value="ziti">Ziti</SelectItem>
                  <SelectItem value="guacamole">Guacamole</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="flex-1 min-w-[200px]">
              <Input
                placeholder="Filter by event type..."
                value={eventType}
                onChange={(e) => setEventType(e.target.value)}
                className="w-full"
              />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Events Table */}
      <Card>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="flex items-center justify-center py-12">
              <LoadingSpinner />
            </div>
          ) : isError ? (
            <div className="p-4"><QueryError error={error} resource="audit events" /></div>
          ) : (
            <Table>
                <TableHeader className="bg-muted">
                  <TableRow>
                    <TableHead className="text-left p-4 font-medium">Timestamp</TableHead>
                    <TableHead className="text-left p-4 font-medium">Source</TableHead>
                    <TableHead className="text-left p-4 font-medium">Event</TableHead>
                    <TableHead className="text-left p-4 font-medium">Service</TableHead>
                    <TableHead className="text-left p-4 font-medium">User</TableHead>
                    <TableHead className="text-left p-4 font-medium">IP</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody className="divide-y">
                  {data?.events?.map((event) => (
                    <TableRow key={event.id} className="hover:bg-muted/50">
                      <TableCell className="p-4 text-sm font-mono whitespace-nowrap">
                        {new Date(event.created_at).toLocaleString()}
                      </TableCell>
                      <TableCell className="p-4">
                        <SourceBadge source={event.source} />
                      </TableCell>
                      <TableCell className="p-4">
                        <span className="font-medium">{event.event_type}</span>
                      </TableCell>
                      <TableCell className="p-4 text-sm">
                        {event.route_name || event.route_id || '-'}
                      </TableCell>
                      <TableCell className="p-4 text-sm">
                        {event.user_email || event.user_id || '-'}
                      </TableCell>
                      <TableCell className="p-4 text-sm font-mono">
                        {event.actor_ip || '-'}
                      </TableCell>
                    </TableRow>
                  ))}
                  {(!data?.events || data.events.length === 0) && (
                    <TableRow>
                      <TableCell colSpan={6} className="p-8 text-center text-muted-foreground">
                        No audit events found
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
          )}
        </CardContent>
      </Card>

      {/* Pagination */}
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          Showing {page * pageSize + 1} - {Math.min((page + 1) * pageSize, data?.total || 0)} of {data?.total || 0} events
        </p>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => setPage(p => p - 1)}
            disabled={page === 0}
          >
            <ChevronLeft className="h-4 w-4 mr-1" />
            Previous
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => setPage(p => p + 1)}
            disabled={page >= totalPages - 1}
          >
            Next
            <ChevronRight className="h-4 w-4 ml-1" />
          </Button>
        </div>
      </div>
    </div>
  )
}
