import { useQuery } from '@tanstack/react-query'
import { Shield, FileCheck, AlertTriangle, Users, Clock, Eye } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../components/ui/table'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'
import { useNavigate } from 'react-router-dom'

interface ConsentBreakdown {
  consent_type: string
  granted: number
  revoked: number
}

interface RecentDSAR {
  id: string
  request_type: string
  status: string
  username: string
  created_at: string
}

interface PrivacyDashboardData {
  total_consents: number
  active_dsars: number
  overdue_dsars: number
  total_assessments: number
  consent_breakdown: ConsentBreakdown[]
  recent_dsars: RecentDSAR[]
}

function SummaryCard({
  title,
  value,
  icon: Icon,
  iconBg,
  iconColor,
}: {
  title: string
  value: number
  icon: React.ComponentType<{ className?: string }>
  iconBg: string
  iconColor: string
}) {
  return (
    <Card>
      <CardContent className="pt-6">
        <div className="flex items-center gap-3">
          <div className={`h-10 w-10 rounded-lg ${iconBg} flex items-center justify-center`}>
            <Icon className={`h-5 w-5 ${iconColor}`} />
          </div>
          <div>
            <p className="text-2xl font-bold">{value}</p>
            <p className="text-sm text-muted-foreground">{title}</p>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

function getStatusBadge(status: string) {
  const styles: Record<string, string> = {
    pending: 'bg-yellow-100 text-yellow-800',
    in_progress: 'bg-blue-100 text-blue-800',
    completed: 'bg-green-100 text-green-800',
    rejected: 'bg-red-100 text-red-800',
  }

  const labels: Record<string, string> = {
    pending: 'Pending',
    in_progress: 'In Progress',
    completed: 'Completed',
    rejected: 'Rejected',
  }

  return (
    <Badge className={styles[status] || 'bg-muted text-foreground'}>
      {labels[status] || status}
    </Badge>
  )
}

function formatDate(dateStr: string): string {
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

export function PrivacyDashboardPage() {
  const navigate = useNavigate()

  const { data: dashboard, isLoading, error } = useQuery({
    queryKey: ['privacy-dashboard'],
    queryFn: () => api.get<PrivacyDashboardData>('/api/v1/privacy/dashboard'),
    refetchInterval: 60000,
  })

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center py-24">
        <LoadingSpinner size="lg" />
        <p className="mt-4 text-sm text-muted-foreground">Loading privacy dashboard...</p>
      </div>
    )
  }

  if (error) {
    return <QueryError error={error} resource="the privacy dashboard" />
  }

  const d = dashboard || {
    total_consents: 0,
    active_dsars: 0,
    overdue_dsars: 0,
    total_assessments: 0,
    consent_breakdown: [],
    recent_dsars: [],
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Privacy Dashboard</h1>
        <p className="text-muted-foreground">
          GDPR compliance overview and data subject request management
        </p>
      </div>

      {/* Summary Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <SummaryCard
          title="Total Consents"
          value={d.total_consents}
          icon={Users}
          iconBg="bg-blue-100"
          iconColor="text-blue-700"
        />
        <SummaryCard
          title="Active DSARs"
          value={d.active_dsars}
          icon={Clock}
          iconBg="bg-purple-100"
          iconColor="text-purple-700"
        />
        <SummaryCard
          title="Overdue DSARs"
          value={d.overdue_dsars}
          icon={AlertTriangle}
          iconBg={d.overdue_dsars > 0 ? 'bg-red-100' : 'bg-green-100'}
          iconColor={d.overdue_dsars > 0 ? 'text-red-700' : 'text-green-700'}
        />
        <SummaryCard
          title="Impact Assessments"
          value={d.total_assessments}
          icon={FileCheck}
          iconBg="bg-green-100"
          iconColor="text-green-700"
        />
      </div>

      {/* Quick Actions */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Quick Actions
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-3">
            <Button
              variant="outline"
              onClick={() => navigate('/consent-management?tab=dsars')}
            >
              <Eye className="h-4 w-4 mr-2" />
              View All DSARs
            </Button>
            <Button
              variant="outline"
              onClick={() => navigate('/consent-management?tab=consents')}
            >
              <Users className="h-4 w-4 mr-2" />
              Manage Consents
            </Button>
            <Button
              variant="outline"
              onClick={() => navigate('/consent-management?tab=retention')}
            >
              <Clock className="h-4 w-4 mr-2" />
              Retention Policies
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Consent Breakdown */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Consent Breakdown
          </CardTitle>
        </CardHeader>
        <CardContent>
          {d.consent_breakdown.length === 0 ? (
            <p className="text-sm text-muted-foreground py-4 text-center">
              No consent data available
            </p>
          ) : (
            <Table className="text-sm">
                <TableHeader>
                  <TableRow className="border-b">
                    <TableHead className="text-left py-3 px-4 font-medium text-muted-foreground">
                      Consent Type
                    </TableHead>
                    <TableHead className="text-right py-3 px-4 font-medium text-muted-foreground">
                      Granted
                    </TableHead>
                    <TableHead className="text-right py-3 px-4 font-medium text-muted-foreground">
                      Revoked
                    </TableHead>
                    <TableHead className="text-right py-3 px-4 font-medium text-muted-foreground">
                      Rate
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {d.consent_breakdown.map((item) => {
                    const total = item.granted + item.revoked
                    const rate = total > 0 ? Math.round((item.granted / total) * 100) : 0
                    return (
                      <TableRow key={item.consent_type} className="border-b last:border-0">
                        <TableCell className="py-3 px-4 font-medium capitalize">
                          {item.consent_type.replace(/_/g, ' ')}
                        </TableCell>
                        <TableCell className="py-3 px-4 text-right">
                          <Badge className="bg-green-100 text-green-800">
                            {item.granted}
                          </Badge>
                        </TableCell>
                        <TableCell className="py-3 px-4 text-right">
                          <Badge className="bg-red-100 text-red-800">
                            {item.revoked}
                          </Badge>
                        </TableCell>
                        <TableCell className="py-3 px-4 text-right">
                          <span className={rate >= 80 ? 'text-green-600' : rate >= 50 ? 'text-yellow-600' : 'text-red-600'}>
                            {rate}%
                          </span>
                        </TableCell>
                      </TableRow>
                    )
                  })}
                </TableBody>
              </Table>
          )}
        </CardContent>
      </Card>

      {/* Recent DSARs */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2">
              <FileCheck className="h-5 w-5" />
              Recent Data Subject Access Requests
            </CardTitle>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => navigate('/consent-management?tab=dsars')}
            >
              View All
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {d.recent_dsars.length === 0 ? (
            <p className="text-sm text-muted-foreground py-4 text-center">
              No recent DSARs
            </p>
          ) : (
            <Table className="text-sm">
                <TableHeader>
                  <TableRow className="border-b">
                    <TableHead className="text-left py-3 px-4 font-medium text-muted-foreground">Type</TableHead>
                    <TableHead className="text-left py-3 px-4 font-medium text-muted-foreground">User</TableHead>
                    <TableHead className="text-left py-3 px-4 font-medium text-muted-foreground">Status</TableHead>
                    <TableHead className="text-left py-3 px-4 font-medium text-muted-foreground">Created</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {d.recent_dsars.map((dsar) => (
                    <TableRow key={dsar.id} className="border-b last:border-0 hover:bg-muted">
                      <TableCell className="py-3 px-4 font-medium">
                        {formatRequestType(dsar.request_type)}
                      </TableCell>
                      <TableCell className="py-3 px-4 text-muted-foreground">{dsar.username}</TableCell>
                      <TableCell className="py-3 px-4">{getStatusBadge(dsar.status)}</TableCell>
                      <TableCell className="py-3 px-4 text-muted-foreground">
                        {formatDate(dsar.created_at)}
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
