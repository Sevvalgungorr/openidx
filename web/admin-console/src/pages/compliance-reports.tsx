import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Plus,
  FileText,
  Download,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Shield,
  Calendar,
  Clock,
  RefreshCw,
  ChevronLeft,
  ChevronRight,
  MoreHorizontal,
  Eye,
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table'
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem,
  DropdownMenuTrigger,
} from '../components/ui/dropdown-menu'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '../components/ui/dialog'
import { Label } from '../components/ui/label'
import { Input } from '../components/ui/input'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'
import { QueryError } from '../components/query-error'

interface ComplianceReport {
  id: string
  name: string
  type: string
  framework: string
  status: string
  start_date: string
  end_date: string
  generated_at: string
  generated_by: string
  summary: {
    total_controls: number
    passed_controls: number
    failed_controls: number
    partial_controls: number
    not_applicable: number
  }
  findings: ReportFinding[]
}

interface ReportFinding {
  control_id: string
  control_name: string
  status: string
  evidence: string
  remediation: string
}

const reportTypeLabels: Record<string, string> = {
  soc2: 'SOC 2 Type II',
  iso27001: 'ISO 27001:2022',
  gdpr: 'GDPR',
  hipaa: 'HIPAA',
  pci_dss: 'PCI-DSS v4.0',
  custom: 'Custom',
}

const reportTypeColors: Record<string, string> = {
  soc2: 'bg-blue-100 text-blue-800',
  iso27001: 'bg-purple-100 text-purple-800',
  gdpr: 'bg-green-100 text-green-800',
  hipaa: 'bg-red-100 text-red-800',
  pci_dss: 'bg-orange-100 text-orange-800',
  custom: 'bg-muted text-foreground',
}

const statusIcons: Record<string, React.ReactNode> = {
  completed: <CheckCircle className="h-4 w-4 text-green-600" />,
  generating: <RefreshCw className="h-4 w-4 text-primary animate-spin" />,
  pending: <Clock className="h-4 w-4 text-yellow-600" />,
  failed: <XCircle className="h-4 w-4 text-red-600" />,
}

export function ComplianceReportsPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [generateModal, setGenerateModal] = useState(false)
  const [viewModal, setViewModal] = useState(false)
  const [selectedReport, setSelectedReport] = useState<ComplianceReport | null>(null)
  const [formData, setFormData] = useState({
    type: 'soc2',
    start_date: '',
    end_date: '',
  })
  const [page, setPage] = useState(0)
  const [totalCount, setTotalCount] = useState(0)
  const PAGE_SIZE = 20

  const { data: reports, isLoading, isError, error } = useQuery({
    queryKey: ['compliance-reports', page],
    queryFn: async () => {
      const params = new URLSearchParams()
      params.set('offset', String(page * PAGE_SIZE))
      params.set('limit', String(PAGE_SIZE))
      const result = await api.getWithHeaders<ComplianceReport[]>(`/api/v1/audit/reports?${params.toString()}`)
      const total = parseInt(result.headers['x-total-count'] || '0', 10)
      if (!isNaN(total)) setTotalCount(total)
      return result.data
    },
  })

  const generateReportMutation = useMutation({
    mutationFn: (data: { type: string; start_date: string; end_date: string }) =>
      api.post<ComplianceReport>('/api/v1/audit/reports', data),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['compliance-reports'] })
      toast({
        title: 'Report Generated',
        description: `${reportTypeLabels[data.type] || data.type} compliance report has been generated.`,
        variant: 'success',
      })
      setGenerateModal(false)
      setSelectedReport(data)
      setViewModal(true)
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: `Failed to generate report: ${error.message}`,
        variant: 'destructive',
      })
    },
  })

  const handleFormChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
    const { name, value } = e.target
    setFormData(prev => ({ ...prev, [name]: value }))
  }

  const handleGenerateSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    generateReportMutation.mutate({
      type: formData.type,
      start_date: new Date(formData.start_date).toISOString(),
      end_date: new Date(formData.end_date).toISOString(),
    })
  }

  const handleViewReport = (report: ComplianceReport) => {
    setSelectedReport(report)
    setViewModal(true)
  }

  const handleDownloadReport = async (report: ComplianceReport) => {
    try {
      const response = await api.get<Blob>(`/api/v1/audit/reports/${report.id}/download?format=csv`, {
        responseType: 'blob',
      })
      const blob = new Blob([response], { type: 'text/csv' })
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${report.type}_compliance_report_${report.generated_at.split('T')[0]}.csv`
      document.body.appendChild(a)
      a.click()
      window.URL.revokeObjectURL(url)
      document.body.removeChild(a)
    } catch {
      toast({
        title: 'Error',
        description: 'Failed to download report',
        variant: 'destructive',
      })
    }
  }

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    })
  }

  const calculateComplianceScore = (summary: ComplianceReport['summary']) => {
    if (summary.total_controls === 0) return 0
    const applicable = summary.total_controls - summary.not_applicable
    if (applicable === 0) return 100
    return Math.round((summary.passed_controls / applicable) * 100)
  }

  const getScoreColor = (score: number) => {
    if (score >= 90) return 'text-green-600'
    if (score >= 70) return 'text-yellow-600'
    return 'text-red-600'
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Compliance Reports</h1>
          <p className="text-muted-foreground">Generate and view compliance reports</p>
        </div>
        <Button onClick={() => setGenerateModal(true)}>
          <Plus className="mr-2 h-4 w-4" /> Generate Report
        </Button>
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="h-12 w-12 rounded-lg bg-blue-100 flex items-center justify-center">
                <Shield className="h-6 w-6 text-blue-700" />
              </div>
              <div>
                <p className="text-2xl font-bold">
                  {reports?.filter(r => r.type === 'soc2').length || 0}
                </p>
                <p className="text-sm text-muted-foreground">SOC 2 Reports</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="h-12 w-12 rounded-lg bg-purple-100 flex items-center justify-center">
                <Shield className="h-6 w-6 text-purple-700" />
              </div>
              <div>
                <p className="text-2xl font-bold">
                  {reports?.filter(r => r.type === 'iso27001').length || 0}
                </p>
                <p className="text-sm text-muted-foreground">ISO 27001 Reports</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="h-12 w-12 rounded-lg bg-green-100 flex items-center justify-center">
                <CheckCircle className="h-6 w-6 text-green-700" />
              </div>
              <div>
                <p className="text-2xl font-bold">
                  {reports?.filter(r => r.status === 'completed').length || 0}
                </p>
                <p className="text-sm text-muted-foreground">Completed</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="h-12 w-12 rounded-lg bg-muted flex items-center justify-center">
                <FileText className="h-6 w-6 text-foreground" />
              </div>
              <div>
                <p className="text-2xl font-bold">{reports?.length || 0}</p>
                <p className="text-sm text-muted-foreground">Total Reports</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Report History</CardTitle>
        </CardHeader>
        <CardContent>
          {isError ? (
            <QueryError error={error} resource="compliance reports" />
          ) : isLoading ? (
            <div className="flex flex-col items-center justify-center py-12">
              <LoadingSpinner size="lg" />
              <p className="mt-4 text-sm text-muted-foreground">Loading reports...</p>
            </div>
          ) : reports?.length === 0 ? (
            <div className="text-center py-12 text-muted-foreground">
              <FileText className="mx-auto h-12 w-12 text-muted-foreground mb-4" />
              <p>No compliance reports yet</p>
              <Button onClick={() => setGenerateModal(true)} className="mt-4">
                <Plus className="mr-2 h-4 w-4" />
                Generate First Report
              </Button>
            </div>
          ) : (
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Report</TableHead>
                    <TableHead>Framework</TableHead>
                    <TableHead>Period</TableHead>
                    <TableHead>Score</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="w-[50px]"></TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {reports?.map((report) => {
                    const score = calculateComplianceScore(report.summary)
                    return (
                      <TableRow key={report.id}>
                        <TableCell>
                          <div className="flex items-center gap-3">
                            <div className={`h-10 w-10 rounded-lg ${reportTypeColors[report.type]?.split(' ')[0] || 'bg-muted'} flex items-center justify-center`}>
                              <Shield className="h-5 w-5" />
                            </div>
                            <div>
                              <p className="font-medium">{report.name || reportTypeLabels[report.type]}</p>
                              <p className="text-sm text-muted-foreground">Generated {formatDate(report.generated_at)}</p>
                            </div>
                          </div>
                        </TableCell>
                        <TableCell>
                          <Badge className={reportTypeColors[report.type]}>
                            {report.framework || reportTypeLabels[report.type]}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <div className="text-sm">
                            <p>{formatDate(report.start_date)}</p>
                            <p className="text-muted-foreground">to {formatDate(report.end_date)}</p>
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <span className={`text-2xl font-bold ${getScoreColor(score)}`}>{score}%</span>
                            <div className="text-xs text-muted-foreground">
                              <p>{report.summary.passed_controls}/{report.summary.total_controls - report.summary.not_applicable} passed</p>
                            </div>
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-1">
                            {statusIcons[report.status]}
                            <Badge variant={report.status === 'completed' ? 'default' : 'secondary'}>
                              {report.status}
                            </Badge>
                          </div>
                        </TableCell>
                        <TableCell>
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button variant="ghost" size="sm" className="h-8 w-8 p-0">
                                <MoreHorizontal className="h-4 w-4" />
                              </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                              <DropdownMenuItem onClick={() => handleViewReport(report)}>
                                <Eye className="mr-2 h-4 w-4" />
                                View Report
                              </DropdownMenuItem>
                              <DropdownMenuItem onClick={() => handleDownloadReport(report)}>
                                <Download className="mr-2 h-4 w-4" />
                                Download CSV
                              </DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </TableCell>
                      </TableRow>
                    )
                  })}
                </TableBody>
              </Table>
            </div>
          )}
          {totalCount > PAGE_SIZE && (
            <div className="flex items-center justify-between pt-4">
              <span className="text-sm text-muted-foreground">
                Page {page + 1} of {Math.ceil(totalCount / PAGE_SIZE)}
              </span>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0}>
                  <ChevronLeft className="h-4 w-4 mr-1" /> Previous
                </Button>
                <Button variant="outline" size="sm" onClick={() => setPage(p => p + 1)} disabled={(page + 1) * PAGE_SIZE >= totalCount}>
                  Next <ChevronRight className="h-4 w-4 ml-1" />
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Generate Report Modal */}
      <Dialog open={generateModal} onOpenChange={setGenerateModal}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Generate Compliance Report</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleGenerateSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="type">Framework *</Label>
              <select
                id="type"
                name="type"
                value={formData.type}
                onChange={handleFormChange}
                className="w-full px-3 py-2 border border-border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                required
              >
                <option value="soc2">SOC 2 Type II</option>
                <option value="iso27001">ISO 27001:2022</option>
                <option value="gdpr">GDPR</option>
                <option value="hipaa">HIPAA</option>
                <option value="pci_dss">PCI-DSS v4.0</option>
              </select>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="start_date">Start Date *</Label>
                <div className="relative">
                  <Calendar className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                  <Input
                    id="start_date"
                    name="start_date"
                    type="date"
                    value={formData.start_date}
                    onChange={handleFormChange}
                    className="pl-10"
                    required
                  />
                </div>
              </div>
              <div className="space-y-2">
                <Label htmlFor="end_date">End Date *</Label>
                <div className="relative">
                  <Calendar className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                  <Input
                    id="end_date"
                    name="end_date"
                    type="date"
                    value={formData.end_date}
                    onChange={handleFormChange}
                    className="pl-10"
                    required
                  />
                </div>
              </div>
            </div>
            <div className="bg-blue-50 p-4 rounded-lg">
              <p className="text-sm text-blue-800">
                The report will analyze audit logs within the specified date range and evaluate compliance against {reportTypeLabels[formData.type]} controls.
              </p>
            </div>
            <div className="flex justify-end gap-2 pt-4">
              <Button
                type="button"
                variant="outline"
                onClick={() => setGenerateModal(false)}
                disabled={generateReportMutation.isPending}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={generateReportMutation.isPending}>
                {generateReportMutation.isPending ? (
                  <>
                    <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
                    Generating...
                  </>
                ) : (
                  'Generate Report'
                )}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* View Report Modal */}
      <Dialog open={viewModal} onOpenChange={setViewModal}>
        <DialogContent className="sm:max-w-3xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>
              {selectedReport?.name || reportTypeLabels[selectedReport?.type || '']} Report
            </DialogTitle>
          </DialogHeader>
          {selectedReport && (
            <div className="space-y-6">
              {/* Summary */}
              <div className="grid grid-cols-5 gap-4">
                <Card>
                  <CardContent className="pt-4 pb-4 text-center">
                    <p className="text-3xl font-bold">{selectedReport.summary.total_controls}</p>
                    <p className="text-xs text-muted-foreground">Total</p>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="pt-4 pb-4 text-center">
                    <p className="text-3xl font-bold text-green-600">{selectedReport.summary.passed_controls}</p>
                    <p className="text-xs text-muted-foreground">Passed</p>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="pt-4 pb-4 text-center">
                    <p className="text-3xl font-bold text-red-600">{selectedReport.summary.failed_controls}</p>
                    <p className="text-xs text-muted-foreground">Failed</p>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="pt-4 pb-4 text-center">
                    <p className="text-3xl font-bold text-yellow-600">{selectedReport.summary.partial_controls}</p>
                    <p className="text-xs text-muted-foreground">Partial</p>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="pt-4 pb-4 text-center">
                    <p className="text-3xl font-bold text-muted-foreground">{selectedReport.summary.not_applicable}</p>
                    <p className="text-xs text-muted-foreground">N/A</p>
                  </CardContent>
                </Card>
              </div>

              {/* Compliance Score */}
              <Card>
                <CardContent className="pt-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-muted-foreground">Compliance Score</p>
                      <p className={`text-4xl font-bold ${getScoreColor(calculateComplianceScore(selectedReport.summary))}`}>
                        {calculateComplianceScore(selectedReport.summary)}%
                      </p>
                    </div>
                    <div className="w-32 h-32 relative">
                      <svg className="w-full h-full transform -rotate-90">
                        <circle
                          cx="64"
                          cy="64"
                          r="56"
                          fill="none"
                          stroke="#e5e7eb"
                          strokeWidth="12"
                        />
                        <circle
                          cx="64"
                          cy="64"
                          r="56"
                          fill="none"
                          stroke={calculateComplianceScore(selectedReport.summary) >= 90 ? '#22c55e' : calculateComplianceScore(selectedReport.summary) >= 70 ? '#eab308' : '#ef4444'}
                          strokeWidth="12"
                          strokeDasharray={`${(calculateComplianceScore(selectedReport.summary) / 100) * 352} 352`}
                          strokeLinecap="round"
                        />
                      </svg>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Findings */}
              <Card>
                <CardHeader>
                  <CardTitle>Control Findings</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {selectedReport.findings?.map((finding, index) => (
                      <div key={index} className="flex items-start gap-3 p-3 border rounded-lg">
                        <div className="mt-0.5">
                          {finding.status === 'passed' && <CheckCircle className="h-5 w-5 text-green-600" />}
                          {finding.status === 'failed' && <XCircle className="h-5 w-5 text-red-600" />}
                          {finding.status === 'partial' && <AlertTriangle className="h-5 w-5 text-yellow-600" />}
                        </div>
                        <div className="flex-1">
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-sm bg-muted px-2 py-0.5 rounded">
                              {finding.control_id}
                            </span>
                            <span className="font-medium">{finding.control_name}</span>
                          </div>
                          {finding.evidence && (
                            <p className="text-sm text-muted-foreground mt-1">{finding.evidence}</p>
                          )}
                          {finding.remediation && finding.status !== 'passed' && (
                            <p className="text-sm text-orange-600 mt-1">
                              Remediation: {finding.remediation}
                            </p>
                          )}
                        </div>
                        <Badge variant={
                          finding.status === 'passed' ? 'default' :
                          finding.status === 'failed' ? 'destructive' : 'secondary'
                        }>
                          {finding.status}
                        </Badge>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              <div className="flex justify-end gap-2">
                <Button variant="outline" onClick={() => handleDownloadReport(selectedReport)}>
                  <Download className="mr-2 h-4 w-4" />
                  Download CSV
                </Button>
                <Button onClick={() => setViewModal(false)}>Close</Button>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}
