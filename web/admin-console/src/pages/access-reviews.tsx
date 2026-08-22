import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../lib/auth'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Search, ClipboardCheck, ClipboardList, Clock, CheckCircle, XCircle, AlertTriangle, Edit, Play, Eye, MoreHorizontal, ChevronLeft, ChevronRight } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '../components/ui/dialog'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '../components/ui/dropdown-menu'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select'
import { Label } from '../components/ui/label'
import { Textarea } from '../components/ui/textarea'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../components/ui/table'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

interface AccessReview {
  id: string
  name: string
  description: string
  type: string
  status: string
  reviewer_id: string
  start_date: string
  end_date: string
  created_at: string
  completed_at: string | null
  total_items: number
  reviewed_items: number
}

const statusIcons: Record<string, React.ReactNode> = {
  pending: <Clock className="h-4 w-4" />,
  in_progress: <ClipboardCheck className="h-4 w-4" />,
  completed: <CheckCircle className="h-4 w-4" />,
  expired: <XCircle className="h-4 w-4" />,
  canceled: <AlertTriangle className="h-4 w-4" />,
}

const statusColors: Record<string, string> = {
  pending: 'bg-yellow-100 text-yellow-800',
  in_progress: 'bg-blue-100 text-blue-800',
  completed: 'bg-green-100 text-green-800',
  expired: 'bg-red-100 text-red-800',
  canceled: 'bg-muted text-foreground',
}

const typeLabels: Record<string, string> = {
  user_access: 'User Access',
  role_assignment: 'Role Assignment',
  application_access: 'Application Access',
  privileged_access: 'Privileged Access',
}

export function AccessReviewsPage() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const { user } = useAuth()
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [createModal, setCreateModal] = useState(false)
  const [editModal, setEditModal] = useState(false)
  const [selectedReview, setSelectedReview] = useState<AccessReview | null>(null)
  const [newReview, setNewReview] = useState({
    name: '',
    description: '',
    type: 'user_access',
    start_date: '',
    end_date: '',
  })
  const [editReview, setEditReview] = useState({
    name: '',
    description: '',
    type: 'user_access',
    start_date: '',
    end_date: '',
  })
  const [page, setPage] = useState(0)
  const [totalCount, setTotalCount] = useState(0)
  const PAGE_SIZE = 20

  const { data: reviews, isLoading, isError, error } = useQuery({
    queryKey: ['access-reviews', search, statusFilter, page],
    queryFn: async () => {
      const params = new URLSearchParams()
      if (search) params.set('search', search)
      if (statusFilter) params.set('status', statusFilter)
      params.set('offset', String(page * PAGE_SIZE))
      params.set('limit', String(PAGE_SIZE))
      const result = await api.getWithHeaders<AccessReview[]>(`/api/v1/governance/reviews?${params.toString()}`)
      const total = parseInt(result.headers['x-total-count'] || '0', 10)
      if (!isNaN(total)) setTotalCount(total)
      return result.data
    },
  })

  // Create access review mutation
  const createReviewMutation = useMutation({
    mutationFn: (reviewData: { name: string; description: string; type: string; reviewer_id: string; start_date: string; end_date: string }) => api.post('/api/v1/governance/reviews', reviewData),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['access-reviews'] })
      toast({
        title: 'Success',
        description: 'Access review created successfully!',
        variant: 'success',
      })
      setCreateModal(false)
      setNewReview({
        name: '',
        description: '',
        type: 'user_access',
        start_date: '',
        end_date: '',
      })
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: `Failed to create access review: ${error.message}`,
        variant: 'destructive',
      })
    },
  })

  // Reviews are filtered server-side via search param
  const filteredReviews = reviews

  const getProgress = (review: AccessReview) => {
    if (review.total_items === 0) return 0
    return Math.round((review.reviewed_items / review.total_items) * 100)
  }

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    })
  }

  const handleNewReviewChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    const { name, value } = e.target
    setNewReview(prev => ({ ...prev, [name]: value }))
  }

  const handleCreateSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (newReview.end_date && newReview.start_date && new Date(newReview.end_date) <= new Date(newReview.start_date)) {
      toast({ title: 'Validation Error', description: 'End date must be after start date', variant: 'destructive' })
      return
    }
    createReviewMutation.mutate({
      name: newReview.name,
      description: newReview.description,
      type: newReview.type,
      reviewer_id: user?.id || '',
      start_date: new Date(newReview.start_date).toISOString(),
      end_date: new Date(newReview.end_date).toISOString(),
    })
  }

  const handleEditReview = (review: AccessReview) => {
    setSelectedReview(review)
    setEditReview({
      name: review.name,
      description: review.description || '',
      type: review.type,
      start_date: review.start_date.split('T')[0], // Extract date part
      end_date: review.end_date.split('T')[0], // Extract date part
    })
    setEditModal(true)
  }

  const handleEditReviewChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    const { name, value } = e.target
    setEditReview(prev => ({ ...prev, [name]: value }))
  }

  const updateReviewMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<AccessReview> }) =>
      api.put(`/api/v1/governance/reviews/${id}`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['access-reviews'] })
      toast({
        title: 'Success',
        description: 'Access review updated successfully!',
        variant: 'success',
      })
      setEditModal(false)
      setSelectedReview(null)
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: `Failed to update review: ${error.message}`,
        variant: 'destructive',
      })
    },
  })

  const startReviewMutation = useMutation({
    mutationFn: (id: string) => api.patch(`/api/v1/governance/reviews/${id}/status`, { status: 'in_progress' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['access-reviews'] })
      toast({
        title: 'Review Started',
        description: 'Access review has been started and items populated.',
        variant: 'success',
      })
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: `Failed to start review: ${error.message}`,
        variant: 'destructive',
      })
    },
  })

  const handleEditSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!selectedReview) return

    updateReviewMutation.mutate({
      id: selectedReview.id,
      data: {
        name: editReview.name,
        description: editReview.description,
        start_date: new Date(editReview.start_date).toISOString(),
        end_date: new Date(editReview.end_date).toISOString(),
      },
    })
  }

  const handleStartReview = (review: AccessReview) => {
    startReviewMutation.mutate(review.id)
  }

  const handleViewReview = (review: AccessReview) => {
    navigate(`/access-reviews/${review.id}`)
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Access Reviews</h1>
          <p className="text-muted-foreground">Manage access certifications and reviews</p>
        </div>
        <Button onClick={() => setCreateModal(true)}>
          <Plus className="mr-2 h-4 w-4" /> Create Review
        </Button>
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="h-12 w-12 rounded-lg bg-yellow-100 flex items-center justify-center">
                <Clock className="h-6 w-6 text-yellow-700" />
              </div>
              <div>
                <p className="text-2xl font-bold">
                  {reviews?.filter(r => r.status === 'pending').length || 0}
                </p>
                <p className="text-sm text-muted-foreground">Pending (this page)</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="h-12 w-12 rounded-lg bg-blue-100 flex items-center justify-center">
                <ClipboardCheck className="h-6 w-6 text-blue-700" />
              </div>
              <div>
                <p className="text-2xl font-bold">
                  {reviews?.filter(r => r.status === 'in_progress').length || 0}
                </p>
                <p className="text-sm text-muted-foreground">In Progress (this page)</p>
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
                  {reviews?.filter(r => r.status === 'completed').length || 0}
                </p>
                <p className="text-sm text-muted-foreground">Completed (this page)</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="h-12 w-12 rounded-lg bg-muted flex items-center justify-center">
                <XCircle className="h-6 w-6 text-foreground" />
              </div>
              <div>
                <p className="text-2xl font-bold">
                  {reviews?.filter(r => r.status === 'expired' || r.status === 'canceled').length || 0}
                </p>
                <p className="text-sm text-muted-foreground">Expired/Canceled (this page)</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder="Search reviews..."
                value={search}
                onChange={(e) => { setSearch(e.target.value); setPage(0) }}
                className="pl-9"
              />
            </div>
            <Select value={statusFilter} onValueChange={(val) => { setStatusFilter(val === 'all' ? '' : val); setPage(0) }}>
              <SelectTrigger className="w-[180px]">
                <SelectValue placeholder="All Statuses" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Statuses</SelectItem>
                <SelectItem value="pending">Pending</SelectItem>
                <SelectItem value="in_progress">In Progress</SelectItem>
                <SelectItem value="completed">Completed</SelectItem>
                <SelectItem value="expired">Expired</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex flex-col items-center justify-center py-12">
              <LoadingSpinner size="lg" />
              <p className="mt-4 text-sm text-muted-foreground">Loading access reviews...</p>
            </div>
          ) : isError ? (
            <QueryError error={error} resource="access reviews" />
          ) : !filteredReviews || filteredReviews.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <ClipboardList className="h-12 w-12 text-muted-foreground/40 mb-3" />
              <p className="font-medium">No access reviews found</p>
              <p className="text-sm">Access reviews will appear here when created</p>
            </div>
          ) : (
          <>
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow className="border-b bg-muted">
                  <TableHead className="p-3 text-left text-sm font-medium">Review</TableHead>
                  <TableHead className="p-3 text-left text-sm font-medium">Type</TableHead>
                  <TableHead className="p-3 text-left text-sm font-medium">Status</TableHead>
                  <TableHead className="p-3 text-left text-sm font-medium">Period</TableHead>
                  <TableHead className="p-3 text-left text-sm font-medium">Progress</TableHead>
                  <TableHead className="p-3 text-right text-sm font-medium">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {
                  filteredReviews?.map((review) => (
                    <TableRow key={review.id} className="border-b hover:bg-muted">
                      <TableCell className="p-3">
                        <div className="flex items-center gap-3">
                          <div className="h-10 w-10 rounded-lg bg-indigo-100 flex items-center justify-center">
                            <ClipboardCheck className="h-5 w-5 text-indigo-700" />
                          </div>
                          <div>
                            <p className="font-medium">{review.name}</p>
                            <p className="text-sm text-muted-foreground max-w-xs truncate">{review.description || '-'}</p>
                          </div>
                        </div>
                      </TableCell>
                      <TableCell className="p-3">
                        <Badge variant="outline">
                          {typeLabels[review.type] || review.type}
                        </Badge>
                      </TableCell>
                      <TableCell className="p-3">
                        <span className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium ${statusColors[review.status] || 'bg-muted text-foreground'}`}>
                          {statusIcons[review.status]}
                          {review.status.replace('_', ' ')}
                        </span>
                      </TableCell>
                      <TableCell className="p-3">
                        <div className="text-sm">
                          <p>{formatDate(review.start_date)}</p>
                          <p className="text-muted-foreground">to {formatDate(review.end_date)}</p>
                        </div>
                      </TableCell>
                      <TableCell className="p-3">
                        <div className="w-32">
                          <div className="flex items-center justify-between text-sm mb-1">
                            <span>{review.reviewed_items || 0}/{review.total_items || 0}</span>
                            <span className="text-muted-foreground">{getProgress(review)}%</span>
                          </div>
                          <div className="h-2 bg-muted rounded-full overflow-hidden">
                            <div
                              className="h-full bg-indigo-600 rounded-full transition-all"
                              style={{ width: `${getProgress(review)}%` }}
                            />
                          </div>
                        </div>
                      </TableCell>
                      <TableCell className="p-3 text-right">
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="sm" className="h-8 w-8 p-0">
                              <MoreHorizontal className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                              <DropdownMenuItem onClick={() => handleViewReview(review)}>
                                <Eye className="h-4 w-4 mr-2" />
                                View Details
                              </DropdownMenuItem>
                              {review.status === 'pending' && (
                                <>
                                  <DropdownMenuItem onClick={() => handleStartReview(review)}>
                                    <Play className="h-4 w-4 mr-2" />
                                    Start Review
                                  </DropdownMenuItem>
                                  <DropdownMenuItem onClick={() => handleEditReview(review)}>
                                    <Edit className="h-4 w-4 mr-2" />
                                    Edit
                                  </DropdownMenuItem>
                                </>
                              )}
                              {review.status === 'in_progress' && (
                                <DropdownMenuItem onClick={() => handleViewReview(review)}>
                                  <ClipboardCheck className="h-4 w-4 mr-2" />
                                  Continue Review
                                </DropdownMenuItem>
                              )}
                            </DropdownMenuContent>
                          </DropdownMenu>
                      </TableCell>
                    </TableRow>
                  ))}
              </TableBody>
            </Table>
          </div>

          {/* Pagination Controls */}
          {totalCount > PAGE_SIZE && (
            <div className="flex items-center justify-between pt-4 px-1">
              <p className="text-sm text-muted-foreground">
                Showing {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, totalCount)} of {totalCount} reviews
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
                <span className="text-sm text-muted-foreground">
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
          </>
          )}
        </CardContent>
      </Card>

      {/* Create Access Review Modal */}
      <Dialog open={createModal} onOpenChange={setCreateModal}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Create Access Review</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleCreateSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="name">Review Name *</Label>
              <Input
                id="name"
                name="name"
                value={newReview.name}
                onChange={handleNewReviewChange}
                placeholder="Q1 2026 Access Review"
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="description">Description</Label>
              <Textarea
                id="description"
                name="description"
                value={newReview.description}
                onChange={handleNewReviewChange}
                placeholder="Quarterly access review for all users"
                rows={3}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="type">Review Type *</Label>
              <Select value={newReview.type} onValueChange={(val) => setNewReview(prev => ({ ...prev, type: val }))}>
                <SelectTrigger className="w-full">
                  <SelectValue placeholder="Select review type" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="user_access">User Access Review</SelectItem>
                  <SelectItem value="role_assignment">Role Assignment Review</SelectItem>
                  <SelectItem value="application_access">Application Access Review</SelectItem>
                  <SelectItem value="privileged_access">Privileged Access Review</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="start_date">Start Date *</Label>
                <Input
                  id="start_date"
                  name="start_date"
                  type="date"
                  value={newReview.start_date}
                  onChange={handleNewReviewChange}
                  required
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="end_date">End Date *</Label>
                <Input
                  id="end_date"
                  name="end_date"
                  type="date"
                  value={newReview.end_date}
                  onChange={handleNewReviewChange}
                  required
                />
              </div>
            </div>
            <div className="flex justify-end gap-2 pt-4">
              <Button
                type="button"
                variant="outline"
                onClick={() => setCreateModal(false)}
                disabled={createReviewMutation.isPending}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={createReviewMutation.isPending}>
                {createReviewMutation.isPending ? 'Creating...' : 'Create Review'}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Edit Access Review Modal */}
      <Dialog open={editModal} onOpenChange={setEditModal}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Edit Access Review</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleEditSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="edit-name">Review Name *</Label>
              <Input
                id="edit-name"
                name="name"
                value={editReview.name}
                onChange={handleEditReviewChange}
                placeholder="Q1 2026 Access Review"
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="edit-description">Description</Label>
              <Textarea
                id="edit-description"
                name="description"
                value={editReview.description}
                onChange={handleEditReviewChange}
                placeholder="Quarterly access review for all users"
                rows={3}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="edit-type">Review Type *</Label>
              <Select value={editReview.type} onValueChange={(val) => setEditReview(prev => ({ ...prev, type: val }))}>
                <SelectTrigger className="w-full">
                  <SelectValue placeholder="Select review type" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="user_access">User Access Review</SelectItem>
                  <SelectItem value="role_assignment">Role Assignment Review</SelectItem>
                  <SelectItem value="application_access">Application Access Review</SelectItem>
                  <SelectItem value="privileged_access">Privileged Access Review</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="edit-start_date">Start Date *</Label>
                <Input
                  id="edit-start_date"
                  name="start_date"
                  type="date"
                  value={editReview.start_date}
                  onChange={handleEditReviewChange}
                  required
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="edit-end_date">End Date *</Label>
                <Input
                  id="edit-end_date"
                  name="end_date"
                  type="date"
                  value={editReview.end_date}
                  onChange={handleEditReviewChange}
                  required
                />
              </div>
            </div>
            <div className="flex justify-end gap-2 pt-4">
              <Button
                type="button"
                variant="outline"
                onClick={() => setEditModal(false)}
              >
                Cancel
              </Button>
              <Button type="submit">
                Save Changes
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  )
}
