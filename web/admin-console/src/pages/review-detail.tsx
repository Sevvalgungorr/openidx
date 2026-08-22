import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  ArrowLeft,
  CheckCircle,
  XCircle,
  Clock,
  User,
  Flag,
  Play,
  CheckCheck,
  MessageSquare,
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '../components/ui/dialog'
import { Textarea } from '../components/ui/textarea'
import { Label } from '../components/ui/label'
import { api } from '../lib/api'
import { QueryError } from '../components/query-error'
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

interface ReviewItem {
  id: string
  review_id: string
  user_id: string
  resource_type: string
  resource_id: string
  resource_name: string
  decision: string
  decided_by: string
  decided_at: string | null
  comments: string
}

const decisionIcons: Record<string, React.ReactNode> = {
  pending: <Clock className="h-4 w-4 text-yellow-600" />,
  approved: <CheckCircle className="h-4 w-4 text-green-600" />,
  revoked: <XCircle className="h-4 w-4 text-red-600" />,
  flagged: <Flag className="h-4 w-4 text-orange-600" />,
}

const decisionColors: Record<string, string> = {
  pending: 'bg-yellow-100 text-yellow-800',
  approved: 'bg-green-100 text-green-800',
  revoked: 'bg-red-100 text-red-800',
  flagged: 'bg-orange-100 text-orange-800',
}

const statusColors: Record<string, string> = {
  pending: 'bg-yellow-100 text-yellow-800',
  in_progress: 'bg-blue-100 text-blue-800',
  completed: 'bg-green-100 text-green-800',
  expired: 'bg-red-100 text-red-800',
  canceled: 'bg-gray-100 text-gray-800',
}

export function ReviewDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [selectedItems, setSelectedItems] = useState<string[]>([])
  const [decisionModal, setDecisionModal] = useState(false)
  const [batchDecision, setBatchDecision] = useState<'approved' | 'revoked' | 'flagged'>('approved')
  const [comments, setComments] = useState('')
  const [filter, setFilter] = useState<string>('')

  const { data: review, isLoading: reviewLoading, isError: reviewError, error: reviewErrorObj } = useQuery({
    queryKey: ['review', id],
    queryFn: () => api.get<AccessReview>(`/api/v1/governance/reviews/${id}`),
  })

  const { data: items, isLoading: itemsLoading } = useQuery({
    queryKey: ['review-items', id, filter],
    queryFn: () => api.get<ReviewItem[]>(`/api/v1/governance/reviews/${id}/items${filter ? `?decision=${filter}` : ''}`),
    enabled: !!id,
  })

  const startReviewMutation = useMutation({
    mutationFn: () => api.patch(`/api/v1/governance/reviews/${id}/status`, { status: 'in_progress' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['review', id] })
      queryClient.invalidateQueries({ queryKey: ['review-items', id] })
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

  const completeReviewMutation = useMutation({
    mutationFn: () => api.patch(`/api/v1/governance/reviews/${id}/status`, { status: 'completed' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['review', id] })
      toast({
        title: 'Review Completed',
        description: 'Access review has been completed.',
        variant: 'success',
      })
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: `Failed to complete review: ${error.message}`,
        variant: 'destructive',
      })
    },
  })

  const singleDecisionMutation = useMutation({
    mutationFn: ({ itemId, decision, comments }: { itemId: string; decision: string; comments: string }) =>
      api.post(`/api/v1/governance/reviews/${id}/items/${itemId}/decision`, { decision, comments }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['review-items', id] })
      queryClient.invalidateQueries({ queryKey: ['review', id] })
      toast({
        title: 'Decision Recorded',
        description: 'Your decision has been recorded.',
        variant: 'success',
      })
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: `Failed to record decision: ${error.message}`,
        variant: 'destructive',
      })
    },
  })

  const batchDecisionMutation = useMutation({
    mutationFn: ({ itemIds, decision, comments }: { itemIds: string[]; decision: string; comments: string }) =>
      api.post(`/api/v1/governance/reviews/${id}/items/batch-decision`, {
        item_ids: itemIds,
        decision,
        comments,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['review-items', id] })
      queryClient.invalidateQueries({ queryKey: ['review', id] })
      setSelectedItems([])
      setDecisionModal(false)
      setComments('')
      toast({
        title: 'Decisions Recorded',
        description: `Successfully recorded decisions for ${selectedItems.length} items.`,
        variant: 'success',
      })
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: `Failed to record decisions: ${error.message}`,
        variant: 'destructive',
      })
    },
  })

  const handleSelectAll = () => {
    if (selectedItems.length === pendingItems.length) {
      setSelectedItems([])
    } else {
      setSelectedItems(pendingItems.map(item => item.id))
    }
  }

  const handleSelectItem = (itemId: string) => {
    setSelectedItems(prev =>
      prev.includes(itemId)
        ? prev.filter(id => id !== itemId)
        : [...prev, itemId]
    )
  }

  const handleQuickDecision = (itemId: string, decision: string) => {
    singleDecisionMutation.mutate({ itemId, decision, comments: '' })
  }

  const handleBatchDecision = () => {
    batchDecisionMutation.mutate({
      itemIds: selectedItems,
      decision: batchDecision,
      comments,
    })
  }

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    })
  }

  const pendingItems = items?.filter(item => item.decision === 'pending') || []
  const reviewedCount = items?.filter(item => item.decision !== 'pending').length || 0
  const totalItems = items?.length || 0
  const progress = totalItems > 0 ? Math.round((reviewedCount / totalItems) * 100) : 0

  if (reviewLoading) {
    return <div className="p-8 text-center">Loading...</div>
  }

  if (reviewError) {
    return <QueryError error={reviewErrorObj} resource="this access review" />
  }

  if (!review) {
    return <div className="p-8 text-center">Review not found</div>
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <Button variant="ghost" size="icon" onClick={() => navigate('/access-reviews')}>
          <ArrowLeft className="h-5 w-5" />
        </Button>
        <div className="flex-1">
          <h1 className="text-3xl font-bold tracking-tight">{review.name}</h1>
          <p className="text-muted-foreground">{review.description || 'No description'}</p>
        </div>
        <div className="flex items-center gap-2">
          {review.status === 'pending' && (
            <Button onClick={() => startReviewMutation.mutate()} disabled={startReviewMutation.isPending}>
              <Play className="mr-2 h-4 w-4" />
              {startReviewMutation.isPending ? 'Starting...' : 'Start Review'}
            </Button>
          )}
          {review.status === 'in_progress' && pendingItems.length === 0 && totalItems > 0 && (
            <Button onClick={() => completeReviewMutation.mutate()} disabled={completeReviewMutation.isPending}>
              <CheckCheck className="mr-2 h-4 w-4" />
              {completeReviewMutation.isPending ? 'Completing...' : 'Complete Review'}
            </Button>
          )}
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-500">Status</p>
                <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium mt-1 ${statusColors[review.status]}`}>
                  {review.status.replace('_', ' ')}
                </span>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div>
              <p className="text-sm text-gray-500">Review Period</p>
              <p className="font-medium mt-1">{formatDate(review.start_date)}</p>
              <p className="text-sm text-gray-500">to {formatDate(review.end_date)}</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div>
              <p className="text-sm text-gray-500">Progress</p>
              <p className="text-2xl font-bold mt-1">{reviewedCount}/{totalItems}</p>
              <div className="h-2 bg-gray-200 rounded-full overflow-hidden mt-2">
                <div
                  className="h-full bg-indigo-600 rounded-full transition-all"
                  style={{ width: `${progress}%` }}
                />
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div>
              <p className="text-sm text-gray-500">Pending Items</p>
              <p className="text-2xl font-bold mt-1 text-yellow-600">{pendingItems.length}</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Batch Action Bar */}
      {selectedItems.length > 0 && (
        <div className="bg-indigo-50 border border-indigo-200 rounded-lg p-4 flex items-center justify-between">
          <p className="text-indigo-700 font-medium">
            {selectedItems.length} item{selectedItems.length > 1 ? 's' : ''} selected
          </p>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                setBatchDecision('approved')
                setDecisionModal(true)
              }}
              className="border-green-300 text-green-700 hover:bg-green-50"
            >
              <CheckCircle className="mr-2 h-4 w-4" />
              Approve Selected
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                setBatchDecision('revoked')
                setDecisionModal(true)
              }}
              className="border-red-300 text-red-700 hover:bg-red-50"
            >
              <XCircle className="mr-2 h-4 w-4" />
              Revoke Selected
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setSelectedItems([])}
            >
              Clear Selection
            </Button>
          </div>
        </div>
      )}

      {/* Items Table */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>Review Items</CardTitle>
            <div className="flex items-center gap-2">
              <select
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                className="border rounded-md px-3 py-2 text-sm"
              >
                <option value="">All Items</option>
                <option value="pending">Pending</option>
                <option value="approved">Approved</option>
                <option value="revoked">Revoked</option>
                <option value="flagged">Flagged</option>
              </select>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {review.status === 'pending' ? (
            <div className="text-center py-12 text-gray-500">
              <Clock className="mx-auto h-12 w-12 text-gray-300 mb-4" />
              <p>Start the review to populate items</p>
              <Button onClick={() => startReviewMutation.mutate()} className="mt-4" disabled={startReviewMutation.isPending}>
                <Play className="mr-2 h-4 w-4" />
                Start Review
              </Button>
            </div>
          ) : itemsLoading ? (
            <div className="text-center py-8">Loading items...</div>
          ) : items?.length === 0 ? (
            <div className="text-center py-8 text-gray-500">No items to review</div>
          ) : (
            <div className="rounded-md border">
              <table className="w-full">
                <thead>
                  <tr className="border-b bg-gray-50">
                    <th className="p-3 text-left w-10">
                      <input
                        type="checkbox"
                        checked={selectedItems.length === pendingItems.length && pendingItems.length > 0}
                        onChange={handleSelectAll}
                        disabled={pendingItems.length === 0}
                        className="h-4 w-4"
                      />
                    </th>
                    <th className="p-3 text-left text-sm font-medium">User</th>
                    <th className="p-3 text-left text-sm font-medium">Resource</th>
                    <th className="p-3 text-left text-sm font-medium">Type</th>
                    <th className="p-3 text-left text-sm font-medium">Decision</th>
                    <th className="p-3 text-right text-sm font-medium">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {items?.map((item) => (
                    <tr key={item.id} className="border-b hover:bg-gray-50">
                      <td className="p-3">
                        <input
                          type="checkbox"
                          checked={selectedItems.includes(item.id)}
                          onChange={() => handleSelectItem(item.id)}
                          disabled={item.decision !== 'pending'}
                          className="h-4 w-4"
                        />
                      </td>
                      <td className="p-3">
                        <div className="flex items-center gap-3">
                          <div className="h-8 w-8 rounded-full bg-gray-100 flex items-center justify-center">
                            <User className="h-4 w-4 text-gray-600" />
                          </div>
                          <span className="text-sm truncate max-w-[150px]" title={item.user_id}>
                            {item.user_id.substring(0, 8)}...
                          </span>
                        </div>
                      </td>
                      <td className="p-3">
                        <p className="font-medium">{item.resource_name || item.resource_id}</p>
                      </td>
                      <td className="p-3">
                        <Badge variant="outline">{item.resource_type}</Badge>
                      </td>
                      <td className="p-3">
                        <span className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium ${decisionColors[item.decision]}`}>
                          {decisionIcons[item.decision]}
                          {item.decision}
                        </span>
                      </td>
                      <td className="p-3 text-right">
                        {item.decision === 'pending' ? (
                          <div className="flex justify-end gap-1">
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => handleQuickDecision(item.id, 'approved')}
                              className="text-green-600 hover:text-green-700 hover:bg-green-50"
                              disabled={singleDecisionMutation.isPending}
                            >
                              <CheckCircle className="h-4 w-4" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => handleQuickDecision(item.id, 'revoked')}
                              className="text-red-600 hover:text-red-700 hover:bg-red-50"
                              disabled={singleDecisionMutation.isPending}
                            >
                              <XCircle className="h-4 w-4" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => handleQuickDecision(item.id, 'flagged')}
                              className="text-orange-600 hover:text-orange-700 hover:bg-orange-50"
                              disabled={singleDecisionMutation.isPending}
                            >
                              <Flag className="h-4 w-4" />
                            </Button>
                          </div>
                        ) : (
                          <span className="text-sm text-gray-500">
                            {item.decided_at ? formatDate(item.decided_at) : '-'}
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Batch Decision Modal */}
      <Dialog open={decisionModal} onOpenChange={setDecisionModal}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>
              {batchDecision === 'approved' ? 'Approve' : batchDecision === 'revoked' ? 'Revoke' : 'Flag'} {selectedItems.length} Items
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="comments">Comments (optional)</Label>
              <div className="flex items-start gap-2">
                <MessageSquare className="h-5 w-5 text-gray-400 mt-2" />
                <Textarea
                  id="comments"
                  value={comments}
                  onChange={(e) => setComments(e.target.value)}
                  placeholder="Add a comment for this batch decision..."
                  rows={3}
                  className="flex-1"
                />
              </div>
            </div>
            <div className="flex justify-end gap-2 pt-4">
              <Button
                variant="outline"
                onClick={() => {
                  setDecisionModal(false)
                  setComments('')
                }}
                disabled={batchDecisionMutation.isPending}
              >
                Cancel
              </Button>
              <Button
                onClick={handleBatchDecision}
                disabled={batchDecisionMutation.isPending}
                className={
                  batchDecision === 'approved'
                    ? 'bg-green-600 hover:bg-green-700'
                    : batchDecision === 'revoked'
                    ? 'bg-red-600 hover:bg-red-700'
                    : 'bg-orange-600 hover:bg-orange-700'
                }
              >
                {batchDecisionMutation.isPending
                  ? 'Processing...'
                  : `${batchDecision === 'approved' ? 'Approve' : batchDecision === 'revoked' ? 'Revoke' : 'Flag'} ${selectedItems.length} Items`}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  )
}
