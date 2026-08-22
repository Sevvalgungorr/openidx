import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Bell, Check, Trash2, Mail, Shield, Eye, Clock, Settings } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'
import { ConfirmAction } from '../components/confirm-action'
import { useToast } from '../hooks/use-toast'

interface Notification {
  id: string
  type: string
  channel: string
  title: string
  body: string
  link: string
  read: boolean
  metadata: Record<string, unknown>
  created_at: string
}

interface DigestRecord {
  id: string
  digest_type: string
  channel: string
  enabled: boolean
}

interface DigestSettings {
  daily_digest: boolean
  weekly_digest: boolean
}

function digestRecordsToSettings(records: DigestRecord[]): DigestSettings {
  return {
    daily_digest: records.some(r => r.digest_type === 'daily' && r.enabled),
    weekly_digest: records.some(r => r.digest_type === 'weekly' && r.enabled),
  }
}

type FilterTab = 'all' | 'unread' | 'security' | 'access' | 'system'

const FILTER_TABS: { key: FilterTab; label: string }[] = [
  { key: 'all', label: 'All' },
  { key: 'unread', label: 'Unread' },
  { key: 'security', label: 'Security' },
  { key: 'access', label: 'Access' },
  { key: 'system', label: 'System' },
]

function getNotificationIcon(type: string) {
  switch (type) {
    case 'security':
      return Shield
    case 'access':
      return Eye
    case 'system':
    default:
      return Bell
  }
}

function formatRelativeTime(dateStr: string): string {
  const now = new Date()
  const date = new Date(dateStr)
  const diffMs = now.getTime() - date.getTime()
  const diffSeconds = Math.floor(diffMs / 1000)
  const diffMinutes = Math.floor(diffSeconds / 60)
  const diffHours = Math.floor(diffMinutes / 60)
  const diffDays = Math.floor(diffHours / 24)

  if (diffSeconds < 60) return 'just now'
  if (diffMinutes < 60) return `${diffMinutes} minute${diffMinutes !== 1 ? 's' : ''} ago`
  if (diffHours < 24) return `${diffHours} hour${diffHours !== 1 ? 's' : ''} ago`
  if (diffDays < 7) return `${diffDays} day${diffDays !== 1 ? 's' : ''} ago`
  return date.toLocaleDateString()
}

export function NotificationCenterPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [activeFilter, setActiveFilter] = useState<FilterTab>('all')
  const [digestDirty, setDigestDirty] = useState(false)
  const [localDigest, setLocalDigest] = useState<DigestSettings | null>(null)

  // Fetch notifications
  const { data: notificationsData, isLoading: notificationsLoading, isError: notificationsIsError, error: notificationsError } = useQuery({
    queryKey: ['notification-history'],
    queryFn: () => api.get<{ data: Notification[] }>('/api/v1/notifications/history'),
  })
  const notifications = notificationsData?.data || []

  // Fetch digest settings
  const { data: digestData, isLoading: digestLoading, isError: digestIsError, error: digestError } = useQuery({
    queryKey: ['notification-digest'],
    queryFn: () => api.get<{ data: DigestRecord[] }>('/api/v1/notifications/digest'),
  })

  const digestRecords = digestData?.data || []
  const currentDigest = localDigest || digestRecordsToSettings(digestRecords)

  // Mark as read mutation
  const markReadMutation = useMutation({
    mutationFn: (ids: string[]) =>
      api.post('/api/v1/notifications/mark-read', { notification_ids: ids }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notification-history'] })
      toast({ title: 'Notification marked as read' })
    },
    onError: () => toast({ title: 'Failed to mark as read', variant: 'destructive' }),
  })

  // Mark all as read mutation
  const markAllReadMutation = useMutation({
    mutationFn: () => {
      const unreadIds = notifications.filter(n => !n.read).map(n => n.id)
      if (unreadIds.length === 0) {
        return Promise.resolve(null)
      }
      return api.post('/api/v1/notifications/mark-read', { notification_ids: unreadIds })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notification-history'] })
      toast({ title: 'All notifications marked as read' })
    },
    onError: () => toast({ title: 'Failed to mark all as read', variant: 'destructive' }),
  })

  // Delete mutation
  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/notifications/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notification-history'] })
      toast({ title: 'Notification deleted' })
    },
    onError: () => toast({ title: 'Failed to delete notification', variant: 'destructive' }),
  })

  // Save digest settings mutation - sends separate requests for daily and weekly
  const saveDigestMutation = useMutation({
    mutationFn: async (settings: DigestSettings) => {
      await api.put('/api/v1/notifications/digest', {
        digest_type: 'daily',
        channel: 'email',
        enabled: settings.daily_digest,
      })
      await api.put('/api/v1/notifications/digest', {
        digest_type: 'weekly',
        channel: 'email',
        enabled: settings.weekly_digest,
      })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notification-digest'] })
      toast({ title: 'Digest settings saved' })
      setDigestDirty(false)
      setLocalDigest(null)
    },
    onError: () => toast({ title: 'Failed to save digest settings', variant: 'destructive' }),
  })

  // Filter notifications based on active tab
  const filteredNotifications = notifications.filter(n => {
    switch (activeFilter) {
      case 'unread':
        return !n.read
      case 'security':
        return n.type === 'security'
      case 'access':
        return n.type === 'access'
      case 'system':
        return n.type === 'system'
      case 'all':
      default:
        return true
    }
  })

  const unreadCount = notifications.filter(n => !n.read).length

  const handleDigestToggle = (field: 'daily_digest' | 'weekly_digest') => {
    const updated = { ...currentDigest, [field]: !currentDigest[field] }
    setLocalDigest(updated)
    setDigestDirty(true)
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Notification Center</h1>
          <p className="text-muted-foreground">View and manage your notifications</p>
        </div>
        {unreadCount > 0 && (
          <Button
            variant="outline"
            onClick={() => markAllReadMutation.mutate()}
            disabled={markAllReadMutation.isPending}
          >
            <Check className="mr-2 h-4 w-4" />
            {markAllReadMutation.isPending ? 'Marking...' : `Mark All Read (${unreadCount})`}
          </Button>
        )}
      </div>

      {/* Filter Tabs */}
      <div className="flex gap-2 border-b pb-2">
        {FILTER_TABS.map(tab => (
          <button
            key={tab.key}
            onClick={() => setActiveFilter(tab.key)}
            className={`px-4 py-2 text-sm font-medium rounded-t-md transition-colors ${
              activeFilter === tab.key
                ? 'bg-primary text-primary-foreground'
                : 'text-muted-foreground hover:text-foreground hover:bg-muted'
            }`}
          >
            {tab.label}
            {tab.key === 'unread' && unreadCount > 0 && (
              <Badge className="ml-2 bg-blue-100 text-blue-800 text-xs">{unreadCount}</Badge>
            )}
          </button>
        ))}
      </div>

      {/* Notifications List */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">
            {activeFilter === 'all' ? 'All Notifications' : `${activeFilter.charAt(0).toUpperCase() + activeFilter.slice(1)} Notifications`}
          </CardTitle>
        </CardHeader>
        <CardContent>
          {notificationsLoading ? (
            <div className="flex flex-col items-center justify-center py-12">
              <LoadingSpinner size="lg" />
              <p className="mt-4 text-sm text-muted-foreground">Loading notifications...</p>
            </div>
          ) : notificationsIsError ? (
            <QueryError error={notificationsError} resource="notifications" />
          ) : filteredNotifications.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <Bell className="h-12 w-12 text-muted-foreground/40 mb-3" />
              <p className="font-medium">No notifications</p>
              <p className="text-sm">
                {activeFilter === 'unread'
                  ? 'You have read all your notifications'
                  : 'Notifications will appear here when events occur'}
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {filteredNotifications.map(notification => {
                const Icon = getNotificationIcon(notification.type)
                return (
                  <div
                    key={notification.id}
                    className={`flex items-start gap-4 p-4 rounded-lg border transition-colors ${
                      notification.read ? 'bg-background' : 'bg-blue-50/50 border-blue-200'
                    }`}
                  >
                    {/* Unread indicator */}
                    <div className="flex-shrink-0 mt-1">
                      {!notification.read && (
                        <div className="h-2.5 w-2.5 rounded-full bg-primary" />
                      )}
                      {notification.read && <div className="h-2.5 w-2.5" />}
                    </div>

                    {/* Icon */}
                    <div className="flex-shrink-0 mt-0.5">
                      <Icon className="h-5 w-5 text-muted-foreground" />
                    </div>

                    {/* Content */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-start justify-between gap-2">
                        <div>
                          <p className="font-semibold text-sm">{notification.title}</p>
                          <p className="text-sm text-muted-foreground mt-1">{notification.body}</p>
                        </div>
                        <div className="flex items-center gap-2 flex-shrink-0">
                          <Badge variant="outline" className="text-xs">
                            {notification.type}
                          </Badge>
                          {notification.channel && (
                            <Badge variant="outline" className="text-xs">
                              {notification.channel === 'email' ? (
                                <Mail className="h-3 w-3 mr-1" />
                              ) : (
                                <Bell className="h-3 w-3 mr-1" />
                              )}
                              {notification.channel}
                            </Badge>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center gap-2 mt-2">
                        <Clock className="h-3.5 w-3.5 text-muted-foreground" />
                        <span className="text-xs text-muted-foreground">
                          {formatRelativeTime(notification.created_at)}
                        </span>
                      </div>
                    </div>

                    {/* Actions */}
                    <div className="flex items-center gap-1 flex-shrink-0">
                      {!notification.read && (
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-8 w-8 p-0"
                          title="Mark as read"
                          onClick={() => markReadMutation.mutate([notification.id])}
                          disabled={markReadMutation.isPending}
                        >
                          <Check className="h-4 w-4 text-green-600" />
                        </Button>
                      )}
                      <ConfirmAction
                        title="Delete this notification?"
                        description="This permanently removes the notification. This cannot be undone."
                        destructive
                        confirmLabel="Delete"
                        onConfirm={() => deleteMutation.mutateAsync(notification.id)}
                      >
                        {(open) => (
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-8 w-8 p-0"
                            title="Delete"
                            onClick={open}
                            disabled={deleteMutation.isPending}
                          >
                            <Trash2 className="h-4 w-4 text-red-500" />
                          </Button>
                        )}
                      </ConfirmAction>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Digest Settings */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Settings className="h-5 w-5 text-muted-foreground" />
              <CardTitle className="text-lg">Digest Settings</CardTitle>
            </div>
            <Button
              size="sm"
              onClick={() => saveDigestMutation.mutate(currentDigest)}
              disabled={!digestDirty || saveDigestMutation.isPending}
            >
              {saveDigestMutation.isPending ? 'Saving...' : 'Save Settings'}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {digestLoading ? (
            <div className="flex items-center justify-center py-8">
              <LoadingSpinner size="sm" />
              <p className="ml-2 text-sm text-muted-foreground">Loading digest settings...</p>
            </div>
          ) : digestIsError ? (
            <QueryError error={digestError} resource="digest settings" />
          ) : (
            <div className="space-y-4">
              <p className="text-sm text-muted-foreground">
                Configure email digests to receive a summary of your notifications.
              </p>
              <div className="space-y-3">
                {/* Daily Digest Toggle */}
                <div className="flex items-center justify-between p-4 rounded-lg border">
                  <div>
                    <p className="font-medium text-sm">Daily Digest</p>
                    <p className="text-xs text-muted-foreground">
                      Receive a daily summary of all notifications every morning
                    </p>
                  </div>
                  <button
                    onClick={() => handleDigestToggle('daily_digest')}
                    className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                      currentDigest.daily_digest ? 'bg-primary' : 'bg-muted'
                    }`}
                  >
                    <span
                      className={`inline-block h-4 w-4 transform rounded-full bg-background transition-transform ${
                        currentDigest.daily_digest ? 'translate-x-6' : 'translate-x-1'
                      }`}
                    />
                  </button>
                </div>

                {/* Weekly Digest Toggle */}
                <div className="flex items-center justify-between p-4 rounded-lg border">
                  <div>
                    <p className="font-medium text-sm">Weekly Digest</p>
                    <p className="text-xs text-muted-foreground">
                      Receive a weekly summary every Monday with highlights from the past week
                    </p>
                  </div>
                  <button
                    onClick={() => handleDigestToggle('weekly_digest')}
                    className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                      currentDigest.weekly_digest ? 'bg-primary' : 'bg-muted'
                    }`}
                  >
                    <span
                      className={`inline-block h-4 w-4 transform rounded-full bg-background transition-transform ${
                        currentDigest.weekly_digest ? 'translate-x-6' : 'translate-x-1'
                      }`}
                    />
                  </button>
                </div>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
