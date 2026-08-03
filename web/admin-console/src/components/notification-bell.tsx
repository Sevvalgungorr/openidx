import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Bell, Check } from 'lucide-react'
import { Button } from './ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from './ui/dropdown-menu'
import { api } from '../lib/api'
import { useNavigate } from 'react-router-dom'

interface Notification {
  id: string
  type: string
  title: string
  body: string
  link?: string
  read: boolean
  created_at: string
}

export function NotificationBell() {
  const queryClient = useQueryClient()
  const navigate = useNavigate()

  const { data: countData } = useQuery({
    queryKey: ['notification-count'],
    queryFn: () => api.get<{ unread_count: number }>('/api/v1/identity/notifications/unread-count'),
    refetchInterval: 30000,
  })
  const unreadCount = countData?.unread_count || 0

  const { data: notifData } = useQuery({
    queryKey: ['recent-notifications'],
    queryFn: () => api.get<{ notifications: Notification[] }>('/api/v1/identity/notifications?limit=5&channel=in_app'),
    refetchInterval: 30000,
  })
  const notifications = notifData?.notifications || []

  const markReadMutation = useMutation({
    mutationFn: (ids: string[]) => api.post('/api/v1/identity/notifications/mark-read', { notification_ids: ids }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notification-count'] })
      queryClient.invalidateQueries({ queryKey: ['recent-notifications'] })
    },
  })

  const markAllReadMutation = useMutation({
    mutationFn: () => api.post('/api/v1/identity/notifications/mark-all-read'),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notification-count'] })
      queryClient.invalidateQueries({ queryKey: ['recent-notifications'] })
    },
  })

  const handleClick = (notif: Notification) => {
    if (!notif.read) {
      markReadMutation.mutate([notif.id])
    }
    if (notif.link) {
      navigate(notif.link)
    }
  }

  const timeAgo = (date: string) => {
    const seconds = Math.floor((Date.now() - new Date(date).getTime()) / 1000)
    if (seconds < 60) return 'just now'
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`
    return `${Math.floor(seconds / 86400)}d ago`
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon" className="relative">
          <Bell className="h-5 w-5" />
          {unreadCount > 0 && (
            <span className="absolute -top-1 -right-1 h-5 w-5 rounded-full bg-red-500 text-white text-xs flex items-center justify-center">
              {unreadCount > 9 ? '9+' : unreadCount}
            </span>
          )}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-80">
        <DropdownMenuLabel className="flex items-center justify-between">
          <span>Notifications</span>
          {unreadCount > 0 && (
            <button className="text-xs text-blue-600 hover:underline flex items-center gap-1"
              onClick={(e) => { e.preventDefault(); markAllReadMutation.mutate() }}>
              <Check className="h-3 w-3" />Mark all read
            </button>
          )}
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        {notifications.length === 0 ? (
          <div className="py-6 text-center text-sm text-muted-foreground">No notifications</div>
        ) : (
          notifications.map(n => (
            <DropdownMenuItem key={n.id} className="flex flex-col items-start p-3 cursor-pointer" onClick={() => handleClick(n)}>
              <div className="flex items-center gap-2 w-full">
                {!n.read && <span className="h-2 w-2 rounded-full bg-blue-500 flex-shrink-0" />}
                <span className={`text-sm font-medium flex-1 ${n.read ? 'text-muted-foreground' : ''}`}>{n.title}</span>
                <span className="text-xs text-muted-foreground flex-shrink-0">{timeAgo(n.created_at)}</span>
              </div>
              <p className="text-xs text-muted-foreground mt-1 line-clamp-2">{n.body}</p>
            </DropdownMenuItem>
          ))
        )}
        <DropdownMenuSeparator />
        <DropdownMenuItem className="justify-center text-sm text-blue-600" onClick={() => navigate('/notification-center')}>
          View All Notifications
        </DropdownMenuItem>
        <DropdownMenuItem className="justify-center text-sm text-muted-foreground" onClick={() => navigate('/notification-preferences')}>
          Manage Preferences
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
