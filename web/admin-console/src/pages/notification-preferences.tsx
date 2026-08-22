import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Bell, Mail } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../components/ui/table'
import { Button } from '../components/ui/button'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'
import { useState, useEffect } from 'react'

interface NotificationPreference {
  channel: string
  event_type: string
  enabled: boolean
}

const EVENT_TYPES = [
  { key: 'access_request', label: 'Access Requests', description: 'When your access requests are approved or denied' },
  { key: 'security_alert', label: 'Security Alerts', description: 'Suspicious login attempts or security events' },
  { key: 'session_revoked', label: 'Session Revoked', description: 'When an admin revokes your session' },
  { key: 'review_assigned', label: 'Review Assigned', description: 'When you are assigned an access review' },
  { key: 'group_request', label: 'Group Requests', description: 'Updates on your group join requests' },
  { key: 'password_expiry', label: 'Password Expiry', description: 'Reminders before your password expires' },
  { key: 'mfa_change', label: 'MFA Changes', description: 'Changes to your multi-factor authentication' },
]

const CHANNELS = [
  { key: 'in_app', label: 'In-App', icon: Bell },
  { key: 'email', label: 'Email', icon: Mail },
]

export function NotificationPreferencesPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [prefs, setPrefs] = useState<Record<string, Record<string, boolean>>>({})
  const [dirty, setDirty] = useState(false)

  const { data, isError, error } = useQuery({
    queryKey: ['notification-preferences'],
    queryFn: () => api.get<{ preferences: NotificationPreference[] }>('/api/v1/identity/notifications/preferences'),
  })

  useEffect(() => {
    if (data?.preferences) {
      const map: Record<string, Record<string, boolean>> = {}
      for (const p of data.preferences) {
        if (!map[p.event_type]) map[p.event_type] = {}
        map[p.event_type][p.channel] = p.enabled
      }
      setPrefs(map)
      setDirty(false)
    }
  }, [data])

  const isEnabled = (eventType: string, channel: string) => {
    return prefs[eventType]?.[channel] ?? true // default enabled
  }

  const toggle = (eventType: string, channel: string) => {
    setPrefs(prev => ({
      ...prev,
      [eventType]: {
        ...prev[eventType],
        [channel]: !isEnabled(eventType, channel),
      }
    }))
    setDirty(true)
  }

  const saveMutation = useMutation({
    mutationFn: (preferences: NotificationPreference[]) =>
      api.put('/api/v1/identity/notifications/preferences', { preferences }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notification-preferences'] })
      toast({ title: 'Preferences saved' })
      setDirty(false)
    },
    onError: () => toast({ title: 'Failed to save preferences', variant: 'destructive' }),
  })

  const handleSave = () => {
    const preferences: NotificationPreference[] = []
    for (const et of EVENT_TYPES) {
      for (const ch of CHANNELS) {
        preferences.push({
          channel: ch.key,
          event_type: et.key,
          enabled: isEnabled(et.key, ch.key),
        })
      }
    }
    saveMutation.mutate(preferences)
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Notification Preferences</h1>
          <p className="text-muted-foreground">Choose how you want to be notified</p>
        </div>
        <Button onClick={handleSave} disabled={!dirty || saveMutation.isPending}>
          Save Preferences
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Notification Channels</CardTitle>
        </CardHeader>
        <CardContent>
          {isError ? (
            <QueryError error={error} resource="notification preferences" />
          ) : (
          <Table>
              <TableHeader>
                <TableRow className="border-b">
                  <TableHead className="text-left py-3 pr-4 font-medium text-sm">Event Type</TableHead>
                  {CHANNELS.map(ch => (
                    <TableHead key={ch.key} className="text-center py-3 px-4 font-medium text-sm">
                      <div className="flex items-center justify-center gap-1">
                        <ch.icon className="h-4 w-4" />
                        {ch.label}
                      </div>
                    </TableHead>
                  ))}
                </TableRow>
              </TableHeader>
              <TableBody>
                {EVENT_TYPES.map(et => (
                  <TableRow key={et.key} className="border-b last:border-0">
                    <TableCell className="py-4 pr-4">
                      <p className="font-medium text-sm">{et.label}</p>
                      <p className="text-xs text-muted-foreground">{et.description}</p>
                    </TableCell>
                    {CHANNELS.map(ch => (
                      <TableCell key={ch.key} className="text-center py-4 px-4">
                        <button
                          onClick={() => toggle(et.key, ch.key)}
                          className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                            isEnabled(et.key, ch.key) ? 'bg-primary' : 'bg-muted'
                          }`}
                        >
                          <span className={`inline-block h-4 w-4 transform rounded-full bg-background transition-transform ${
                            isEnabled(et.key, ch.key) ? 'translate-x-6' : 'translate-x-1'
                          }`} />
                        </button>
                      </TableCell>
                    ))}
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
