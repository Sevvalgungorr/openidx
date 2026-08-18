import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { AppWindow, ExternalLink, Search } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Input } from '../components/ui/input'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

interface UserApp {
  id: string
  name: string
  description: string
  base_url: string
  protocol: string
  logo_url: string
  sso_enabled: boolean
}

export function AppLauncherPage() {
  const [search, setSearch] = useState('')
  const { toast } = useToast()

  const { data, isLoading } = useQuery({
    queryKey: ['my-applications'],
    queryFn: () => api.get<{ applications: UserApp[] }>('/api/v1/identity/portal/applications'),
  })
  const apps = (data?.applications || []).filter(a =>
    !search || a.name.toLowerCase().includes(search.toLowerCase()) || a.description.toLowerCase().includes(search.toLowerCase())
  )

  const launchApp = (app: UserApp) => {
    // Only open a real absolute http(s) URL. A blank/whitespace/relative
    // base_url previously produced window.open('') → an about:blank tab with an
    // empty address bar (QA 12.2, SecureTask had no launch URL configured).
    const url = app.base_url?.trim()
    if (url && /^https?:\/\//i.test(url)) {
      window.open(url, '_blank', 'noopener,noreferrer')
    } else {
      toast({
        title: 'Cannot launch application',
        description: `${app.name} has no valid launch URL configured. Contact your administrator.`,
        variant: 'destructive',
      })
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">My Applications</h1>
        <p className="text-muted-foreground">Launch your assigned applications with single sign-on</p>
      </div>

      <div className="relative max-w-md">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <Input className="pl-10" placeholder="Search applications..." value={search} onChange={e => setSearch(e.target.value)} />
      </div>

      {isLoading ? (
        <p className="text-center py-12 text-muted-foreground">Loading applications...</p>
      ) : apps.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <AppWindow className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
            <p className="text-lg font-medium">No applications assigned</p>
            <p className="text-muted-foreground">Contact your administrator to get access to applications.</p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {apps.map(app => (
            <Card key={app.id} className="hover:shadow-lg transition-shadow cursor-pointer group" onClick={() => launchApp(app)}>
              <CardHeader className="pb-3">
                <div className="flex items-center gap-3">
                  {app.logo_url ? (
                    <img src={app.logo_url} alt={app.name} className="h-10 w-10 rounded-lg object-cover" />
                  ) : (
                    <div className="h-10 w-10 rounded-lg bg-blue-100 flex items-center justify-center">
                      <AppWindow className="h-6 w-6 text-blue-600" />
                    </div>
                  )}
                  <div className="flex-1 min-w-0">
                    <CardTitle className="text-base truncate">{app.name}</CardTitle>
                    <div className="flex items-center gap-2 mt-1">
                      <Badge variant="outline" className="text-xs">{app.protocol}</Badge>
                      {app.sso_enabled && <Badge variant="secondary" className="text-xs">SSO</Badge>}
                    </div>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground line-clamp-2 mb-3">{app.description || 'No description available'}</p>
                <Button variant="outline" size="sm" className="w-full group-hover:bg-blue-50 group-hover:text-blue-700 group-hover:border-blue-200">
                  <ExternalLink className="mr-2 h-4 w-4" />
                  Launch
                </Button>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  )
}
