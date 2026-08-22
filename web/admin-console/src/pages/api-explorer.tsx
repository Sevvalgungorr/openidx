import { useState, useMemo } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import {
  Search,
  Send,
  ChevronRight,
  ChevronDown,
  Copy,
  Loader2,
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Textarea } from '../components/ui/textarea'
import { Badge } from '../components/ui/badge'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '../components/ui/card'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '../components/ui/tabs'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface ApiEndpoint {
  id: string
  service: string
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'
  path: string
  description: string
  scopes: string[]
  path_params: ParamDef[]
  query_params: ParamDef[]
  has_body: boolean
  body_example?: string
}

interface ParamDef {
  name: string
  type: string
  required: boolean
  description: string
}

interface CodeSamples {
  curl: string
  javascript: string
  go: string
  python: string
}

interface ApiResponse {
  status: number
  headers: Record<string, string>
  body: string
  duration_ms: number
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SERVICE_GROUPS = [
  { id: 'identity', label: 'Identity' },
  { id: 'oauth', label: 'OAuth' },
  { id: 'governance', label: 'Governance' },
  { id: 'audit', label: 'Audit' },
  { id: 'admin', label: 'Admin' },
  { id: 'provisioning', label: 'Provisioning' },
] as const

const METHOD_COLORS: Record<string, string> = {
  GET: 'bg-green-100 text-green-800 border-green-200',
  POST: 'bg-blue-100 text-blue-800 border-blue-200',
  PUT: 'bg-orange-100 text-orange-800 border-orange-200',
  PATCH: 'bg-yellow-100 text-yellow-800 border-yellow-200',
  DELETE: 'bg-red-100 text-red-800 border-red-200',
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function ApiExplorerPage() {
  const { toast } = useToast()

  // State
  const [searchTerm, setSearchTerm] = useState('')
  const [selectedEndpoint, setSelectedEndpoint] = useState<ApiEndpoint | null>(null)
  const [expandedServices, setExpandedServices] = useState<Set<string>>(
    new Set(SERVICE_GROUPS.map((s) => s.id))
  )
  const [pathParamValues, setPathParamValues] = useState<Record<string, string>>({})
  const [queryParamValues, setQueryParamValues] = useState<Record<string, string>>({})
  const [bodyText, setBodyText] = useState('')
  const [apiResponse, setApiResponse] = useState<ApiResponse | null>(null)

  // Queries
  const { data: endpoints = [], isLoading, isError, error } = useQuery({
    queryKey: ['api-endpoints'],
    // The backend returns { endpoints: { <service>: ApiEndpoint[] } }. Flatten to
    // the array the UI groups/filters over (the raw object is not iterable and
    // crashed the grouping useMemo with "K is not iterable").
    queryFn: async () => {
      const res = await api.get<{ endpoints: Record<string, ApiEndpoint[]> }>(
        '/api/v1/developer/api-catalog'
      )
      return Object.values(res.endpoints ?? {}).flat()
    },
  })

  const { data: codeSamples } = useQuery({
    queryKey: ['code-samples', selectedEndpoint?.path, selectedEndpoint?.method],
    queryFn: () =>
      api.get<CodeSamples>(
        `/api/v1/developer/code-samples?endpoint=${encodeURIComponent(selectedEndpoint!.path)}&method=${selectedEndpoint!.method}`
      ),
    enabled: !!selectedEndpoint,
  })

  const sendRequestMutation = useMutation({
    mutationFn: async () => {
      // Build the actual URL with path params substituted
      let url = selectedEndpoint!.path
      for (const [key, value] of Object.entries(pathParamValues)) {
        url = url.replace(`:${key}`, encodeURIComponent(value))
        url = url.replace(`{${key}}`, encodeURIComponent(value))
      }

      // Append query params
      const queryParts = Object.entries(queryParamValues)
        .filter(([, v]) => v.trim() !== '')
        .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
      if (queryParts.length > 0) {
        url += '?' + queryParts.join('&')
      }

      const method = selectedEndpoint!.method.toLowerCase() as 'get' | 'post' | 'put' | 'patch' | 'delete'
      const start = performance.now()
      let body: unknown = undefined
      if (selectedEndpoint!.has_body && bodyText.trim()) {
        try {
          body = JSON.parse(bodyText)
        } catch {
          throw new Error('Invalid JSON body')
        }
      }

      const response = await api.getWithHeaders<unknown>(url, {
        method: method.toUpperCase(),
        data: body,
      }).catch(async (err) => {
        // Axios error — extract response if available
        if (err.response) {
          return {
            data: err.response.data,
            headers: Object.fromEntries(
              Object.entries(err.response.headers || {}).filter(
                ([, v]) => typeof v === 'string'
              )
            ) as Record<string, string>,
            status: err.response.status as number,
          }
        }
        throw err
      })

      const duration = Math.round(performance.now() - start)
      return {
        status: (response as { status?: number }).status || 200,
        headers: (response as { headers: Record<string, string> }).headers || {},
        body: JSON.stringify((response as { data: unknown }).data, null, 2),
        duration_ms: duration,
      } as ApiResponse
    },
    onSuccess: (data) => {
      setApiResponse(data)
    },
    onError: (error: Error) => {
      toast({
        title: 'Request Failed',
        description: error.message,
        variant: 'destructive',
      })
    },
  })

  // Filter endpoints by search
  const filteredEndpoints = useMemo(() => {
    if (!searchTerm.trim()) return endpoints
    const term = searchTerm.toLowerCase()
    return endpoints.filter(
      (ep) =>
        ep.path.toLowerCase().includes(term) ||
        ep.description.toLowerCase().includes(term) ||
        ep.method.toLowerCase().includes(term)
    )
  }, [endpoints, searchTerm])

  // Group by service
  const groupedEndpoints = useMemo(() => {
    const groups: Record<string, ApiEndpoint[]> = {}
    for (const ep of filteredEndpoints) {
      if (!groups[ep.service]) groups[ep.service] = []
      groups[ep.service].push(ep)
    }
    return groups
  }, [filteredEndpoints])

  const toggleService = (serviceId: string) => {
    setExpandedServices((prev) => {
      const next = new Set(prev)
      if (next.has(serviceId)) {
        next.delete(serviceId)
      } else {
        next.add(serviceId)
      }
      return next
    })
  }

  const selectEndpoint = (ep: ApiEndpoint) => {
    setSelectedEndpoint(ep)
    setPathParamValues({})
    setQueryParamValues({})
    setBodyText(ep.body_example || '')
    setApiResponse(null)
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
    toast({ title: 'Copied', description: 'Copied to clipboard.' })
  }

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

  if (isLoading) {
    return (
      <div className="space-y-6">
        <h1 className="text-3xl font-bold tracking-tight">API Explorer</h1>
        <p className="text-center py-8">Loading API endpoints...</p>
      </div>
    )
  }

  if (isError) {
    return (
      <div className="space-y-6">
        <h1 className="text-3xl font-bold tracking-tight">API Explorer</h1>
        <QueryError error={error} resource="API endpoints" />
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">API Explorer</h1>
          <p className="text-muted-foreground">
            Browse, test, and generate code for OpenIDX API endpoints
          </p>
        </div>
      </div>

      <div className="flex gap-4" style={{ minHeight: 'calc(100vh - 220px)' }}>
        {/* Left sidebar - endpoint tree */}
        <div className="w-80 flex-shrink-0 space-y-2">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search endpoints..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-9"
            />
          </div>

          <div className="border rounded-lg overflow-y-auto max-h-[calc(100vh-300px)]">
            {SERVICE_GROUPS.map((group) => {
              const serviceEndpoints = groupedEndpoints[group.id] || []
              if (searchTerm && serviceEndpoints.length === 0) return null
              const isExpanded = expandedServices.has(group.id)

              return (
                <div key={group.id}>
                  <button
                    onClick={() => toggleService(group.id)}
                    className="w-full flex items-center gap-2 px-3 py-2 text-sm font-semibold hover:bg-muted/50 border-b"
                  >
                    {isExpanded ? (
                      <ChevronDown className="h-4 w-4" />
                    ) : (
                      <ChevronRight className="h-4 w-4" />
                    )}
                    {group.label}
                    <span className="ml-auto text-xs text-muted-foreground">
                      {serviceEndpoints.length}
                    </span>
                  </button>
                  {isExpanded &&
                    serviceEndpoints.map((ep) => (
                      <button
                        key={ep.id}
                        onClick={() => selectEndpoint(ep)}
                        className={`w-full flex items-center gap-2 px-4 py-1.5 text-xs hover:bg-muted/50 border-b ${
                          selectedEndpoint?.id === ep.id ? 'bg-muted' : ''
                        }`}
                      >
                        <span
                          className={`inline-block w-14 text-center text-[10px] font-bold rounded px-1 py-0.5 border ${
                            METHOD_COLORS[ep.method] || ''
                          }`}
                        >
                          {ep.method}
                        </span>
                        <span className="truncate font-mono">{ep.path}</span>
                      </button>
                    ))}
                </div>
              )
            })}
          </div>
        </div>

        {/* Right panel - endpoint detail */}
        <div className="flex-1 min-w-0">
          {!selectedEndpoint ? (
            <Card>
              <CardContent className="py-16 text-center text-muted-foreground">
                Select an endpoint from the sidebar to explore it.
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-4">
              {/* Header */}
              <Card>
                <CardHeader>
                  <div className="flex items-center gap-3">
                    <span
                      className={`text-sm font-bold rounded px-2 py-1 border ${
                        METHOD_COLORS[selectedEndpoint.method] || ''
                      }`}
                    >
                      {selectedEndpoint.method}
                    </span>
                    <code className="text-lg font-mono">{selectedEndpoint.path}</code>
                  </div>
                  <CardDescription>{selectedEndpoint.description}</CardDescription>
                  {selectedEndpoint.scopes.length > 0 && (
                    <div className="flex items-center gap-2 mt-2">
                      <span className="text-xs text-muted-foreground">Scopes:</span>
                      {selectedEndpoint.scopes.map((scope) => (
                        <Badge key={scope} variant="secondary" className="text-xs">
                          {scope}
                        </Badge>
                      ))}
                    </div>
                  )}
                </CardHeader>
              </Card>

              {/* Try It section */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Try It</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  {/* Path parameters */}
                  {selectedEndpoint.path_params.length > 0 && (
                    <div className="space-y-2">
                      <label className="text-sm font-medium">Path Parameters</label>
                      <div className="grid gap-2 md:grid-cols-2">
                        {selectedEndpoint.path_params.map((param) => (
                          <div key={param.name} className="space-y-1">
                            <label className="text-xs text-muted-foreground">
                              {param.name}
                              {param.required && (
                                <span className="text-red-500 ml-1">*</span>
                              )}
                            </label>
                            <Input
                              placeholder={param.description || param.name}
                              value={pathParamValues[param.name] || ''}
                              onChange={(e) =>
                                setPathParamValues((prev) => ({
                                  ...prev,
                                  [param.name]: e.target.value,
                                }))
                              }
                            />
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Query parameters */}
                  {selectedEndpoint.query_params.length > 0 && (
                    <div className="space-y-2">
                      <label className="text-sm font-medium">Query Parameters</label>
                      <div className="grid gap-2 md:grid-cols-2">
                        {selectedEndpoint.query_params.map((param) => (
                          <div key={param.name} className="space-y-1">
                            <label className="text-xs text-muted-foreground">
                              {param.name}
                              {param.required && (
                                <span className="text-red-500 ml-1">*</span>
                              )}
                              <span className="ml-1 text-[10px]">({param.type})</span>
                            </label>
                            <Input
                              placeholder={param.description || param.name}
                              value={queryParamValues[param.name] || ''}
                              onChange={(e) =>
                                setQueryParamValues((prev) => ({
                                  ...prev,
                                  [param.name]: e.target.value,
                                }))
                              }
                            />
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Request body */}
                  {selectedEndpoint.has_body && (
                    <div className="space-y-2">
                      <label className="text-sm font-medium">Request Body (JSON)</label>
                      <Textarea
                        className="font-mono text-xs min-h-[120px]"
                        placeholder='{ "key": "value" }'
                        value={bodyText}
                        onChange={(e) => setBodyText(e.target.value)}
                      />
                    </div>
                  )}

                  <Button
                    onClick={() => sendRequestMutation.mutate()}
                    disabled={sendRequestMutation.isPending}
                  >
                    {sendRequestMutation.isPending ? (
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    ) : (
                      <Send className="mr-2 h-4 w-4" />
                    )}
                    {sendRequestMutation.isPending ? 'Sending...' : 'Send Request'}
                  </Button>
                </CardContent>
              </Card>

              {/* Response */}
              {apiResponse && (
                <Card>
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <CardTitle className="text-base">Response</CardTitle>
                      <div className="flex items-center gap-3 text-sm">
                        <Badge
                          variant={apiResponse.status < 400 ? 'default' : 'destructive'}
                        >
                          {apiResponse.status}
                        </Badge>
                        <span className="text-muted-foreground">
                          {apiResponse.duration_ms}ms
                        </span>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => copyToClipboard(apiResponse.body)}
                        >
                          <Copy className="h-3 w-3 mr-1" />
                          Copy
                        </Button>
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <details className="mb-3">
                      <summary className="text-xs text-muted-foreground cursor-pointer">
                        Response Headers
                      </summary>
                      <pre className="mt-1 text-xs bg-muted rounded p-2 overflow-x-auto">
                        {Object.entries(apiResponse.headers)
                          .map(([k, v]) => `${k}: ${v}`)
                          .join('\n') || '(none)'}
                      </pre>
                    </details>
                    <pre className="text-xs bg-muted rounded p-3 overflow-x-auto max-h-96">
                      {apiResponse.body}
                    </pre>
                  </CardContent>
                </Card>
              )}

              {/* Code samples */}
              {codeSamples && (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">Code Samples</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <Tabs defaultValue="curl">
                      <TabsList>
                        <TabsTrigger value="curl">cURL</TabsTrigger>
                        <TabsTrigger value="javascript">JavaScript</TabsTrigger>
                        <TabsTrigger value="go">Go</TabsTrigger>
                        <TabsTrigger value="python">Python</TabsTrigger>
                      </TabsList>
                      {(
                        ['curl', 'javascript', 'go', 'python'] as const
                      ).map((lang) => (
                        <TabsContent key={lang} value={lang}>
                          <div className="relative">
                            <Button
                              variant="ghost"
                              size="sm"
                              className="absolute right-2 top-2"
                              onClick={() =>
                                copyToClipboard(codeSamples[lang])
                              }
                            >
                              <Copy className="h-3 w-3" />
                            </Button>
                            <pre className="text-xs bg-muted rounded p-3 overflow-x-auto">
                              {codeSamples[lang]}
                            </pre>
                          </div>
                        </TabsContent>
                      ))}
                    </Tabs>
                  </CardContent>
                </Card>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
