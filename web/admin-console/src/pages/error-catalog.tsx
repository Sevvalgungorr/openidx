import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Search,
  Copy,
  ChevronDown,
  ChevronRight,
  AlertCircle,
  Filter,
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import {
  Card,
  CardContent,
} from '../components/ui/card'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '../components/ui/table'
import { api } from '../lib/api'
import { QueryError } from '../components/query-error'
import { useToast } from '../hooks/use-toast'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface ErrorEntry {
  code: string
  http_status: number
  category: string
  description: string
  resolution: string
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const CATEGORIES = [
  { value: '', label: 'All Categories' },
  { value: 'auth', label: 'Authentication' },
  { value: 'resource', label: 'Resource' },
  { value: 'validation', label: 'Validation' },
  { value: 'system', label: 'System' },
] as const

const CATEGORY_COLORS: Record<string, string> = {
  auth: 'bg-yellow-100 text-yellow-800 border-yellow-200',
  resource: 'bg-blue-100 text-blue-800 border-blue-200',
  validation: 'bg-orange-100 text-orange-800 border-orange-200',
  system: 'bg-red-100 text-red-800 border-red-200',
}

const HTTP_STATUS_COLORS: Record<string, string> = {
  '4': 'bg-yellow-100 text-yellow-800',
  '5': 'bg-red-100 text-red-800',
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function ErrorCatalogPage() {
  const { toast } = useToast()

  const [searchTerm, setSearchTerm] = useState('')
  const [categoryFilter, setCategoryFilter] = useState('')
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set())

  const { data: errors = [], isLoading, isError, error } = useQuery({
    queryKey: ['error-catalog'],
    // The backend wraps the list as { errors: [...], total }. Unwrap to the
    // array the UI filters over (a bare array would crash with
    // "j.filter is not a function").
    queryFn: async () => {
      const res = await api.get<{ errors: ErrorEntry[]; total: number }>(
        '/api/v1/error-catalog'
      )
      return res.errors ?? []
    },
  })

  // Filter errors
  const filteredErrors = useMemo(() => {
    return errors.filter((err) => {
      const matchesSearch =
        !searchTerm.trim() ||
        err.code.toLowerCase().includes(searchTerm.toLowerCase()) ||
        err.description.toLowerCase().includes(searchTerm.toLowerCase())
      const matchesCategory =
        !categoryFilter || err.category === categoryFilter
      return matchesSearch && matchesCategory
    })
  }, [errors, searchTerm, categoryFilter])

  const toggleRow = (code: string) => {
    setExpandedRows((prev) => {
      const next = new Set(prev)
      if (next.has(code)) {
        next.delete(code)
      } else {
        next.add(code)
      }
      return next
    })
  }

  const copyErrorCode = (code: string) => {
    navigator.clipboard.writeText(code)
    toast({ title: 'Copied', description: `Error code "${code}" copied to clipboard.` })
  }

  const httpStatusColor = (status: number) => {
    const prefix = String(status).charAt(0)
    return HTTP_STATUS_COLORS[prefix] || 'bg-muted text-foreground'
  }

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Error Catalog</h1>
          <p className="text-muted-foreground">
            Reference of all error codes, descriptions, and resolution hints
          </p>
        </div>
      </div>

      {/* Search and filters */}
      <Card>
        <CardContent className="pt-6">
          <div className="flex gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search by error code or description..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-9"
              />
            </div>
            <div className="flex items-center gap-2">
              <Filter className="h-4 w-4 text-muted-foreground" />
              <select
                value={categoryFilter}
                onChange={(e) => setCategoryFilter(e.target.value)}
                className="flex h-10 rounded-md border border-input bg-background px-3 py-2 text-sm"
              >
                {CATEGORIES.map((cat) => (
                  <option key={cat.value} value={cat.value}>
                    {cat.label}
                  </option>
                ))}
              </select>
            </div>
          </div>
          <p className="text-xs text-muted-foreground mt-2">
            {filteredErrors.length} of {errors.length} error codes shown
          </p>
        </CardContent>
      </Card>

      {/* Error table */}
      <Card>
        <CardContent className="p-0">
          {isLoading ? (
            <p className="text-center py-8 text-muted-foreground">Loading error catalog...</p>
          ) : isError ? (
            <QueryError error={error} resource="the error catalog" />
          ) : filteredErrors.length === 0 ? (
            <div className="text-center py-12">
              <AlertCircle className="h-10 w-10 mx-auto text-muted-foreground mb-3" />
              <p className="text-muted-foreground">No error codes match your search.</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-8" />
                  <TableHead>Error Code</TableHead>
                  <TableHead className="w-24">HTTP Status</TableHead>
                  <TableHead className="w-32">Category</TableHead>
                  <TableHead>Description</TableHead>
                  <TableHead className="w-12" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredErrors.map((err) => {
                  const isExpanded = expandedRows.has(err.code)
                  const catColor =
                    CATEGORY_COLORS[err.category] || 'bg-muted text-foreground border-border'

                  return (
                    <>
                      <TableRow
                        key={err.code}
                        className="cursor-pointer"
                        onClick={() => toggleRow(err.code)}
                      >
                        <TableCell className="w-8 pr-0">
                          {isExpanded ? (
                            <ChevronDown className="h-4 w-4 text-muted-foreground" />
                          ) : (
                            <ChevronRight className="h-4 w-4 text-muted-foreground" />
                          )}
                        </TableCell>
                        <TableCell>
                          <code className="text-sm font-mono font-semibold">{err.code}</code>
                        </TableCell>
                        <TableCell>
                          <span
                            className={`inline-block text-xs font-semibold px-2 py-0.5 rounded ${httpStatusColor(
                              err.http_status
                            )}`}
                          >
                            {err.http_status}
                          </span>
                        </TableCell>
                        <TableCell>
                          <span
                            className={`inline-block text-xs font-medium px-2 py-0.5 rounded-full border ${catColor}`}
                          >
                            {err.category}
                          </span>
                        </TableCell>
                        <TableCell className="text-sm">{err.description}</TableCell>
                        <TableCell>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={(e) => {
                              e.stopPropagation()
                              copyErrorCode(err.code)
                            }}
                          >
                            <Copy className="h-3.5 w-3.5" />
                          </Button>
                        </TableCell>
                      </TableRow>
                      {isExpanded && (
                        <TableRow key={`${err.code}-detail`}>
                          <TableCell colSpan={6} className="bg-muted/30">
                            <div className="p-3 space-y-2">
                              <h4 className="text-sm font-semibold">Resolution</h4>
                              <p className="text-sm text-muted-foreground leading-relaxed">
                                {err.resolution}
                              </p>
                            </div>
                          </TableCell>
                        </TableRow>
                      )}
                    </>
                  )
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
