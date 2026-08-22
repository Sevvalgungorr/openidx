import { ReactNode } from 'react'
import type { UseQueryResult } from '@tanstack/react-query'
import { QueryError } from './query-error'
import { LoadingSpinner } from './ui/loading-spinner'

interface QueryGateProps<T> {
  /** The react-query result for the page's primary query. */
  query: Pick<UseQueryResult<T>, 'isLoading' | 'isError' | 'error' | 'data'>
  /** Human-readable name for the QueryError message, e.g. "users". */
  resource: string
  /** Optional element shown when the loaded data is empty (empty array / null). */
  empty?: ReactNode
  children: (data: T) => ReactNode
}

function isEmptyData(data: unknown): boolean {
  if (Array.isArray(data)) return data.length === 0
  return data == null
}

/**
 * Single choke-point for read-state rendering: a failed query renders QueryError
 * (which distinguishes 401/403 from a generic failure) instead of falling through
 * to a page's empty state. This is the structural fix for "401/403 masked as empty".
 */
export function QueryGate<T>({ query, resource, empty, children }: QueryGateProps<T>) {
  if (query.isLoading) return <LoadingSpinner />
  if (query.isError) return <QueryError error={query.error} resource={resource} />
  const data = query.data as T
  if (empty !== undefined && isEmptyData(data)) return <>{empty}</>
  return <>{children(data)}</>
}
