import type { HTMLAttributes } from 'react'
import { cn } from '../../lib/utils'

/** A single pulsing placeholder block. Size it via className (height/width). */
export function Skeleton({
  className,
  ...props
}: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn('animate-pulse rounded-md bg-muted', className)}
      {...props}
    />
  )
}

export interface TableSkeletonProps {
  rows?: number
  cols?: number
}

/**
 * A grid of skeleton cells that stands in for a table while data loads. It is a
 * plain CSS grid (not a real <table>) so it can drop into any layout.
 */
export function TableSkeleton({ rows = 5, cols = 4 }: TableSkeletonProps) {
  return (
    <div className="space-y-2" role="status" aria-label="Loading">
      {Array.from({ length: rows }).map((_, r) => (
        <div
          key={r}
          className="grid gap-2"
          style={{ gridTemplateColumns: `repeat(${cols}, minmax(0, 1fr))` }}
        >
          {Array.from({ length: cols }).map((_, c) => (
            <Skeleton key={c} className="h-6 w-full" />
          ))}
        </div>
      ))}
    </div>
  )
}
