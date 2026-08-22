import { useLocation } from 'react-router-dom'
import { ChevronRight } from 'lucide-react'
import { navigation } from '../config/navigation'

/** Routes that are their own root and get no breadcrumb trail. */
const ROOT_PATHS = new Set(['/', '/dashboard'])

interface Match {
  domainLabel: string
  itemName: string
}

/** Find the nav item whose href matches pathname, carrying its domain label. */
function findMatch(pathname: string): Match | null {
  for (const domain of navigation) {
    for (const section of domain.sections) {
      for (const item of section.items) {
        if (item.href === pathname) {
          return { domainLabel: domain.label, itemName: item.name }
        }
      }
    }
  }
  return null
}

/**
 * Derives a "<domain> / <page>" breadcrumb trail from the nav config for the
 * current route. Renders nothing on root routes (/ and /dashboard) or when the
 * path is not in the nav (e.g. detail pages), so pages don't need to wire it up.
 */
export function Breadcrumbs() {
  const { pathname } = useLocation()
  if (ROOT_PATHS.has(pathname)) return null

  const match = findMatch(pathname)
  if (!match) return null

  return (
    <nav aria-label="Breadcrumb" className="flex items-center text-sm text-muted-foreground">
      {match.domainLabel && (
        <>
          <span>{match.domainLabel}</span>
          <ChevronRight className="mx-1 h-4 w-4" aria-hidden="true" />
        </>
      )}
      <span className="font-medium text-foreground">{match.itemName}</span>
    </nav>
  )
}
