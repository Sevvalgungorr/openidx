import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Building2 } from 'lucide-react'
import { useOrgStore } from '@/lib/store'
import { api } from '@/lib/api'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'

interface Organization {
  id: string
  name: string
  slug: string
}

// SELF is the sentinel for "act as my own token org" (no X-Org-Slug override).
// Radix Select forbids an empty-string item value, so we map this to null.
const SELF = '__self__'

/**
 * Lets a platform admin (super_admin) switch the org the console acts as.
 * The selected slug is stored (and attached as X-Org-Slug by the api
 * interceptor); switching invalidates cached queries so data refetches under
 * the new org. Mount only for platform admins so its query never runs for
 * regular admins.
 */
export function TenantSelector() {
  const { selectedOrgSlug, setOrg } = useOrgStore()
  const queryClient = useQueryClient()

  const { data } = useQuery({
    queryKey: ['organizations', 'selector'],
    queryFn: () => api.get<Organization[]>('/api/v1/organizations'),
  })

  const orgs = data ?? []

  return (
    <div className="flex items-center gap-2">
      <Building2 className="h-4 w-4 text-muted-foreground" />
      <Select
        value={selectedOrgSlug ?? SELF}
        onValueChange={(v) => {
          setOrg(v === SELF ? null : v)
          // Re-fetch everything under the newly selected tenant scope.
          queryClient.invalidateQueries()
        }}
      >
        <SelectTrigger className="h-9 w-48" aria-label="Select organization">
          <SelectValue placeholder="Your organization" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value={SELF}>Your organization</SelectItem>
          {orgs.map((o) => (
            <SelectItem key={o.id} value={o.slug}>
              {o.name}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  )
}
