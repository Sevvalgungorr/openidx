import { Link } from 'react-router-dom'
import { ExternalLink } from 'lucide-react'

/**
 * A user identifier that links to that user's cross-pillar Access 360 view.
 *
 * The platform detects risk in one pillar (a fused risk score, a security
 * alert, a login anomaly, an audit event) but the admin has to act in another
 * — reviewing the user's IAM roles, PAM grants and Ziti identity together, or
 * hitting the kill switch. Access 360 already fuses all of that; this makes the
 * jump one click from anywhere a user is named, instead of a manual search.
 *
 * Access 360 is an admin-only route; render this only on admin surfaces.
 */
export function UserLink({
  userId,
  name,
  subtitle,
  className,
}: {
  userId: string
  name: string
  subtitle?: string
  className?: string
}) {
  if (!userId) {
    // No id to route to — show the text without a dead link.
    return (
      <div className={className}>
        <div className="font-medium">{name}</div>
        {subtitle && <div className="text-xs text-muted-foreground">{subtitle}</div>}
      </div>
    )
  }
  return (
    <Link
      to={`/users/${userId}/access-360`}
      className={`group inline-block ${className ?? ''}`}
      title="Open this user's Access 360 (IAM · PAM · Network)"
    >
      <div className="flex items-center gap-1 font-medium text-blue-600 group-hover:underline dark:text-blue-400">
        <span className="truncate">{name}</span>
        <ExternalLink className="h-3 w-3 shrink-0 opacity-0 transition-opacity group-hover:opacity-100" />
      </div>
      {subtitle && <div className="text-xs text-muted-foreground">{subtitle}</div>}
    </Link>
  )
}
