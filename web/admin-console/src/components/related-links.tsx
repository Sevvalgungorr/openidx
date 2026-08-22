import { Fragment } from 'react'
import { Link } from 'react-router-dom'

export interface RelatedLink {
  to: string
  label: string
}

interface RelatedLinksProps {
  links: RelatedLink[]
  className?: string
}

/**
 * A small token-styled row of cross-links, e.g. "Related: A · B · C".
 * Renders nothing when there are no links.
 */
export function RelatedLinks({ links, className }: RelatedLinksProps) {
  if (links.length === 0) return null

  return (
    <div className={`flex flex-wrap items-center gap-2 text-sm ${className ?? ''}`.trim()}>
      <span className="text-muted-foreground">Related:</span>
      {links.map((link, i) => (
        <Fragment key={link.to}>
          {i > 0 && <span className="text-muted-foreground">·</span>}
          <Link to={link.to} className="text-primary hover:underline text-sm">
            {link.label}
          </Link>
        </Fragment>
      ))}
    </div>
  )
}
