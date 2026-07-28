import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { CheckCircle2, Circle, X, Rocket } from 'lucide-react'

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from './ui/card'
import { api } from '../lib/api'

const DISMISS_KEY = 'oidx.getting_started_dismissed'

interface ZitiStatus {
  enabled: boolean
  controller_reachable?: boolean
}

/**
 * First-run onboarding checklist for a fresh admin. A brand-new install lands
 * on a Dashboard of zeros with no guided path; this walks the admin through the
 * core setup — register an app, connect a directory, configure sign-in, and
 * (optionally) stand up the zero-trust network — each step deep-linking to the
 * page that does it and ticking itself off as it's completed.
 *
 * It hides automatically once the required steps are done, and can be dismissed
 * (persisted in localStorage). Render only on admin surfaces.
 */
export function GettingStarted() {
  const [dismissed, setDismissed] = useState(() => localStorage.getItem(DISMISS_KEY) === '1')

  // Cheap admin reads; length is all we need to know a step is done.
  const { data: apps } = useQuery({
    queryKey: ['gs-applications'],
    queryFn: () => api.get<unknown[]>('/api/v1/applications'),
    staleTime: 60_000,
  })
  const { data: directories } = useQuery({
    queryKey: ['gs-directories'],
    queryFn: () => api.get<unknown[]>('/api/v1/directories'),
    staleTime: 60_000,
  })
  const { data: idps } = useQuery({
    queryKey: ['gs-identity-providers'],
    queryFn: () => api.get<unknown[]>('/api/v1/identity-providers'),
    staleTime: 60_000,
  })
  const { data: ziti } = useQuery({
    queryKey: ['gs-ziti-status'],
    queryFn: () => api.get<ZitiStatus>('/api/v1/access/ziti/status'),
    staleTime: 60_000,
  })

  // Wait until the reads resolve so a completed step never flashes as "to-do".
  const loaded = apps != null && directories != null && idps != null
  if (dismissed || !loaded) return null

  const len = (v: unknown): number => (Array.isArray(v) ? v.length : 0)
  const steps = [
    {
      title: 'Register your first application',
      description: 'Add an app so users have something to sign in to.',
      link: '/applications',
      done: len(apps) > 0,
      required: true,
    },
    {
      title: 'Connect a directory or invite users',
      description: 'Sync users from LDAP/AD/SCIM, or add them manually.',
      link: '/directories',
      done: len(directories) > 0,
      required: true,
    },
    {
      title: 'Configure sign-in',
      description: 'Add an identity provider (Google, Microsoft, SAML/OIDC).',
      link: '/identity-providers',
      done: len(idps) > 0,
      required: true,
    },
    {
      title: 'Set up the Zero Trust Network',
      description: 'Optional: stand up the OpenZiti overlay for private access.',
      link: '/ziti-setup',
      done: !!ziti?.enabled && !!ziti?.controller_reachable,
      required: false,
    },
  ]

  // Once every required step is done, retire the checklist automatically.
  if (steps.filter((s) => s.required).every((s) => s.done)) return null

  const completed = steps.filter((s) => s.done).length

  const dismiss = () => {
    localStorage.setItem(DISMISS_KEY, '1')
    setDismissed(true)
  }

  return (
    <Card className="border-blue-200 bg-blue-50/40 dark:border-blue-900 dark:bg-blue-950/20">
      <CardHeader className="flex flex-row items-start justify-between">
        <div>
          <CardTitle className="flex items-center gap-2 text-base">
            <Rocket className="h-5 w-5 text-blue-600" />
            Get started with OpenIDX
          </CardTitle>
          <CardDescription>
            {completed} of {steps.length} steps done — finish setting up your platform.
          </CardDescription>
        </div>
        <button
          onClick={dismiss}
          className="text-muted-foreground hover:text-foreground"
          aria-label="Dismiss getting started"
        >
          <X className="h-4 w-4" />
        </button>
      </CardHeader>
      <CardContent className="space-y-2">
        {steps.map((s) => (
          <Link
            key={s.title}
            to={s.link}
            className="flex items-start gap-3 rounded-lg p-2 transition-colors hover:bg-blue-100/50 dark:hover:bg-blue-900/30"
          >
            {s.done ? (
              <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-green-600" />
            ) : (
              <Circle className="mt-0.5 h-5 w-5 shrink-0 text-muted-foreground" />
            )}
            <div className="min-w-0">
              <div className={`text-sm font-medium ${s.done ? 'text-muted-foreground line-through' : ''}`}>
                {s.title}
                {!s.required && <span className="ml-2 text-xs font-normal text-muted-foreground">(optional)</span>}
              </div>
              <div className="text-xs text-muted-foreground">{s.description}</div>
            </div>
          </Link>
        ))}
      </CardContent>
    </Card>
  )
}
