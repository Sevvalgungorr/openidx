import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link2, Link2Off, Loader2, Plus } from 'lucide-react'
import { useState } from 'react'
import { Button } from './ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card'
import { api } from '../lib/api'

// Linked sign-in accounts.
//
// The sign-in flow deliberately refuses to attach an unknown external account
// to a local user just because the email addresses match, since anyone able to
// create an account bearing someone else's address would otherwise inherit
// that person's access. Attaching is therefore an explicit action taken from
// here, by someone already signed in, and it still requires proving control of
// the external account by signing in to it.
//
// The wording avoids protocol vocabulary on purpose: people think in terms of
// "the accounts I can sign in with", not providers, subjects or links.

interface IdentityLink {
  id: string
  provider_id: string
  provider_name: string | null
  external_email: string | null
  display_name: string | null
  linked_at: string
  last_used_at: string | null
}

interface AvailableProvider {
  id: string
  name: string
  type?: string
}

function formatWhen(value: string | null): string {
  if (!value) return 'not used yet'
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return 'not used yet'
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
}

export function LinkedAccountsCard() {
  const queryClient = useQueryClient()
  const [busyProvider, setBusyProvider] = useState<string | null>(null)
  const [problem, setProblem] = useState<string | null>(null)

  const { data: links, isLoading } = useQuery({
    queryKey: ['my-identity-links'],
    queryFn: async () => {
      const res = await api.get<{ data: IdentityLink[] }>(
        '/api/v1/identity/users/me/identity-links',
      )
      return res.data ?? []
    },
  })

  // Providers an admin has switched on for this organisation. Anything already
  // linked is filtered out below so the list only offers real next steps.
  const { data: providers } = useQuery({
    queryKey: ['available-login-providers'],
    queryFn: async () => {
      try {
        const res = await api.get<{ data?: AvailableProvider[] } | AvailableProvider[]>(
          '/api/v1/identity/providers',
        )
        if (Array.isArray(res)) return res
        return res.data ?? []
      } catch {
        // Not being able to offer new providers must not blank out the list of
        // accounts already linked.
        return []
      }
    },
  })

  const unlink = useMutation({
    mutationFn: async (linkId: string) =>
      api.delete(`/api/v1/identity/users/me/identity-links/${linkId}`),
    onSuccess: () => {
      setProblem(null)
      queryClient.invalidateQueries({ queryKey: ['my-identity-links'] })
    },
    onError: () => setProblem('Could not remove that account. Please try again.'),
  })

  // Starting a link hands back an authorization URL rather than redirecting, so
  // the browser navigates only on a deliberate click.
  async function startLink(providerId: string) {
    setBusyProvider(providerId)
    setProblem(null)
    try {
      const res = await api.post<{ authorization_url: string }>(
        `/oauth/social/link/${providerId}/start`,
        {},
      )
      if (res?.authorization_url) {
        window.location.href = res.authorization_url
        return
      }
      setProblem('Could not start sign-in with that account.')
    } catch {
      setProblem('Could not start sign-in with that account.')
    } finally {
      setBusyProvider(null)
    }
  }

  const linked = links ?? []
  const linkedProviderIds = new Set(linked.map((l) => l.provider_id))
  const addable = (providers ?? []).filter((p) => !linkedProviderIds.has(p.id))

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Link2 className="h-4 w-4" />
          Ways you can sign in
        </CardTitle>
        <CardDescription>
          Accounts you have connected, so you can sign in with them instead of your password
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {problem && (
          <p className="text-sm text-red-600 dark:text-red-400" role="alert">
            {problem}
          </p>
        )}

        {isLoading ? (
          <p className="text-sm text-muted-foreground">Loading…</p>
        ) : linked.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            You sign in with your work account only. Connect another account below to use it as an
            extra way in.
          </p>
        ) : (
          <ul className="space-y-2">
            {linked.map((link) => (
              <li
                key={link.id}
                className="flex items-center justify-between gap-3 rounded-md border p-3"
              >
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium">
                    {link.provider_name ?? 'Connected account'}
                  </p>
                  <p className="truncate text-xs text-muted-foreground">
                    {link.external_email ?? link.display_name ?? 'connected'} · last used{' '}
                    {formatWhen(link.last_used_at)}
                  </p>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={unlink.isPending}
                  onClick={() => unlink.mutate(link.id)}
                >
                  <Link2Off className="mr-1 h-3 w-3" />
                  Remove
                </Button>
              </li>
            ))}
          </ul>
        )}

        {addable.length > 0 && (
          <div className="space-y-2 pt-1">
            <p className="text-xs text-muted-foreground">
              You will be asked to sign in to the account to prove it is yours.
            </p>
            <div className="flex flex-wrap gap-2">
              {addable.map((p) => (
                <Button
                  key={p.id}
                  variant="outline"
                  size="sm"
                  disabled={busyProvider === p.id}
                  onClick={() => startLink(p.id)}
                >
                  {busyProvider === p.id ? (
                    <Loader2 className="mr-1 h-3 w-3 animate-spin" />
                  ) : (
                    <Plus className="mr-1 h-3 w-3" />
                  )}
                  Connect {p.name}
                </Button>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
