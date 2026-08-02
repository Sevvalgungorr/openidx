import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Monitor, CheckCircle2, XCircle, AlertTriangle, Clock } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { OAUTH_URL } from '../lib/auth'

/**
 * Device authorization (RFC 8628) — the page the user opens on a phone or
 * laptop after a TV app, CLI or kiosk shows them a code.
 *
 * Without this page the grant is only reachable by hand-crafting requests to
 * /oauth/device/lookup and /oauth/device/decision, which is not a flow any
 * actual user can complete.
 */

interface DeviceCodeInfo {
  user_code: string
  client_id: string
  client_name: string
  scope: string
  state: string
  expires_in: number
}

// The server accepts any casing and separators; normalizing here too means the
// button enables when the code *looks* complete rather than only when it was
// typed in the one shape the screen happened to show.
function normalizeUserCode(input: string): string {
  return input.toUpperCase().replace(/[-\s_]/g, '')
}

const USER_CODE_LENGTH = 8

// The device endpoints live on the OAuth service, which is a different origin
// from the admin API the shared `api` client is bound to. Calling them through
// that client would send these requests to the wrong service entirely, so they
// go direct — same shape as the other OAuth call in the console (logout-all).
async function oauthFetch(path: string, init?: RequestInit): Promise<Response> {
  const token = localStorage.getItem('token')
  return fetch(`${OAUTH_URL}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(init?.headers ?? {}),
    },
  })
}

/** Human-readable scope list; an empty scope means the client asked for none. */
function describeScopes(scope: string): string[] {
  return scope.split(' ').map((s) => s.trim()).filter(Boolean)
}

export function DeviceAuthorizationPage() {
  const [searchParams] = useSearchParams()
  // verification_uri_complete puts the code in the query string so a device
  // that can render a QR code spares the user the typing entirely.
  const prefilled = searchParams.get('user_code') ?? ''

  const [code, setCode] = useState(prefilled)
  const [info, setInfo] = useState<DeviceCodeInfo | null>(null)
  const [lookupError, setLookupError] = useState<string | null>(null)
  const [looking, setLooking] = useState(false)
  const [deciding, setDeciding] = useState(false)
  const [outcome, setOutcome] = useState<'approved' | 'denied' | null>(null)
  const [decideError, setDecideError] = useState<string | null>(null)

  const normalized = normalizeUserCode(code)
  const complete = normalized.length === USER_CODE_LENGTH

  async function lookup(userCode: string) {
    setLooking(true)
    setLookupError(null)
    setInfo(null)
    try {
      const res = await oauthFetch(
        `/oauth/device/lookup?user_code=${encodeURIComponent(userCode)}`,
      )
      if (!res.ok) {
        // The server answers identically for "no such code" and "expired" so
        // this page cannot be used to probe which codes exist; the message says
        // the same thing rather than inventing a distinction the API refuses to
        // make.
        setLookupError(
          res.status === 404
            ? 'That code is not valid or has expired. Check the code on your device, or start again there.'
            : 'Could not check that code. Please try again.',
        )
        return
      }
      setInfo((await res.json()) as DeviceCodeInfo)
    } catch {
      setLookupError('Could not check that code. Please try again.')
    } finally {
      setLooking(false)
    }
  }

  // Auto-look-up a prefilled code so the QR path lands straight on the
  // confirmation rather than on an already-filled form the user must submit.
  useEffect(() => {
    const initial = normalizeUserCode(prefilled)
    if (initial.length === USER_CODE_LENGTH) {
      void lookup(initial)
    }
    // Runs once for the value the page was opened with.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  async function decide(approve: boolean) {
    if (!info) return
    setDeciding(true)
    setDecideError(null)
    try {
      const res = await oauthFetch('/oauth/device/decision', {
        method: 'POST',
        body: JSON.stringify({ user_code: info.user_code, approve }),
      })
      if (!res.ok) {
        setDecideError(
          res.status === 404
            ? 'That code expired or was already used while you were deciding. Start again on your device.'
            : 'Could not record your decision. Please try again.',
        )
        return
      }
      setOutcome(approve ? 'approved' : 'denied')
    } catch {
      setDecideError('Could not record your decision. Please try again.')
    } finally {
      setDeciding(false)
    }
  }

  if (outcome) {
    return (
      <div className="mx-auto max-w-lg py-10">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              {outcome === 'approved' ? (
                <CheckCircle2 className="h-5 w-5 text-green-600" />
              ) : (
                <XCircle className="h-5 w-5 text-red-600" />
              )}
              {outcome === 'approved' ? 'Device connected' : 'Request denied'}
            </CardTitle>
            <CardDescription>
              {outcome === 'approved'
                ? 'You can return to your device — it should continue on its own within a few seconds.'
                : 'The device was not given access. You can close this page.'}
            </CardDescription>
          </CardHeader>
        </Card>
      </div>
    )
  }

  return (
    <div className="mx-auto max-w-lg py-10">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Monitor className="h-5 w-5" />
            Connect a device
          </CardTitle>
          <CardDescription>
            Enter the code shown on your TV, terminal or other device.
          </CardDescription>
        </CardHeader>

        <CardContent className="space-y-6">
          {!info && (
            <form
              onSubmit={(e) => {
                e.preventDefault()
                if (complete) void lookup(normalized)
              }}
              className="space-y-4"
            >
              <div className="space-y-2">
                <label htmlFor="user_code" className="text-sm font-medium">
                  Device code
                </label>
                <input
                  id="user_code"
                  name="user_code"
                  autoFocus
                  autoComplete="off"
                  autoCapitalize="characters"
                  spellCheck={false}
                  placeholder="ACDE-FGHJ"
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  className="w-full rounded-md border px-3 py-2 text-center font-mono text-2xl tracking-widest uppercase"
                />
                <p className="text-xs text-muted-foreground">
                  Dashes, spaces and lower case are all fine.
                </p>
              </div>

              {lookupError && (
                <div className="flex items-start gap-2 rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-800">
                  <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                  <span>{lookupError}</span>
                </div>
              )}

              <Button type="submit" disabled={!complete || looking} className="w-full">
                {looking ? <LoadingSpinner /> : 'Continue'}
              </Button>
            </form>
          )}

          {info && (
            <div className="space-y-6">
              <div className="rounded-md border p-4">
                <p className="text-sm text-muted-foreground">You are about to give</p>
                <p className="mt-1 text-lg font-semibold">{info.client_name}</p>
                <p className="mt-1 text-sm text-muted-foreground">
                  access to your account.
                </p>

                <div className="mt-4 flex items-center gap-2 text-sm">
                  <span className="text-muted-foreground">Code</span>
                  <code className="font-mono tracking-widest">{info.user_code}</code>
                </div>

                {describeScopes(info.scope).length > 0 && (
                  <div className="mt-4">
                    <p className="text-sm text-muted-foreground">It is asking for</p>
                    <div className="mt-2 flex flex-wrap gap-2">
                      {describeScopes(info.scope).map((s) => (
                        <Badge key={s} variant="secondary">
                          {s}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                {info.expires_in > 0 && (
                  <p className="mt-4 flex items-center gap-1.5 text-xs text-muted-foreground">
                    <Clock className="h-3.5 w-3.5" />
                    Expires in about {Math.max(1, Math.round(info.expires_in / 60))} minute
                    {Math.round(info.expires_in / 60) === 1 ? '' : 's'}
                  </p>
                )}
              </div>

              <div className="flex items-start gap-2 rounded-md border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                <span>
                  Only continue if you started this on the device yourself. If someone
                  asked you to enter a code you did not request, deny it.
                </span>
              </div>

              {decideError && (
                <div className="flex items-start gap-2 rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-800">
                  <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                  <span>{decideError}</span>
                </div>
              )}

              <div className="flex gap-3">
                <Button
                  variant="outline"
                  className="flex-1"
                  disabled={deciding}
                  onClick={() => void decide(false)}
                >
                  Deny
                </Button>
                <Button className="flex-1" disabled={deciding} onClick={() => void decide(true)}>
                  {deciding ? <LoadingSpinner /> : 'Allow'}
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
