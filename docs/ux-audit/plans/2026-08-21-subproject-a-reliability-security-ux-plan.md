# Sub-project A — Reliability & Security-UX Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship four reusable safety primitives (query-error gate, confirm-action dialog, secret field, revealed-secret hook) + a global session-expiry handler, then sweep them across the console, locked in by two CI guards — so 401/403 can't masquerade as empty, destructive actions can't fire unconfirmed, and secrets can't leak client-side.

**Architecture:** Small focused units under `web/admin-console/src/`. Primitives first (A0), each TDD'd in isolation. Then a safety-first sweep: P0 security pages (A1), broad error-handling adoption by domain (A2), session-expiry activation (A3). Two repo-idiomatic `scripts/check-*.sh` guards (with mutation-tested `.test.sh`) ship in warn mode and flip to enforce last (A4). No backend changes; no visual redesign (that's Sub-project B).

**Tech Stack:** React 18 + TypeScript, @tanstack/react-query, axios, tailwind, `components/ui/*` primitives (Radix-based), vitest + @testing-library/react. Test commands run from `web/admin-console`.

**Spec:** `docs/ux-audit/specs/2026-08-21-subproject-a-reliability-security-ux-design.md`

---

## File Structure

**New files:**
- `src/components/query-gate.tsx` — renders LoadingSpinner/QueryError/empty/data for a react-query result. (Unit 1)
- `src/components/confirm-action.tsx` — danger-dialog wrapper + `useConfirm` hook. (Unit 3)
- `src/components/secret-field.tsx` — edit-safe secret input (never prefilled). (Unit 4a)
- `src/lib/secret-reveal.ts` — `useRevealedSecret` hook + `copyWithWarning`. (Unit 4b)
- `src/components/session-expired-dialog.tsx` — non-dismissable "sign in again" modal. (Unit 2)
- `scripts/check-query-error-coverage.sh` + `.test.sh` — Guard 1. (Unit 5)
- `scripts/check-destructive-confirm.sh` + `.test.sh` — Guard 2. (Unit 5)
- Test files: `*.test.tsx`/`*.test.ts` colocated with each new source file.

**Modified files:**
- `src/lib/api.ts` — registerable `onAuthExpired` handler invoked from the existing 401 interceptor.
- `src/lib/auth.tsx` — register the handler; hold `sessionExpired` state; render `SessionExpiredDialog`.
- `.github/workflows/ci.yml` — new job running both guards.
- Sweep targets (A1/A2) — listed per task.

**Reused as-is:** `src/components/query-error.tsx` (`QueryError`, `getErrorStatus`), `src/components/ui/{loading-spinner,alert-dialog,textarea,label,input,dialog,button}.tsx`.

---

## Task 1: `QueryGate` component (Unit 1)

**Files:**
- Create: `web/admin-console/src/components/query-gate.tsx`
- Test: `web/admin-console/src/components/query-gate.test.tsx`

- [ ] **Step 1: Write the failing test**

```tsx
// src/components/query-gate.test.tsx
import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { QueryGate } from './query-gate'

// Minimal stand-in for a react-query UseQueryResult; only the fields QueryGate reads.
const q = (over: Record<string, unknown>) =>
  ({ isLoading: false, isError: false, error: null, data: undefined, ...over }) as never

describe('QueryGate', () => {
  it('renders a spinner while loading', () => {
    const { container } = render(<QueryGate query={q({ isLoading: true })} resource="users">{() => <div>rows</div>}</QueryGate>)
    expect(container.querySelector('.animate-spin')).toBeTruthy()
    expect(screen.queryByText('rows')).toBeNull()
  })

  it('renders QueryError (permission copy) on a 403', () => {
    render(<QueryGate query={q({ isError: true, error: { response: { status: 403 } } })} resource="users">{() => <div>rows</div>}</QueryGate>)
    expect(screen.getByText(/don't have permission to view users/i)).toBeInTheDocument()
    expect(screen.queryByText('rows')).toBeNull()
  })

  it('renders the empty fallback when data is an empty array', () => {
    render(<QueryGate query={q({ data: [] })} resource="users" empty={<div>none</div>}>{() => <div>rows</div>}</QueryGate>)
    expect(screen.getByText('none')).toBeInTheDocument()
  })

  it('renders children with data', () => {
    render(<QueryGate query={q({ data: [1, 2] })} resource="users">{(d: number[]) => <div>{d.length} rows</div>}</QueryGate>)
    expect(screen.getByText('2 rows')).toBeInTheDocument()
  })
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd web/admin-console && npx vitest run src/components/query-gate.test.tsx`
Expected: FAIL — `Failed to resolve import './query-gate'`.

- [ ] **Step 3: Write the implementation**

```tsx
// src/components/query-gate.tsx
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
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd web/admin-console && npx vitest run src/components/query-gate.test.tsx`
Expected: PASS (4 tests).

- [ ] **Step 5: Typecheck + commit**

```bash
cd web/admin-console && npx tsc --noEmit
cd /home/cmit/openidx
git add web/admin-console/src/components/query-gate.tsx web/admin-console/src/components/query-gate.test.tsx
git commit -m "feat(ui): QueryGate — render QueryError on read failure, never mask as empty

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: `ConfirmAction` danger-dialog (Unit 3)

**Files:**
- Create: `web/admin-console/src/components/confirm-action.tsx`
- Test: `web/admin-console/src/components/confirm-action.test.tsx`

- [ ] **Step 1: Write the failing test**

```tsx
// src/components/confirm-action.test.tsx
import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { ConfirmAction } from './confirm-action'

describe('ConfirmAction', () => {
  it('opens the dialog from the trigger and confirms', async () => {
    const onConfirm = vi.fn()
    render(
      <ConfirmAction title="Delete item?" description="This cannot be undone." onConfirm={onConfirm}>
        {(open) => <button onClick={open}>Delete</button>}
      </ConfirmAction>,
    )
    fireEvent.click(screen.getByText('Delete'))
    expect(await screen.findByText('Delete item?')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /confirm/i }))
    await waitFor(() => expect(onConfirm).toHaveBeenCalledTimes(1))
  })

  it('blocks confirm until a required reason is entered, then passes it', async () => {
    const onConfirm = vi.fn()
    render(
      <ConfirmAction title="Revoke access?" description="Removes the grant." requireReason onConfirm={onConfirm}>
        {(open) => <button onClick={open}>Revoke</button>}
      </ConfirmAction>,
    )
    fireEvent.click(screen.getByText('Revoke'))
    const confirm = screen.getByRole('button', { name: /confirm/i })
    expect(confirm).toBeDisabled()
    fireEvent.change(await screen.findByLabelText(/reason/i), { target: { value: 'offboarding' } })
    expect(confirm).not.toBeDisabled()
    fireEvent.click(confirm)
    await waitFor(() => expect(onConfirm).toHaveBeenCalledWith('offboarding'))
  })
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd web/admin-console && npx vitest run src/components/confirm-action.test.tsx`
Expected: FAIL — cannot resolve `./confirm-action`.

- [ ] **Step 3: Write the implementation**

```tsx
// src/components/confirm-action.tsx
import { ReactNode, useState } from 'react'
import {
  AlertDialog, AlertDialogContent, AlertDialogHeader, AlertDialogFooter,
  AlertDialogTitle, AlertDialogDescription, AlertDialogAction, AlertDialogCancel,
} from './ui/alert-dialog'
import { Textarea } from './ui/textarea'
import { Label } from './ui/label'

interface ConfirmActionProps {
  title: string
  description: string
  /** Optional blast-radius summary rendered above the actions. */
  impact?: ReactNode
  confirmLabel?: string
  /** Red styling for irreversible actions. */
  destructive?: boolean
  /** Require a typed reason (audited) before confirm is enabled. */
  requireReason?: boolean
  onConfirm: (reason?: string) => void | Promise<unknown>
  /** Render-prop for the trigger; call `open()` to show the dialog. */
  children: (open: () => void) => ReactNode
}

/**
 * The single component every destructive/privileged mutation routes through.
 * Security-critical actions pass `requireReason` so the confirmation is auditable.
 */
export function ConfirmAction({
  title, description, impact, confirmLabel = 'Confirm',
  destructive, requireReason, onConfirm, children,
}: ConfirmActionProps) {
  const [open, setOpen] = useState(false)
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const disabled = busy || (!!requireReason && reason.trim() === '')

  const handleConfirm = async () => {
    setBusy(true)
    try {
      await onConfirm(requireReason ? reason.trim() : undefined)
      setOpen(false)
      setReason('')
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      {children(() => setOpen(true))}
      <AlertDialog open={open} onOpenChange={setOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{title}</AlertDialogTitle>
            <AlertDialogDescription>{description}</AlertDialogDescription>
          </AlertDialogHeader>
          {impact}
          {requireReason && (
            <div className="space-y-1">
              <Label htmlFor="confirm-reason">Reason (required)</Label>
              <Textarea
                id="confirm-reason"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder="Why are you doing this? (recorded in the audit log)"
              />
            </div>
          )}
          <AlertDialogFooter>
            <AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              disabled={disabled}
              onClick={(e) => { e.preventDefault(); void handleConfirm() }}
              className={destructive ? 'bg-red-600 hover:bg-red-700 focus:ring-red-600' : undefined}
            >
              {confirmLabel}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd web/admin-console && npx vitest run src/components/confirm-action.test.tsx`
Expected: PASS (2 tests).

- [ ] **Step 5: Typecheck + commit**

```bash
cd web/admin-console && npx tsc --noEmit
cd /home/cmit/openidx
git add web/admin-console/src/components/confirm-action.tsx web/admin-console/src/components/confirm-action.test.tsx
git commit -m "feat(ui): ConfirmAction danger-dialog (optional required reason)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: `SecretField` (Unit 4a)

**Files:**
- Create: `web/admin-console/src/components/secret-field.tsx`
- Test: `web/admin-console/src/components/secret-field.test.tsx`

- [ ] **Step 1: Write the failing test**

```tsx
// src/components/secret-field.test.tsx
import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { SecretField } from './secret-field'

describe('SecretField', () => {
  it('in edit mode starts blank with a "leave blank to keep" placeholder', () => {
    render(<SecretField mode="edit" value="" onChange={() => {}} />)
    const input = screen.getByPlaceholderText(/leave blank to keep/i) as HTMLInputElement
    expect(input.type).toBe('password')
    expect(input.value).toBe('')
  })

  it('reports changed=true only when a value is typed', () => {
    const onChange = vi.fn()
    render(<SecretField mode="edit" value="" onChange={onChange} />)
    fireEvent.change(screen.getByPlaceholderText(/leave blank to keep/i), { target: { value: 's3cret' } })
    expect(onChange).toHaveBeenCalledWith('s3cret', true)
  })
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd web/admin-console && npx vitest run src/components/secret-field.test.tsx`
Expected: FAIL — cannot resolve `./secret-field`.

- [ ] **Step 3: Write the implementation**

```tsx
// src/components/secret-field.tsx
import { Input } from './ui/input'

interface SecretFieldProps {
  id?: string
  /** 'edit' = a secret already exists server-side; never prefill it. */
  mode: 'create' | 'edit'
  value: string
  /** (value, changed) — parent sends the value only when changed is true. */
  onChange: (value: string, changed: boolean) => void
  placeholder?: string
}

/**
 * A password input that never receives a stored secret from the API. On edit it
 * starts blank ("leave blank to keep current") and reports `changed` so the
 * parent only transmits a new secret when the user actually typed one. This stops
 * stored secrets (client_secret, bind_password) from being shipped to the browser.
 */
export function SecretField({ id, mode, value, onChange, placeholder }: SecretFieldProps) {
  const ph = mode === 'edit' ? 'leave blank to keep current' : (placeholder ?? '')
  return (
    <Input
      id={id}
      type="password"
      autoComplete="new-password"
      value={value}
      placeholder={ph}
      onChange={(e) => onChange(e.target.value, e.target.value.length > 0)}
    />
  )
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd web/admin-console && npx vitest run src/components/secret-field.test.tsx`
Expected: PASS (2 tests).

- [ ] **Step 5: Typecheck + commit**

```bash
cd web/admin-console && npx tsc --noEmit
cd /home/cmit/openidx
git add web/admin-console/src/components/secret-field.tsx web/admin-console/src/components/secret-field.test.tsx
git commit -m "feat(ui): SecretField — never prefill stored secrets on edit

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: `useRevealedSecret` + `copyWithWarning` (Unit 4b)

**Files:**
- Create: `web/admin-console/src/lib/secret-reveal.ts`
- Test: `web/admin-console/src/lib/secret-reveal.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// src/lib/secret-reveal.test.ts
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { useRevealedSecret, copyWithWarning } from './secret-reveal'

describe('useRevealedSecret', () => {
  beforeEach(() => vi.useFakeTimers())
  afterEach(() => vi.useRealTimers())

  it('reveals then auto-clears after the TTL', () => {
    const { result } = renderHook(() => useRevealedSecret(1000))
    act(() => result.current.reveal('topsecret'))
    expect(result.current.value).toBe('topsecret')
    act(() => vi.advanceTimersByTime(1000))
    expect(result.current.value).toBeNull()
  })

  it('clear() wipes the value immediately', () => {
    const { result } = renderHook(() => useRevealedSecret(10000))
    act(() => result.current.reveal('x'))
    act(() => result.current.clear())
    expect(result.current.value).toBeNull()
  })
})

describe('copyWithWarning', () => {
  it('returns false when clipboard write rejects', async () => {
    vi.stubGlobal('navigator', { clipboard: { writeText: () => Promise.reject(new Error('denied')) } })
    expect(await copyWithWarning('s')).toBe(false)
    vi.unstubAllGlobals()
  })
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd web/admin-console && npx vitest run src/lib/secret-reveal.test.ts`
Expected: FAIL — cannot resolve `./secret-reveal`.

- [ ] **Step 3: Write the implementation**

```ts
// src/lib/secret-reveal.ts
import { useCallback, useEffect, useRef, useState } from 'react'

const DEFAULT_TTL_MS = 30_000

/**
 * Holds a revealed plaintext secret that auto-clears after `ttlMs` and on unmount,
 * so a decrypted value does not linger in React state / the DOM indefinitely.
 */
export function useRevealedSecret(ttlMs: number = DEFAULT_TTL_MS) {
  const [value, setValue] = useState<string | null>(null)
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)

  const clear = useCallback(() => {
    if (timer.current) clearTimeout(timer.current)
    timer.current = undefined
    setValue(null)
  }, [])

  const reveal = useCallback((secret: string) => {
    if (timer.current) clearTimeout(timer.current)
    setValue(secret)
    timer.current = setTimeout(() => setValue(null), ttlMs)
  }, [ttlMs])

  useEffect(() => () => { if (timer.current) clearTimeout(timer.current) }, [])

  return { value, reveal, clear }
}

/**
 * Copy a secret to the clipboard, returning false (instead of throwing) when the
 * write is denied/unavailable so the caller can warn the user. The caller should
 * also warn that the OS clipboard may retain the value.
 */
export async function copyWithWarning(secret: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(secret)
    return true
  } catch {
    return false
  }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd web/admin-console && npx vitest run src/lib/secret-reveal.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 5: Typecheck + commit**

```bash
cd web/admin-console && npx tsc --noEmit
cd /home/cmit/openidx
git add web/admin-console/src/lib/secret-reveal.ts web/admin-console/src/lib/secret-reveal.test.ts
git commit -m "feat(ui): useRevealedSecret (auto-clear) + copyWithWarning

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: Session-expiry handler + dialog (Unit 2)

**Files:**
- Create: `web/admin-console/src/components/session-expired-dialog.tsx`
- Modify: `web/admin-console/src/lib/api.ts` (add registerable handler; call it from the existing 401 branch at ~line 209)
- Modify: `web/admin-console/src/lib/auth.tsx` (register handler; state; render dialog)
- Test: `web/admin-console/src/lib/api.auth-expired.test.ts`

- [ ] **Step 1: Write the failing test for the api handler seam**

```ts
// src/lib/api.auth-expired.test.ts
import { describe, it, expect, vi } from 'vitest'
import { setAuthExpiredHandler, notifyAuthExpired } from './api'

describe('auth-expired handler', () => {
  it('invokes a registered handler once, and is a no-op after clearing', () => {
    const fn = vi.fn()
    setAuthExpiredHandler(fn)
    notifyAuthExpired('/api/v1/users')
    expect(fn).toHaveBeenCalledTimes(1)
    setAuthExpiredHandler(null)
    notifyAuthExpired('/api/v1/users')
    expect(fn).toHaveBeenCalledTimes(1)
  })

  it('does not fire for OAuth/refresh/login URLs (avoids redirect loops)', () => {
    const fn = vi.fn()
    setAuthExpiredHandler(fn)
    notifyAuthExpired('/oauth/token')
    notifyAuthExpired('https://host/login')
    expect(fn).not.toHaveBeenCalled()
    setAuthExpiredHandler(null)
  })
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd web/admin-console && npx vitest run src/lib/api.auth-expired.test.ts`
Expected: FAIL — `setAuthExpiredHandler`/`notifyAuthExpired` are not exported.

- [ ] **Step 3: Add the handler seam to `api.ts`**

Add near the top of `src/lib/api.ts` (after imports, before `axiosInstance`):

```ts
// Registerable session-expiry hook. The auth context registers a handler; the
// 401 interceptor calls notifyAuthExpired so a dead session surfaces ONE re-login
// dialog instead of scattered masked-empty states. Exempts the auth endpoints to
// avoid redirect loops.
let authExpiredHandler: (() => void) | null = null
export function setAuthExpiredHandler(fn: (() => void) | null) {
  authExpiredHandler = fn
}
export function notifyAuthExpired(url: string | undefined) {
  const u = url || ''
  const exempt = u.includes('/oauth/') || u.includes('/token') || u.endsWith('/login')
  if (!exempt && authExpiredHandler) authExpiredHandler()
}
```

Then, inside the existing response interceptor's 401 branch (currently just `console.warn` at ~line 212), add the notify call:

```ts
    if (error.response?.status === 401) {
      console.warn('[API] 401 Unauthorized:', error.config?.url)
      notifyAuthExpired(error.config?.url)
    }
```

- [ ] **Step 4: Run the handler test to verify it passes**

Run: `cd web/admin-console && npx vitest run src/lib/api.auth-expired.test.ts`
Expected: PASS (2 tests).

- [ ] **Step 5: Write the `SessionExpiredDialog` test**

```tsx
// src/components/session-expired-dialog.test.tsx
import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { SessionExpiredDialog } from './session-expired-dialog'

describe('SessionExpiredDialog', () => {
  it('shows when open and calls onSignIn', () => {
    const onSignIn = vi.fn()
    render(<SessionExpiredDialog open onSignIn={onSignIn} />)
    expect(screen.getByText(/session ended/i)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))
    expect(onSignIn).toHaveBeenCalled()
  })

  it('renders nothing when closed', () => {
    const { container } = render(<SessionExpiredDialog open={false} onSignIn={() => {}} />)
    expect(container.textContent).toBe('')
  })
})
```

- [ ] **Step 6: Run it to verify it fails, then implement `SessionExpiredDialog`**

Run: `cd web/admin-console && npx vitest run src/components/session-expired-dialog.test.tsx` → FAIL (unresolved import).

```tsx
// src/components/session-expired-dialog.tsx
import { Button } from './ui/button'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from './ui/dialog'

interface SessionExpiredDialogProps {
  open: boolean
  onSignIn: () => void
}

/**
 * Non-dismissable modal shown when a request 401s mid-session. Gives the user one
 * clear path back (re-authenticate) instead of leaving them on masked-empty pages.
 */
export function SessionExpiredDialog({ open, onSignIn }: SessionExpiredDialogProps) {
  if (!open) return null
  return (
    <Dialog open={open}>
      <DialogContent onPointerDownOutside={(e) => e.preventDefault()} onEscapeKeyDown={(e) => e.preventDefault()}>
        <DialogHeader>
          <DialogTitle>Your session ended</DialogTitle>
          <DialogDescription>Please sign in again to continue.</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button onClick={onSignIn}>Sign in</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
```

Run again → PASS (2 tests).

- [ ] **Step 7: Wire the dialog into `auth.tsx`**

In `src/lib/auth.tsx`: import the seam + dialog, add state, register on mount, render the dialog inside the provider. Add these imports at the top:

```tsx
import { setAuthExpiredHandler } from './api'
import { SessionExpiredDialog } from '../components/session-expired-dialog'
```

Inside `AuthProvider`, after the existing state declarations, add:

```tsx
  const [sessionExpired, setSessionExpired] = useState(false)

  useEffect(() => {
    setAuthExpiredHandler(() => setSessionExpired(true))
    return () => setAuthExpiredHandler(null)
  }, [])
```

Then render the dialog alongside `children` in the provider's returned JSX (the provider returns `<AuthContext.Provider value=...>{children}</AuthContext.Provider>` — wrap so the dialog is a sibling of `children`):

```tsx
    <AuthContext.Provider value={/* existing value object */}>
      {children}
      <SessionExpiredDialog open={sessionExpired} onSignIn={login} />
    </AuthContext.Provider>
```

(`login` already exists in this scope and redirects to OAuth.)

- [ ] **Step 8: Typecheck, build, commit**

```bash
cd web/admin-console && npx tsc --noEmit && npm run build
cd /home/cmit/openidx
git add web/admin-console/src/lib/api.ts web/admin-console/src/lib/api.auth-expired.test.ts \
  web/admin-console/src/lib/auth.tsx \
  web/admin-console/src/components/session-expired-dialog.tsx web/admin-console/src/components/session-expired-dialog.test.tsx
git commit -m "feat(ui): global session-expiry — 401 surfaces one re-login dialog

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 6: Guard 1 — query-error coverage (`check-query-error-coverage.sh`)

**Files:**
- Create: `scripts/check-query-error-coverage.sh`
- Create: `scripts/check-query-error-coverage.test.sh`

Convention (from the repo's existing `scripts/check-*.sh` + `*.test.sh`): the checker has a "why" header, `set -uo pipefail`, a default **warn** mode (prints offenders, exits 0) and an `--enforce` mode (exits 1 if any offender). The paired `.test.sh` uses temp fixtures to prove it flags a bad file and ignores a good one (both directions), tracked with a `fails` counter, and runs in CI via `bash scripts/<name>.test.sh`.

- [ ] **Step 1: Write the failing test**

```bash
# scripts/check-query-error-coverage.test.sh
#!/usr/bin/env bash
# Mutation test for the query-error coverage guard: it must FLAG a page that
# fetches with useQuery but never renders QueryError/QueryGate, and IGNORE a page
# that does. A guard that can't go red (or that flags good code) is worse than none.
set -uo pipefail
cd "$(dirname "$0")/.."
fails=0; ok(){ echo "  OK  $1"; }; bad(){ echo "  FAIL  $1"; fails=$((fails+1)); }
tmp=$(mktemp -d)

# BAD: uses useQuery, no error surface.
cat > "$tmp/bad.tsx" <<'TSX'
const q = useQuery({ queryKey: ['x'], queryFn: () => api.get('/x') })
return <div>{q.data?.length ?? 'No items found'}</div>
TSX
# GOOD: uses useQuery AND QueryGate.
cat > "$tmp/good.tsx" <<'TSX'
const q = useQuery({ queryKey: ['x'], queryFn: () => api.get('/x') })
return <QueryGate query={q} resource="x">{(d) => <div>{d.length}</div>}</QueryGate>
TSX

out=$(SH_PAGES_DIR="$tmp" bash scripts/check-query-error-coverage.sh)
echo "$out" | grep -q 'bad.tsx' && ok "flags a page with no QueryError" || bad "missed the bad page"
echo "$out" | grep -q 'good.tsx' && bad "flagged a good page" || ok "ignores a compliant page"

# enforce mode exits nonzero when an offender exists.
SH_PAGES_DIR="$tmp" bash scripts/check-query-error-coverage.sh --enforce >/dev/null 2>&1 && bad "enforce did not fail on offender" || ok "enforce fails on offender"

rm -rf "$tmp"
[ "$fails" -eq 0 ] && echo "check-query-error-coverage PASS" || { echo "FAIL ($fails)"; exit 1; }
```

- [ ] **Step 2: Run it to verify it fails**

Run: `bash scripts/check-query-error-coverage.test.sh`
Expected: FAIL — `check-query-error-coverage.sh: No such file or directory`.

- [ ] **Step 3: Write the guard**

```bash
# scripts/check-query-error-coverage.sh
#!/usr/bin/env bash
# Guard: every admin-console page that reads data with useQuery MUST render
# QueryError (directly or via QueryGate). Otherwise a 401/403 silently becomes a
# "no data" empty state — the console-wide masking defect this sub-project fixes.
# Default: warn (list offenders, exit 0). --enforce: exit 1 if any offender.
set -uo pipefail
cd "$(dirname "$0")/.."
PAGES="${SH_PAGES_DIR:-web/admin-console/src/pages}"
ENFORCE=0; [ "${1:-}" = "--enforce" ] && ENFORCE=1

# Files that legitimately have no data read (pure forms/static) may be allowlisted.
ALLOWLIST="api-docs.tsx"

offenders=0
while IFS= read -r f; do
  base=$(basename "$f")
  case " $ALLOWLIST " in *" $base "*) continue;; esac
  grep -q 'useQuery' "$f" || continue
  if ! grep -Eq 'QueryError|QueryGate' "$f"; then
    echo "offender: $f"
    offenders=$((offenders+1))
  fi
done < <(find "$PAGES" -name '*.tsx' ! -name '*.test.tsx')

echo "query-error-coverage offenders: $offenders"
if [ "$ENFORCE" = 1 ] && [ "$offenders" -gt 0 ]; then exit 1; fi
exit 0
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `bash scripts/check-query-error-coverage.test.sh`
Expected: PASS (`check-query-error-coverage PASS`).

- [ ] **Step 5: Record the baseline (warn) + commit**

Run (informational — captures how many pages need fixing in A2):
```bash
bash scripts/check-query-error-coverage.sh | tail -1
```
Expected: a large offender count (the audit estimated ~90+). This is the A2 worklist.

```bash
chmod +x scripts/check-query-error-coverage.sh scripts/check-query-error-coverage.test.sh
git add scripts/check-query-error-coverage.sh scripts/check-query-error-coverage.test.sh
git commit -m "ci(ui): guard — pages with useQuery must render QueryError (warn mode)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 7: Guard 2 — destructive-confirm (`check-destructive-confirm.sh`)

**Files:**
- Create: `scripts/check-destructive-confirm.sh`
- Create: `scripts/check-destructive-confirm.test.sh`

- [ ] **Step 1: Write the failing test**

```bash
# scripts/check-destructive-confirm.test.sh
#!/usr/bin/env bash
# Mutation test for the destructive-confirm guard: a page whose mutation is named
# with a destructive verb (delete/revoke/rotate/terminate/deprovision/quarantine/
# legalHold/broadcast) must gate it behind ConfirmAction/AlertDialog. Flag the bad
# page, ignore the good one.
set -uo pipefail
cd "$(dirname "$0")/.."
fails=0; ok(){ echo "  OK  $1"; }; bad(){ echo "  FAIL  $1"; fails=$((fails+1)); }
tmp=$(mktemp -d)

cat > "$tmp/bad.tsx" <<'TSX'
const deleteMutation = useMutation({ mutationFn: (id) => api.delete(`/x/${id}`) })
return <button onClick={() => deleteMutation.mutate(id)}>Delete</button>
TSX
cat > "$tmp/good.tsx" <<'TSX'
const deleteMutation = useMutation({ mutationFn: (id) => api.delete(`/x/${id}`) })
return <ConfirmAction title="Delete?" description="." onConfirm={() => deleteMutation.mutate(id)}>{(open)=><button onClick={open}>Delete</button>}</ConfirmAction>
TSX

out=$(SH_PAGES_DIR="$tmp" bash scripts/check-destructive-confirm.sh)
echo "$out" | grep -q 'bad.tsx' && ok "flags unconfirmed destructive mutation" || bad "missed the bad page"
echo "$out" | grep -q 'good.tsx' && bad "flagged a confirmed page" || ok "ignores a confirmed page"

SH_PAGES_DIR="$tmp" bash scripts/check-destructive-confirm.sh --enforce >/dev/null 2>&1 && bad "enforce did not fail" || ok "enforce fails on offender"

rm -rf "$tmp"
[ "$fails" -eq 0 ] && echo "check-destructive-confirm PASS" || { echo "FAIL ($fails)"; exit 1; }
```

- [ ] **Step 2: Run it to verify it fails**

Run: `bash scripts/check-destructive-confirm.test.sh`
Expected: FAIL — script not found.

- [ ] **Step 3: Write the guard**

```bash
# scripts/check-destructive-confirm.sh
#!/usr/bin/env bash
# Guard: a page containing a destructive mutation (identifier matches a destructive
# verb) MUST also use ConfirmAction or AlertDialog. Heuristic + allowlist. This is
# a backstop against "one-click delete/revoke/terminate with no confirmation".
# Default: warn (exit 0). --enforce: exit 1 if any offender.
set -uo pipefail
cd "$(dirname "$0")/.."
PAGES="${SH_PAGES_DIR:-web/admin-console/src/pages}"
ENFORCE=0; [ "${1:-}" = "--enforce" ] && ENFORCE=1

# Destructive intent detected when a mutation/handler identifier matches one of
# these verbs near a .mutate( call or api.delete(.
VERBS='delete|revoke|rotate|terminate|deprovision|quarantine|legalHold|legal_hold|broadcast|revert|unblock|remove'
ALLOWLIST=""

offenders=0
while IFS= read -r f; do
  base=$(basename "$f")
  case " $ALLOWLIST " in *" $base "*) continue;; esac
  # Does the file express destructive intent at a mutate/delete call site?
  if grep -Eiq "($VERBS)[A-Za-z]*\.mutate\(|\.mutate\([^)]*($VERBS)|api\.delete\(" "$f"; then
    # If it does, it must also gate behind a confirm surface.
    if ! grep -Eq 'ConfirmAction|AlertDialog' "$f"; then
      echo "offender: $f"
      offenders=$((offenders+1))
    fi
  fi
done < <(find "$PAGES" -name '*.tsx' ! -name '*.test.tsx')

echo "destructive-confirm offenders: $offenders"
if [ "$ENFORCE" = 1 ] && [ "$offenders" -gt 0 ]; then exit 1; fi
exit 0
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `bash scripts/check-destructive-confirm.test.sh`
Expected: PASS (`check-destructive-confirm PASS`).

- [ ] **Step 5: Record baseline + commit**

```bash
bash scripts/check-destructive-confirm.sh | tail -1   # A1 worklist size
chmod +x scripts/check-destructive-confirm.sh scripts/check-destructive-confirm.test.sh
git add scripts/check-destructive-confirm.sh scripts/check-destructive-confirm.test.sh
git commit -m "ci(ui): guard — destructive mutations must be confirmed (warn mode)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 8: Wire both guards into CI (warn mode)

**Files:**
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Add a job mirroring the existing `selfheal` job**

Add after the `selfheal` job (same file, same indentation as other jobs):

```yaml
  ui-safety-guards:
    name: UI safety guards
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@v7
      - name: Guard self-tests (must go red on a real regression)
        run: |
          bash scripts/check-query-error-coverage.test.sh
          bash scripts/check-destructive-confirm.test.sh
      - name: Report coverage (warn mode — informational until the sweep completes)
        run: |
          bash scripts/check-query-error-coverage.sh
          bash scripts/check-destructive-confirm.sh
```

- [ ] **Step 2: Validate YAML locally**

Run: `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml')); print('yaml ok')"`
Expected: `yaml ok`.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci(ui): run UI safety guards (warn mode) + their self-tests

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 9: A1 — P0 security sweep (secrets + top destructive confirms)

This wave applies Units 3 & 4 to the highest-risk pages the audit named. Each page is its own commit. After each, run that page's existing test + `npx tsc --noEmit`.

**Files (secrets — apply `SecretField` on edit + stop echoing the stored secret):**
- Modify: `web/admin-console/src/pages/identity-providers.tsx` (stop prefilling `client_secret` ~L190)
- Modify: `web/admin-console/src/pages/directories.tsx` (`bind_password`, `client_secret` on edit)
- Modify: `web/admin-console/src/pages/vault-secrets.tsx` (reveal via `useRevealedSecret`, `copyWithWarning`)
- Modify: `web/admin-console/src/pages/pam-connections.tsx` (same reveal treatment)
- Modify: `web/admin-console/src/pages/passwordless-settings.tsx` (remove hardcoded `enabled:true`; gate behind `isError`)

**Files (destructive — wrap the action in `ConfirmAction`, `requireReason` for the security-critical ones):**
- `certificates.tsx` (revert-to-self-signed — requireReason), `ziti-ai-insights.tsx` (quarantine — requireReason), `lifecycle-policies.tsx` (live deprovision Run + delete — requireReason on deprovision), `notification-admin.tsx` (send broadcast — requireReason; delete rule/broadcast), `remote-support.tsx` (legal-hold — replace `window.prompt`, requireReason), `device-trust-approval.tsx` (bulk approve/reject — requireReason), `lifecycle-workflows.tsx` (delete workflow), `certification-campaigns.tsx` (delete + revoke — requireReason on revoke), `attestation-campaigns.tsx` (revoke — requireReason), `hardware-tokens.tsx` (revoke/report-lost), `mfa-bypass-codes.tsx` (revoke), `security-alerts.tsx` (unblock IP), `bulk-operations.tsx` (delete/disable/reset — requireReason).

- [ ] **Step 1: Worked exemplar — `SecretField` in `identity-providers.tsx`**

Replace the client-secret `<Input>` in the edit/create form and stop seeding it from the API. Pattern:

```tsx
// import
import { SecretField } from '../components/secret-field'

// in the form state init on EDIT: do NOT copy provider.client_secret into form state.
// Render:
<SecretField
  id="idp-client-secret"
  mode={editingId ? 'edit' : 'create'}
  value={form.client_secret}
  onChange={(v, changed) => setForm((f) => ({ ...f, client_secret: v, client_secret_changed: changed }))}
/>

// on submit: only include client_secret when it changed (edit) or on create.
const payload = {
  ...form,
  ...(editingId && !form.client_secret_changed ? { client_secret: undefined } : {}),
}
```

- [ ] **Step 2: Verify + commit the exemplar**

Run: `cd web/admin-console && npx vitest run src/pages/identity-providers.test.tsx && npx tsc --noEmit`
Expected: PASS + no type errors.

```bash
cd /home/cmit/openidx
git add web/admin-console/src/pages/identity-providers.tsx
git commit -m "fix(ui): identity-providers — stop echoing client_secret to the browser

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

- [ ] **Step 3: Worked exemplar — `ConfirmAction` in `certificates.tsx` (revert cert)**

```tsx
import { ConfirmAction } from '../components/confirm-action'

// Replace the direct revert button:
<ConfirmAction
  title="Revert to a self-signed certificate?"
  description="This replaces the active platform TLS certificate with a self-signed one. Clients will see certificate warnings and services may restart."
  destructive
  requireReason
  confirmLabel="Revert certificate"
  onConfirm={(reason) => revertMutation.mutateAsync({ reason })}
>
  {(open) => <Button variant="destructive" onClick={open}>Revert to self-signed</Button>}
</ConfirmAction>
```

- [ ] **Step 4: Verify + commit the exemplar**

Run: `cd web/admin-console && npx vitest run src/pages/certificates.test.tsx && npx tsc --noEmit`

```bash
cd /home/cmit/openidx
git add web/admin-console/src/pages/certificates.tsx
git commit -m "fix(ui): certificates — confirm + reason before reverting platform cert

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

- [ ] **Step 5: Apply the two exemplar transforms to the remaining A1 files**

For each remaining file in the two lists above: apply the same `SecretField`/`useRevealedSecret` (secrets) or `ConfirmAction` (destructive) transform, adding `requireReason` where noted. One commit per file, message `fix(ui): <page> — <secret-safety|confirm destructive action>`. After each: run that page's `*.test.tsx` + `npx tsc --noEmit`.

- [ ] **Step 6: Confirm the destructive-confirm guard count dropped**

Run: `bash scripts/check-destructive-confirm.sh | tail -1`
Expected: offender count is 0 (or only allowlisted). If any remain, wrap them.

- [ ] **Step 7: Build**

Run: `cd web/admin-console && npm run build`
Expected: build succeeds.

---

## Task 10: A2 — broad QueryError sweep, by domain

Adopt `QueryGate` (or an explicit `if (isError) return <QueryError resource="..."/>`) on every page flagged by Guard 1, one domain per commit so reviews stay small. Domains and their page sets come from `src/config/navigation.ts` (home, iam, ziti, pam, audit, ai, platform).

- [ ] **Step 1: Worked exemplar — `users.tsx` (IAM)**

```tsx
import { QueryGate } from '../components/query-gate'

// Replace the hand-rolled list render:
<QueryGate query={usersQuery} resource="users" empty={<EmptyState label="No users found" />}>
  {(users) => (
    <Table>{/* existing rows over `users` */}</Table>
  )}
</QueryGate>
```

Run: `cd web/admin-console && npx vitest run src/pages/users.test.tsx && npx tsc --noEmit`, then commit `fix(ui): users — QueryGate so 401/403 shows an error not empty`.

- [ ] **Step 2: Sweep each domain (one commit per domain)**

For each domain, list its offender pages with:
```bash
bash scripts/check-query-error-coverage.sh | grep offender:
```
Apply the exemplar transform to each offender in that domain, then verify the whole console still builds and the domain's tests pass:
```bash
cd web/admin-console && npx tsc --noEmit && npx vitest run src/pages
```
Commit per domain: `fix(ui): <domain> pages — adopt QueryGate (no masked 401/403)`. Repeat for home, iam, ziti, pam, audit, ai, platform.

- [ ] **Step 3: Confirm Guard 1 is at zero**

Run: `bash scripts/check-query-error-coverage.sh | tail -1`
Expected: `query-error-coverage offenders: 0` (or only allowlisted).

- [ ] **Step 4: Full build**

Run: `cd web/admin-console && npm run build`
Expected: build succeeds.

---

## Task 11: A4 — flip guards to enforce

**Files:**
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Change the report step to enforce**

In the `ui-safety-guards` job, replace the warn-mode "Report coverage" step with:

```yaml
      - name: Enforce UI safety guards
        run: |
          bash scripts/check-query-error-coverage.sh --enforce
          bash scripts/check-destructive-confirm.sh --enforce
```

- [ ] **Step 2: Verify both guards pass in enforce mode locally**

Run:
```bash
bash scripts/check-query-error-coverage.sh --enforce && echo Q_OK
bash scripts/check-destructive-confirm.sh --enforce && echo D_OK
```
Expected: `Q_OK` and `D_OK` (exit 0). If not, a page was missed — fix it before committing.

- [ ] **Step 3: Full verification + commit**

```bash
cd web/admin-console && npx tsc --noEmit && npm run build && npx vitest run
cd /home/cmit/openidx
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml')); print('yaml ok')"
git add .github/workflows/ci.yml
git commit -m "ci(ui): enforce UI safety guards (query-error coverage + destructive confirm)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage:**
- Unit 1 QueryGate → Task 1; adoption → Task 10. ✓
- Unit 2 session-expiry (api seam + dialog + auth wiring) → Task 5. ✓
- Unit 3 ConfirmAction → Task 2; applied → Task 9. ✓
- Unit 4 SecretField + useRevealedSecret/copyWithWarning → Tasks 3, 4; applied → Task 9. ✓
- Unit 5 guards (both, mutation-tested, warn→enforce) → Tasks 6, 7, 11; CI wiring → Task 8. ✓
- Sweep waves A0 (Tasks 1–8) → A1 (Task 9) → A2 (Task 10) → A3 session-expiry (built in Task 5, active) → A4 (Task 11). ✓
- passwordless-settings fake-posture fix → Task 9 secrets list. ✓
- Success criteria map to Guard-1-zero (Task 10 Step 3), Guard-2-zero (Task 9 Step 6), enforce in CI (Task 11), session dialog (Task 5). ✓

**Placeholder scan:** No TBD/"handle errors"/"similar to". Sweep tasks (9 Step 5, 10 Step 2) are exemplar-driven with the exact file lists named and a guard that verifies completion — the mechanism is fully specified, not hand-waved.

**Type/name consistency:** `QueryGate` props `{query,resource,empty,children}`; `ConfirmAction` `{title,description,impact,confirmLabel,destructive,requireReason,onConfirm,children}` with `onConfirm(reason?)`; `SecretField` `{id,mode,value,onChange(value,changed),placeholder}`; `useRevealedSecret(ttlMs) → {value,reveal,clear}`; `copyWithWarning(secret) → Promise<boolean>`; api seam `setAuthExpiredHandler`/`notifyAuthExpired`; `SessionExpiredDialog {open,onSignIn}` — all used consistently across tasks. Guard script names + `--enforce` flag consistent between Tasks 6/7/8/11.
