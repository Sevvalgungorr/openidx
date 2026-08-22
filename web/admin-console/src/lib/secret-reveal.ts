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
 * write is denied/unavailable so the caller can warn the user.
 */
export async function copyWithWarning(secret: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(secret)
    return true
  } catch {
    return false
  }
}
