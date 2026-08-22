import { createContext, useContext, useEffect, useState, ReactNode } from 'react'
import { setAuthInitializing, setAuthExpiredHandler } from './api'
import { SessionExpiredDialog } from '../components/session-expired-dialog'

interface User {
  id: string
  email: string
  name: string
  roles: string[]
  groups: string[]
  permissions: string[]
}

interface AuthContextType {
  isAuthenticated: boolean
  isLoading: boolean
  user: User | null
  token: string | null
  login: () => void
  logout: () => void
  hasRole: (role: string) => boolean
  hasPermission: (resource: string, action: string) => boolean
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export const OAUTH_URL = import.meta.env.VITE_OAUTH_URL || 'http://localhost:8006'
export const OAUTH_CLIENT_ID = import.meta.env.VITE_OAUTH_CLIENT_ID || 'admin-console'

// Helper to parse JWT token
function parseJwt(token: string): Record<string, unknown> | null {
  try {
    const base64Url = token.split('.')[1]
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/')
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split('')
        .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    )
    return JSON.parse(jsonPayload)
  } catch {
    return null
  }
}

// Generate PKCE code verifier and challenge
function generateCodeVerifier(): string {
  const array = new Uint8Array(32)
  crypto.getRandomValues(array)
  return btoa(String.fromCharCode.apply(null, Array.from(array)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

async function generateCodeChallenge(verifier: string): Promise<{ challenge: string; method: 'S256' | 'plain' }> {
  // PKCE S256 requires crypto.subtle, which is ONLY available in a secure
  // context (HTTPS, or http://localhost). In an insecure context it is
  // undefined. Previously we fell back to the plain verifier as the challenge
  // but still told the server method=S256 — the server then computed
  // SHA256(verifier) and compared it to the plain verifier, which never matches,
  // so the token exchange failed and LOGIN WAS IMPOSSIBLE on any non-HTTPS /
  // non-localhost deployment. Return the method we actually used so the caller
  // sends a consistent code_challenge_method.
  if (!crypto.subtle) {
    console.warn('[Auth] crypto.subtle unavailable (insecure context) — using PKCE method=plain. Serve the console over HTTPS to use S256.')
    return { challenge: verifier, method: 'plain' }
  }

  try {
    const encoder = new TextEncoder()
    const data = encoder.encode(verifier)
    const digest = await crypto.subtle.digest('SHA-256', data)
    const challenge = btoa(String.fromCharCode.apply(null, Array.from(new Uint8Array(digest))))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '')
    return { challenge, method: 'S256' }
  } catch (error) {
    // A SubtleCrypto failure is rare, but if it happens fall back to plain and
    // report method=plain so the challenge and method stay consistent.
    console.error('[Auth] Failed to generate S256 challenge, falling back to plain:', error)
    return { challenge: verifier, method: 'plain' }
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [isLoading, setIsLoading] = useState(true)
  const [user, setUser] = useState<User | null>(null)
  const [token, setToken] = useState<string | null>(null)
  const [sessionExpired, setSessionExpired] = useState(false)

  useEffect(() => {
    setAuthExpiredHandler(() => setSessionExpired(true))
    return () => setAuthExpiredHandler(null)
  }, [])

  useEffect(() => {
    initOpenIDXAuth()
  }, [])

  // OpenIDX OAuth authentication
  const initOpenIDXAuth = async () => {
    console.log('[Auth] Initializing OpenIDX OAuth')

    const url = new URL(window.location.href)
    const code = url.searchParams.get('code')
    const storedToken = localStorage.getItem('token')
    const refreshToken = localStorage.getItem('refresh_token')

    // Check if we have a code from OAuth callback
    if (code) {
      console.log('[Auth] Processing OAuth callback')
      const codeVerifier = sessionStorage.getItem('pkce_code_verifier')

      try {
        const tokenResponse = await fetch(`${OAUTH_URL}/oauth/token`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: new URLSearchParams({
            grant_type: 'authorization_code',
            client_id: OAUTH_CLIENT_ID,
            code: code,
            redirect_uri: window.location.origin + '/login',
            code_verifier: codeVerifier || '',
          }),
        })

        if (tokenResponse.ok) {
          const tokens = await tokenResponse.json()
          localStorage.setItem('token', tokens.access_token)
          if (tokens.refresh_token) {
            localStorage.setItem('refresh_token', tokens.refresh_token)
          }
          sessionStorage.removeItem('pkce_code_verifier')

          // Clean URL
          url.searchParams.delete('code')
          url.searchParams.delete('state')
          window.history.replaceState({}, '', url.pathname)

          // Set auth state
          const parsed = parseJwt(tokens.access_token)
          if (parsed) {
            setUser({
              id: (parsed.sub as string) || '',
              email: (parsed.email as string) || '',
              name: (parsed.name as string) || (parsed.preferred_username as string) || '',
              roles: (parsed.roles as string[]) || [],
              groups: (parsed.groups as string[]) || [],
              permissions: (parsed.permissions as string[]) || [],
            })
            setToken(tokens.access_token)
            setIsAuthenticated(true)
          }
        } else {
          console.error('[Auth] Token exchange failed')
          localStorage.removeItem('token')
          localStorage.removeItem('refresh_token')
        }
      } catch (error) {
        console.error('[Auth] Token exchange error:', error)
      }

      setAuthInitializing(false)
      setIsLoading(false)
      return
    }

    // Check for existing token
    if (storedToken) {
      const parsed = parseJwt(storedToken)
      if (parsed) {
        const exp = (parsed.exp as number) * 1000
        if (exp > Date.now()) {
          console.log('[Auth] Valid token found', parsed)

          // Check if token has roles field
          const roles = parsed.roles as string[] | undefined
          if (!roles || roles.length === 0) {
            console.warn('[Auth] Token missing roles - logging out to re-authenticate')
            localStorage.removeItem('token')
            localStorage.removeItem('refresh_token')
            setAuthInitializing(false)
            setIsLoading(false)
            return
          }

          setUser({
            id: (parsed.sub as string) || '',
            email: (parsed.email as string) || '',
            name: (parsed.name as string) || (parsed.preferred_username as string) || '',
            roles: roles,
            groups: (parsed.groups as string[]) || [],
            permissions: (parsed.permissions as string[]) || [],
          })
          setToken(storedToken)
          setIsAuthenticated(true)
          setAuthInitializing(false)
          setIsLoading(false)

          // Setup token refresh
          setupTokenRefresh()
          return
        } else if (refreshToken) {
          // Token expired, try to refresh
          const refreshed = await refreshAccessToken(refreshToken)
          if (refreshed) {
            setAuthInitializing(false)
            setIsLoading(false)
            return
          }
        }
      }
      // Invalid token
      localStorage.removeItem('token')
      localStorage.removeItem('refresh_token')
    }

    console.log('[Auth] Not authenticated')
    setAuthInitializing(false)
    setIsLoading(false)
  }

  const refreshAccessToken = async (refreshToken: string): Promise<boolean> => {
    try {
      const response = await fetch(`${OAUTH_URL}/oauth/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          client_id: OAUTH_CLIENT_ID,
          refresh_token: refreshToken,
        }),
      })

      if (response.ok) {
        const tokens = await response.json()
        localStorage.setItem('token', tokens.access_token)
        if (tokens.refresh_token) {
          localStorage.setItem('refresh_token', tokens.refresh_token)
        }

        const parsed = parseJwt(tokens.access_token)
        if (parsed) {
          setUser({
            id: (parsed.sub as string) || '',
            email: (parsed.email as string) || '',
            name: (parsed.name as string) || (parsed.preferred_username as string) || '',
            roles: (parsed.roles as string[]) || [],
            groups: (parsed.groups as string[]) || [],
            permissions: (parsed.permissions as string[]) || [],
          })
          setToken(tokens.access_token)
          setIsAuthenticated(true)
          return true
        }
      } else {
        // Check for session revocation
        const errorData = await response.json().catch(() => ({}))
        if (errorData.error_description === 'session_revoked') {
          console.warn('[Auth] Session was revoked - redirecting to login')
        }
      }
    } catch (error) {
      console.error('[Auth] Token refresh failed:', error)
    }

    localStorage.removeItem('token')
    localStorage.removeItem('refresh_token')
    setIsAuthenticated(false)
    setUser(null)
    setToken(null)
    return false
  }

  const setupTokenRefresh = () => {
    const refreshInterval = setInterval(async () => {
      const refreshToken = localStorage.getItem('refresh_token')
      const currentToken = localStorage.getItem('token')

      if (currentToken && refreshToken) {
        const parsed = parseJwt(currentToken)
        if (parsed) {
          const exp = (parsed.exp as number) * 1000
          // Refresh if token expires in less than 60 seconds
          if (exp - Date.now() < 60000) {
            await refreshAccessToken(refreshToken)
          }
        }
      }
    }, 30000)

    return () => clearInterval(refreshInterval)
  }

  const login = async () => {
    // OpenIDX OAuth login with PKCE
    const codeVerifier = generateCodeVerifier()
    const { challenge: codeChallenge, method: codeChallengeMethod } = await generateCodeChallenge(codeVerifier)
    sessionStorage.setItem('pkce_code_verifier', codeVerifier)

    const authUrl = new URL(`${OAUTH_URL}/oauth/authorize`)
    authUrl.searchParams.set('response_type', 'code')
    authUrl.searchParams.set('client_id', OAUTH_CLIENT_ID)
    authUrl.searchParams.set('redirect_uri', window.location.origin + '/login')
    authUrl.searchParams.set('scope', 'openid profile email')
    authUrl.searchParams.set('code_challenge', codeChallenge)
    // Send the method that MATCHES the challenge we generated (S256 in a secure
    // context, plain otherwise) so backend PKCE verification succeeds.
    authUrl.searchParams.set('code_challenge_method', codeChallengeMethod)

    window.location.href = authUrl.toString()
  }

  const logout = async () => {
    // Server-side logout — revoke all sessions and refresh tokens
    const currentToken = localStorage.getItem('token')
    if (currentToken) {
      try {
        await fetch(`${OAUTH_URL}/oauth/logout`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': `Bearer ${currentToken}`,
          },
          body: new URLSearchParams({
            id_token_hint: currentToken,
          }),
        })
      } catch {
        // Proceed with local logout even if server call fails
      }
    }

    localStorage.removeItem('token')
    localStorage.removeItem('refresh_token')
    sessionStorage.removeItem('pkce_code_verifier')

    setIsAuthenticated(false)
    setUser(null)
    setToken(null)
    window.location.href = window.location.origin + '/login'
  }

  const hasRole = (role: string) => {
    return user?.roles.includes(role) || false
  }

  const hasPermission = (resource: string, action: string) => {
    if (user?.roles.includes('admin')) return true
    return user?.permissions.includes(`${resource}:${action}`) || false
  }

  return (
    <AuthContext.Provider
      value={{
        isAuthenticated,
        isLoading,
        user,
        token,
        login,
        logout,
        hasRole,
        hasPermission,
      }}
    >
      {children}
      <SessionExpiredDialog open={sessionExpired} onSignIn={login} />
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}

// Export PKCE functions for use in login component
export { generateCodeVerifier, generateCodeChallenge }
