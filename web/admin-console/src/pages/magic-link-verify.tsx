import { useEffect } from 'react'
import { baseURL } from '../lib/api'
import { Loader2 } from 'lucide-react'

export function MagicLinkVerifyPage() {
  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const token = params.get('token')
    const loginSession = params.get('login_session')
    if (token && loginSession) {
      window.location.href = `${baseURL}/oauth/magic-link-verify?token=${encodeURIComponent(token)}&login_session=${encodeURIComponent(loginSession)}`
    } else {
      window.location.href = '/login?error=invalid_magic_link'
    }
  }, [])

  return (
    <div className="min-h-screen flex items-center justify-center">
      <div className="text-center space-y-4">
        <Loader2 className="h-8 w-8 animate-spin mx-auto text-primary" />
        <p className="text-sm text-muted-foreground">Verifying your sign-in link...</p>
      </div>
    </div>
  )
}
