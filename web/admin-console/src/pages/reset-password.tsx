import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { Shield, ArrowLeft, Loader2, CheckCircle, AlertCircle } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card'
import { Input } from '../components/ui/input'
import { Label } from '../components/ui/label'
import { baseURL } from '../lib/api'

export function ResetPasswordPage() {
  const [searchParams] = useSearchParams()
  const token = searchParams.get('token') || ''
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [success, setSuccess] = useState(false)
  const [error, setError] = useState('')
  const [violations, setViolations] = useState<string[]>([])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setViolations([])

    if (password !== confirmPassword) {
      setError('Passwords do not match')
      return
    }

    if (password.length < 8) {
      setError('Password must be at least 8 characters')
      return
    }

    setIsSubmitting(true)

    try {
      const response = await fetch(`${baseURL}/api/v1/identity/users/reset-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, password }),
      })

      const data = await response.json()

      if (response.ok) {
        setSuccess(true)
      } else if (data.violations) {
        setViolations(data.violations)
        setError('Password does not meet the requirements:')
      } else {
        setError(data.error || 'Failed to reset password. The link may be expired.')
      }
    } catch {
      setError('Unable to connect to the server. Please try again.')
    } finally {
      setIsSubmitting(false)
    }
  }

  if (!token) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50">
        <Card className="w-full max-w-md shadow-xl">
          <CardContent className="pt-6">
            <div className="flex items-center gap-2 p-3 bg-red-50 border border-red-200 rounded-md">
              <AlertCircle className="h-4 w-4 text-red-600 flex-shrink-0" />
              <p className="text-sm text-red-600">Invalid or missing reset token.</p>
            </div>
            <Link to="/login" className="block mt-4">
              <Button variant="ghost" className="w-full">
                <ArrowLeft className="mr-2 h-4 w-4" />
                Back to login
              </Button>
            </Link>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50">
      <Card className="w-full max-w-md shadow-xl">
        <CardHeader className="text-center space-y-4">
          <div className="flex justify-center">
            <div className="h-16 w-16 rounded-full bg-gradient-to-br from-blue-600 to-indigo-700 flex items-center justify-center shadow-lg">
              <Shield className="h-9 w-9 text-white" />
            </div>
          </div>
          <div>
            <CardTitle className="text-3xl font-bold bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent">
              OpenIDX
            </CardTitle>
            <CardDescription className="text-base mt-2">
              Set a new password
            </CardDescription>
          </div>
        </CardHeader>

        <CardContent>
          {success ? (
            <div className="space-y-4">
              <div className="flex items-center gap-2 p-3 bg-green-50 border border-green-200 rounded-md">
                <CheckCircle className="h-4 w-4 text-green-600 flex-shrink-0" />
                <p className="text-sm text-green-700">
                  Your password has been reset successfully. You can now sign in with your new password.
                </p>
              </div>
              <Link to="/login">
                <Button className="w-full bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700" size="lg">
                  Go to Login
                </Button>
              </Link>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-4">
              {(error || violations.length > 0) && (
                <div className="p-3 bg-red-50 border border-red-200 rounded-md">
                  <div className="flex items-center gap-2">
                    <AlertCircle className="h-4 w-4 text-red-600 flex-shrink-0" />
                    <p className="text-sm text-red-600">{error}</p>
                  </div>
                  {violations.length > 0 && (
                    <ul className="mt-2 ml-6 list-disc text-sm text-red-600 space-y-1">
                      {violations.map((v, i) => <li key={i}>{v}</li>)}
                    </ul>
                  )}
                </div>
              )}

              <div className="space-y-2">
                <Label htmlFor="password">New Password</Label>
                <Input
                  id="password"
                  type="password"
                  placeholder="Enter new password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  minLength={8}
                  autoFocus
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="confirm-password">Confirm Password</Label>
                <Input
                  id="confirm-password"
                  type="password"
                  placeholder="Confirm new password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  required
                  minLength={8}
                />
              </div>

              <Button
                type="submit"
                className="w-full bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700"
                size="lg"
                disabled={isSubmitting}
              >
                {isSubmitting ? (
                  <span className="flex items-center gap-2">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Resetting...
                  </span>
                ) : (
                  'Reset Password'
                )}
              </Button>

              <Link to="/login">
                <Button type="button" variant="ghost" className="w-full">
                  <ArrowLeft className="mr-2 h-4 w-4" />
                  Back to login
                </Button>
              </Link>
            </form>
          )}
        </CardContent>

        <div className="px-6 py-4 bg-muted border-t border-border rounded-b-lg">
          <div className="flex items-center justify-center gap-4 text-xs text-muted-foreground">
            <span>Privacy</span>
            <span>•</span>
            <span>Terms</span>
            <span>•</span>
            <span>Help</span>
          </div>
        </div>
      </Card>

      <div className="absolute bottom-4 text-center w-full">
        <p className="text-sm text-muted-foreground">
          Powered by <span className="font-semibold text-foreground">OpenIDX</span>
        </p>
      </div>
    </div>
  )
}
