import { Input } from './ui/input'

interface SecretFieldProps {
  id?: string
  mode: 'create' | 'edit'
  value: string
  onChange: (value: string, changed: boolean) => void
  placeholder?: string
}

/**
 * A password input that never receives a stored secret from the API. On edit it
 * starts blank ("leave blank to keep current") and reports `changed` so the parent
 * only transmits a new secret when the user actually typed one.
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
