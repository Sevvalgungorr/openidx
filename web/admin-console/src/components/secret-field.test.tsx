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
