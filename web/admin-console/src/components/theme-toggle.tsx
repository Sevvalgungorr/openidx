import { Sun, Moon, Monitor } from 'lucide-react'
import { useAppStore } from '../lib/store'
import { Button } from './ui/button'
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
} from './ui/dropdown-menu'

type Theme = 'light' | 'dark' | 'system'

const OPTIONS: { value: Theme; label: string; icon: typeof Sun }[] = [
  { value: 'light', label: 'Light', icon: Sun },
  { value: 'dark', label: 'Dark', icon: Moon },
  { value: 'system', label: 'System', icon: Monitor },
]

/**
 * Header control that switches between light, dark and system themes. Reads and
 * writes the shared app store; App.tsx applies the resulting `.dark` root class.
 */
export function ThemeToggle() {
  const { theme, setTheme } = useAppStore()
  const active = OPTIONS.find((o) => o.value === theme) ?? OPTIONS[2]
  const ActiveIcon = active.icon

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon" aria-label="Toggle theme">
          <ActiveIcon className="h-5 w-5" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        {OPTIONS.map(({ value, label, icon: Icon }) => (
          <DropdownMenuItem key={value} onSelect={() => setTheme(value)}>
            <Icon className="h-4 w-4" />
            {label}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
